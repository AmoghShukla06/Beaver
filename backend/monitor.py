"""Real OS socket inventory sampled independently of the UI."""
import collections
import hashlib
import logging
import os
import platform
import socket
import threading
import time
import uuid

import psutil
from .binaries import Binaries
from .capture import Capture
from .dnscache import DnsCache
from .intelligence import Intelligence, Geolocation
from .risk import PROTECTED, assess, public

# Active protection only acts on these unambiguous behaviors, and never on OS or validly signed binaries.
AUTO_RESPONSE = {"reverse-shell", "masquerading", "fileless", "tampered-signature", "known-c2", "threat-intel", "intel-domain", "exfil-channel"}

INTERVAL = 2.0
CHECKPOINT = 30  # seconds between last_seen checkpoints for live connections
CLOSED = {"TIME_WAIT", "CLOSE", "CLOSE_WAIT", "FIN_WAIT1", "FIN_WAIT2", "LAST_ACK", "CLOSING"}

class Monitor:
    def __init__(self, store, emit=None):
        self.store = store; self.emit = emit or (lambda event, data: None)
        settings = store.settings(); self.system = platform.system()
        self.intel = Intelligence(store.directory, settings["disabled_feeds"]); self.geo = Geolocation()
        self.capture = Capture(); self.binaries = Binaries(store); self.dns = DnsCache()
        self.lock = threading.Lock(); self.stop_event = threading.Event()
        self.thread = None; self.error = None; self.current = {}; self.identities = {}; self.observations = collections.Counter()
        self.previous_bytes = {}; self.last_io = None; self.io_tick = None; self.last_tick = None
        self.series = collections.deque(maxlen=1800); self.visible = True; self.samples = 0
        self.started = time.time(); self.last_feed_attempt = 0; self.last_prune = 0; self.last_checkpoint = 0
        self.dns_names = {}; self.last_dns = 0; self.starts = {}; self.summary = None; self.listening = {}
        self.capture_available = None; self.on_battery = False; self.last_power = None
        self.state = {"ready": False, "apps": [], "connections": [], "traffic": [], "sampled_at": None}

    def identity(self, pid, now):
        if pid is None or pid == 0:
            return {"id": "unattributed", "name": "Unattributed sockets", "path": None, "pid": None, "created": None}
        cached = self.identities.get(pid)
        # Fast create_time() lookups are revalidated every sample (PID reuse); protected processes cost ~4 ms each, so every 30 s.
        if cached and (now - cached[1] < (30 if cached[2] else 0)):
            return cached[0]
        try:
            proc = psutil.Process(pid)
            started = time.perf_counter(); created = proc.create_time(); slow = time.perf_counter() - started > .001
            if cached and cached[0]["created"] == created:
                self.identities[pid] = (cached[0], now, slow)
                return cached[0]
            with proc.oneshot():
                name = proc.name(); executable = None; parent = None
                try:
                    executable = proc.exe() or None
                except (psutil.AccessDenied, psutil.NoSuchProcess):
                    pass
                try:
                    parent = psutil.Process(proc.ppid()).name()
                except (psutil.Error, OSError):
                    pass
            deleted = fileless = False
            if self.system == "Linux":
                try:
                    link = os.readlink(f"/proc/{pid}/exe")
                    deleted = link.endswith(" (deleted)"); fileless = link.startswith("/memfd:")
                    if deleted:
                        executable = link[:-10]
                except OSError:
                    pass
            key = os.path.normcase(executable) if executable else f"pid:{pid}:{created}"
            result = {"id": hashlib.sha256(key.encode()).hexdigest()[:24], "name": name, "path": executable, "pid": pid,
                      "created": created, "parent": parent, "deleted": deleted, "fileless": fileless}
            self.identities[pid] = (result, now, slow)
            return result
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            self.identities.pop(pid, None)
            return {"id": f"unavailable-{pid}", "name": f"Process {pid} (unavailable)", "path": None, "pid": pid, "created": None}

    def domains(self, now):
        if self.dns.api and now - self.last_dns >= 10:
            self.last_dns = now; self.dns_names = self.dns.read()
        return self.dns_names

    def sample(self):
        tick = time.monotonic(); now = time.time(); settings = self.store.settings()
        self.geo.configure(settings["geoip_path"])
        if set(settings["disabled_feeds"]) != self.intel.disabled:
            self.intel.set_disabled(settings["disabled_feeds"])
        if settings["capture"] and not self.capture.enabled:
            self.capture.start()
        elif not settings["capture"] and self.capture.enabled:
            self.capture.stop()
        apps = {}; conns = []; identities = {}; inventory_error = None; listening = collections.defaultdict(set)
        try:
            sockets = psutil.net_connections(kind="inet")
        except (psutil.AccessDenied, OSError) as exc:
            sockets = []; inventory_error = str(exc) or "Connection inventory requires additional OS permissions"
        for conn in sockets:
            if not conn.laddr:
                continue
            if conn.pid not in identities:
                identities[conn.pid] = self.identity(conn.pid, now)
            ident = identities[conn.pid]; aid = ident["id"]
            if aid not in apps:
                apps[aid] = {"id": aid, "name": ident["name"], "path": ident["path"], "pids": [], "connections": 0, "parent": ident.get("parent")}
            if conn.pid and conn.pid not in apps[aid]["pids"]:
                apps[aid]["pids"].append(conn.pid)
            protocol = "TCP" if conn.type == socket.SOCK_STREAM else "UDP"
            if conn.status == "LISTEN":
                listening[aid].add((protocol, conn.laddr.port))
            conns.append({"app_id": aid, "pid": conn.pid or None, "process_created": ident["created"],
                          "local_ip": conn.laddr.ip, "local_port": conn.laddr.port,
                          "remote_ip": conn.raddr.ip if conn.raddr else None, "remote_port": conn.raddr.port if conn.raddr else None,
                          "protocol": protocol, "status": conn.status, "source": "OS socket table"})
        if inventory_error:
            # A failed sample must not turn missing visibility into closed sockets.
            raise RuntimeError(inventory_error)
        self.capture.update_owners(conns)
        totals, flows, captured_domains = self.capture.snapshot(); captured = self.capture.status()["active"]
        domains = self.domains(now) | captured_domains
        existing = {(c["app_id"], c["protocol"], c["local_ip"], c["local_port"], c["remote_ip"], c["remote_port"]) for c in conns}
        for key in flows:
            aid, proto, lip, lp, rip, rp = key
            if key not in existing and aid in apps:
                conns.append({"app_id": aid, "pid": None, "process_created": None, "local_ip": lip, "local_port": lp,
                              "remote_ip": rip, "remote_port": rp, "protocol": proto, "status": "OBSERVED", "source": "Packet metadata"})
        current = {}; new = []
        for c in conns:
            key = (c["app_id"], c["pid"], c["process_created"], c["protocol"], c["local_ip"], c["local_port"], c["remote_ip"], c["remote_port"])
            old = self.current.get(key)
            c["id"] = old["id"] if old else uuid.uuid4().hex
            c["first_seen"] = old["first_seen"] if old else now
            c["last_seen"] = now
            c["domain"] = domains.get(c["remote_ip"]) or (old and old["domain"])
            c["geo"] = self.geo.lookup(c["remote_ip"]) if c["remote_ip"] else None
            hits = (self.intel.match(c["remote_ip"]) + self.intel.match_domain(c["domain"])) if c["remote_ip"] else []
            c["threat"] = max(hits, key=lambda h: h["points"]) if hits else None
            current[key] = c; apps[c["app_id"]]["connections"] += 1
            if not old:
                new.append(c)
                if c["protocol"] == "TCP" and c["remote_ip"] and (c["protocol"], c["local_port"]) not in listening[c["app_id"]]:
                    starts = self.starts.setdefault((c["app_id"], c["remote_ip"], c["remote_port"]), collections.deque(maxlen=10))
                    starts.append(now)
        ended = [(v["id"], v["last_seen"]) for k, v in self.current.items() if k not in current]
        if now - self.last_checkpoint >= CHECKPOINT:
            self.last_checkpoint = now; new = list(current.values())  # checkpoint last_seen and late domains for live rows
        self.store.connections(new, ended); self.current = current
        if len(self.starts) > 5000 or self.samples % 300 == 0:
            self.starts = {k: v for k, v in self.starts.items() if now - v[-1] < 3600}
        allow = self.store.allowlist(); allowed_apps = {r["target"] for r in allow if r["kind"] == "application"}
        allowed_endpoints = {r["target"] for r in allow if r["kind"] == "endpoint"}
        grouped = collections.defaultdict(list)
        for c in conns:
            grouped[c["app_id"]].append(c)
        beacons = collections.defaultdict(dict)
        for (aid, ip, port), starts in self.starts.items():
            if aid in apps and len(starts) >= 6:
                beacons[aid][(ip, port)] = list(starts)
        elapsed = tick - self.last_tick if self.last_tick else None
        self.listening = listening
        by_id = {i["id"]: i for i in identities.values()}
        for aid, app in apps.items():
            self.observations[aid] += 1
            ident = by_id.get(aid, {}); total = totals.get(aid, [0, 0]); previous = self.previous_bytes.get(aid)
            binary = self.binaries.info(app["path"]) if app["path"] else None
            app["binary"] = binary
            app["risk"] = assess(app, grouped[aid], self.intel, self.observations[aid], app["path"] in allowed_apps, allowed_endpoints,
                                 {"system": self.system, "binary": binary, "listening": listening[aid], "beacons": beacons.get(aid),
                                  "totals": total if captured else None, "deleted": ident.get("deleted"), "fileless": ident.get("fileless"),
                                  "parent": app.get("parent")})
            app["listening"] = len(listening[aid])
            app["upload_bps"] = max(0, total[0] - previous[0]) / elapsed if captured and elapsed and previous else None
            app["download_bps"] = max(0, total[1] - previous[1]) / elapsed if captured and elapsed and previous else None
            app["uploaded"] = total[0] if captured else None; app["downloaded"] = total[1] if captured else None
            # Wait for executable inspection before a Medium alert so a late signature result does not re-alert.
            if app["risk"]["level"] == "High" or (app["risk"]["level"] == "Medium" and (binary or {}).get("state") != "pending"):
                self.alert(app, grouped[aid], now, settings["active_protection"])
            self.new_app(app, grouped[aid], now)
        self.previous_bytes = totals
        self.traffic(tick, now)
        self.last_tick = tick; self.error = None; self.samples += 1
        with self.lock:
            self.state = {"ready": True, "sampled_at": now,
                          "apps": sorted(apps.values(), key=lambda a: (-(a["risk"]["score"] or 0), -a["connections"], a["name"])),
                          "connections": conns, "traffic": list(self.series), "upload_bps": self.series[-1]["upload"] if self.series else None,
                          "download_bps": self.series[-1]["download"] if self.series else None, "started": self.started}
        self.publish(apps, conns)
        alive = set(identities)
        self.identities = {k: v for k, v in self.identities.items() if k in alive}
        self.observations = collections.Counter({k: v for k, v in self.observations.items() if k in apps})
        if now - self.last_prune > 60:
            self.store.prune(); self.last_prune = now
            self.binaries.forget_missing({a["path"] for a in apps.values()})
        if settings["feed_updates"] and now - self.last_feed_attempt > 600:
            self.last_feed_attempt = now
            threading.Thread(target=self.refresh_feed_safely, daemon=True).start()

    def traffic(self, tick, now):
        # Interface counters cost ~25 ms on Windows; while no window is open, sample them every third tick.
        if not self.visible and self.io_tick is not None and self.samples % 3:
            return
        counters = psutil.net_io_counters(pernic=True, nowrap=True)
        # Interface counters can include VPN/virtual adapters: label as aggregate, not Internet-only usage.
        sent = sum(v.bytes_sent for k, v in counters.items() if not k.lower().startswith(("lo", "loopback")))
        recv = sum(v.bytes_recv for k, v in counters.items() if not k.lower().startswith(("lo", "loopback")))
        up = down = None
        if self.last_io and self.io_tick:
            span = tick - self.io_tick
            up = max(0, sent - self.last_io[0]) / span; down = max(0, recv - self.last_io[1]) / span
        self.last_io = (sent, recv); self.io_tick = tick
        self.series.append({"time": now, "upload": up, "download": down})

    def alert(self, app, connections, now, active=False):
        risk = app["risk"]; rules = sorted({e["rule"] + (":" + e["endpoint"] if e.get("category") == "intel" else "") for e in risk["evidence"] if e["points"] >= 15})
        key = app["id"] + "|" + risk["level"] + "|" + ",".join(rules)
        top = max((e for e in risk["evidence"] if e["points"] > 0), key=lambda e: e["points"])
        endpoint = next((c for c in connections if c.get("remote_ip") == top.get("endpoint")), None)
        alert = {"id": uuid.uuid4().hex, "key": key, "app_id": app["id"], "app_name": app["name"], "path": app["path"],
                 "created": now, "level": risk["level"], "title": top["title"], "risk": risk,
                 "endpoint": {"ip": endpoint["remote_ip"], "port": endpoint["remote_port"], "domain": endpoint["domain"],
                              "country": (endpoint["geo"] or {}).get("country")} if endpoint else None}
        if self.store.add_alert(alert):
            binary = app.get("binary") or {}
            if (active and risk["level"] == "High" and binary.get("signature") != "valid" and not binary.get("os_binary")
                    and any(e["rule"] in AUTO_RESPONSE for e in risk["evidence"])):
                try:
                    alert["response"] = {"action": "terminated", "at": time.time()} | self.terminate(app["id"], True, app)
                except (ValueError, psutil.Error) as exc:
                    alert["response"] = {"action": "failed", "at": time.time(), "error": str(exc)[:200]}
                self.store.update_alert(alert)
            self.emit("alert", alert | {"acknowledged": False})

    def new_app(self, app, connections, now):
        """Record an executable's first internet connection; alert unless it is an OS binary or Beaver is still learning."""
        binary = app.get("binary") or {}
        if not app["path"] or binary.get("state") == "pending" or app["path"] in self.store.known_apps:
            return
        first = next((c for c in connections if c.get("remote_ip") and public(c["remote_ip"])
                      and (c["protocol"], c["local_port"]) not in self.listening.get(app["id"], ())), None)
        if not first or not self.store.first_internet(app["path"]) or self.store.learning() or binary.get("os_binary"):
            return
        alert = {"id": uuid.uuid4().hex, "key": "new-app|" + app["path"], "app_id": app["id"], "app_name": app["name"],
                 "path": app["path"], "created": now, "level": "Info", "kind": "new-app", "title": "First internet connection",
                 "publisher": binary.get("publisher"), "signature": binary.get("signature"),
                 "risk": {"level": "Info", "score": None, "evidence": [], "reason": "A program connected to the internet for the first time.",
                          "allowlisted": False},
                 "endpoint": {"ip": first["remote_ip"], "port": first["remote_port"], "domain": first["domain"],
                              "country": (first["geo"] or {}).get("country")}}
        if self.store.add_alert(alert):
            self.emit("alert", alert | {"acknowledged": False})

    def terminate(self, app_id, automatic=False, app=None):
        """Stop every live process of one observed application. Refuses Beaver, PID 0/4 and core Windows processes."""
        if app is None:
            with self.lock:
                app = next((a for a in self.state["apps"] if a["id"] == app_id), None)
        if not app or not app["pids"]:
            raise ValueError("That application is no longer running")
        binary = app.get("binary") or {}
        if (app["name"] or "").lower() in PROTECTED or (binary.get("os_binary") and not app["risk"].get("remote_tool")):
            raise ValueError("Beaver will not stop core operating-system processes. Block its endpoints in Firewall instead.")
        stopped = []; failed = []; own = {os.getpid(), os.getppid()}
        for pid in app["pids"]:
            cached = self.identities.get(pid)
            if pid <= 4 or pid in own or not cached or cached[0]["id"] != app_id:
                failed.append({"pid": pid, "error": "Process identity changed or is protected"}); continue
            try:
                proc = psutil.Process(pid)
                if proc.create_time() != cached[0]["created"]:
                    raise psutil.NoSuchProcess(pid)
                proc.terminate(); stopped.append(proc)
            except psutil.AccessDenied:
                failed.append({"pid": pid, "error": "Requires administrator rights. Block the application in Firewall instead."})
            except psutil.NoSuchProcess:
                pass
        gone, alive = psutil.wait_procs(stopped, timeout=3)
        for proc in alive:
            try:
                proc.kill()
            except psutil.Error:
                pass
        if not stopped and failed:
            raise ValueError(failed[0]["error"])
        return {"terminated": [p.pid for p in stopped], "failed": failed, "automatic": automatic}

    def publish(self, apps, conns):
        """Push a small status summary (tray tooltip, badge) only when it changes."""
        counts = collections.Counter(a["risk"]["level"] for a in apps.values())
        unacknowledged = self.store.alert_counts()
        summary = {"apps": len([a for a in apps if a != "unattributed"]), "high": counts["High"], "medium": counts["Medium"],
                   "connections": sum(1 for c in conns if c["remote_ip"] and c["status"] not in CLOSED),
                   "unacknowledged": sum(unacknowledged.values()), "unacknowledged_high": unacknowledged.get("High", 0),
                   "intel_fresh": self.intel.fresh()}
        if summary != self.summary:
            self.summary = summary; self.emit("status", summary)

    def refresh_feed_safely(self):
        try:
            self.intel.refresh(only_due=True)
        except Exception:
            pass

    def snapshot(self):
        with self.lock:
            data = dict(self.state)
        elevated = False
        if self.system == "Windows":
            import ctypes
            elevated = bool(ctypes.windll.shell32.IsUserAnAdmin())
        elif hasattr(os, "geteuid"):
            elevated = os.geteuid() == 0
        data["coverage"] = {"platform": self.system, "elevated": elevated, "inventory_error": self.error,
            "inventory": "OS socket polling every 2 seconds; short-lived connections can be missed. Linux may omit sockets without sufficient permissions.",
            "capture": self.capture.status() | {"available": self.capture_probe()}, "intel": self.intel.status(),
            "power": {"on_battery": self.on_battery, "interval": self.interval()},
            "geo": {"available": self.geo.reader is not None, "error": self.geo.error, "provider": self.geo.reader.metadata().database_type if self.geo.reader else None},
            "dns_cache": {"available": bool(self.dns.api), "names": len(self.dns_names), "error": self.dns.error},
            "binaries": {"error": self.binaries.error, "signatures": self.system == "Windows"},
            "domains": "Domains come from observed plaintext DNS answers" + (" and the Windows DNS client cache" if self.dns.api else "")
                       + ". Encrypted DNS (DoH/DoT) lookups are not visible."}
        return data

    def capture_probe(self):
        """Whether the packet-capture library is installed (cached). Does not open any interface."""
        if self.capture_available is None:
            from . import pcap
            try:
                pcap.load(); self.capture_available = True
            except (RuntimeError, OSError):
                self.capture_available = False
        return self.capture_available

    def set_visible(self, visible):
        self.visible = bool(visible)

    def loop(self):
        while not self.stop_event.is_set():
            start = time.monotonic()
            try:
                self.sample()
            except Exception as exc:
                if str(exc)[:300] != self.error:
                    logging.getLogger("beaver").warning("Sample failed: %s", exc)  # once per distinct error
                self.error = str(exc)[:300]
            self.stop_event.wait(max(.1, self.interval() - (time.monotonic() - start)))

    def interval(self):
        """2 s normally; 4 s when no window is open and the device runs on battery."""
        now = time.monotonic()
        if self.last_power is None or now - self.last_power > 60:
            self.last_power = now
            try:
                battery = psutil.sensors_battery()
                self.on_battery = bool(battery and not battery.power_plugged)
            except (OSError, AttributeError, RuntimeError):
                self.on_battery = False
        return INTERVAL * 2 if self.on_battery and not self.visible else INTERVAL

    def start(self):
        self.thread = threading.Thread(target=self.loop, name="beaver-monitor", daemon=True); self.thread.start()

    def stop(self):
        self.stop_event.set()
        if self.thread:
            self.thread.join(timeout=10)
        self.capture.stop(); self.geo.close()
