"""Local matching against public threat feeds; optional local GeoIP. Observed endpoints never leave the device."""
import array
import bisect
import hashlib
import ipaddress
import json
import logging
import os
import threading
import time
import urllib.request
from pathlib import Path

USER_AGENT = "Beaver/1.0 (+https://github.com/AmoghShukla06/Beaver; local threat matching)"

# points: contribution of one match. Feeds below 80 cannot raise High on their own.
FEEDS = [
    {"id": "feodo", "name": "Feodo Tracker botnet C2", "kind": "ip", "format": "feodo", "points": 90,
     "url": "https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.json",
     "home": "https://feodotracker.abuse.ch/blocklist/", "category": "Botnet command-and-control server",
     "refresh": 3600, "max_age": 6 * 3600, "limit": 4_000_000},
    {"id": "spamhaus-drop", "name": "Spamhaus DROP (IPv4)", "kind": "cidr", "format": "spamhaus", "points": 80,
     "url": "https://www.spamhaus.org/drop/drop_v4.json",
     "home": "https://www.spamhaus.org/blocklists/do-not-route-or-peer/", "category": "Hijacked or criminal-operated network",
     "refresh": 12 * 3600, "max_age": 4 * 86400, "limit": 4_000_000},
    {"id": "spamhaus-drop-v6", "name": "Spamhaus DROP (IPv6)", "kind": "cidr", "format": "spamhaus", "points": 80,
     "url": "https://www.spamhaus.org/drop/drop_v6.json",
     "home": "https://www.spamhaus.org/blocklists/do-not-route-or-peer/", "category": "Hijacked or criminal-operated network",
     "refresh": 12 * 3600, "max_age": 4 * 86400, "limit": 2_000_000},
    {"id": "threat-domains", "name": "HaGeZi Threat Intelligence domains", "kind": "domain", "format": "lines", "points": 80,
     "url": "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/tif.mini-onlydomains.txt",
     "home": "https://github.com/hagezi/dns-blocklists", "category": "Malware, phishing or C2 domain",
     "refresh": 12 * 3600, "max_age": 4 * 86400, "limit": 12_000_000},
    {"id": "et-compromised", "name": "Emerging Threats compromised hosts", "kind": "ip", "format": "lines", "points": 45,
     "url": "https://rules.emergingthreats.net/blockrules/compromised-ips.txt",
     "home": "https://rules.emergingthreats.net/", "category": "Known compromised host",
     "refresh": 12 * 3600, "max_age": 4 * 86400, "limit": 4_000_000},
    {"id": "ipsum", "name": "IPsum (on 4+ blocklists)", "kind": "ip", "format": "lines", "points": 40,
     "url": "https://raw.githubusercontent.com/stamparm/ipsum/master/levels/4.txt",
     "home": "https://github.com/stamparm/ipsum", "category": "Repeatedly reported attacker or scanner",
     "refresh": 12 * 3600, "max_age": 4 * 86400, "limit": 4_000_000},
]
FEED_IDS = {f["id"] for f in FEEDS}
MAX_AGE = FEEDS[0]["max_age"]

def domain_hash(name):
    return int.from_bytes(hashlib.blake2b(name.encode("utf-8", "replace"), digest_size=8).digest(), "little")

def parse(feed, raw):
    """Return a compact lookup structure for one feed. Raises ValueError on unexpected content."""
    text = raw.decode("utf-8", "replace") if isinstance(raw, bytes) else raw
    if feed["format"] == "feodo":
        rows = json.loads(text)
        if not isinstance(rows, list) or len(rows) > 100000:
            raise ValueError("Unexpected threat feed format")
        values = []
        for row in rows:
            if not isinstance(row, dict):
                raise ValueError("Invalid threat entry")
            values.append(row["ip_address"])
    elif feed["format"] == "spamhaus":
        values = [json.loads(line)["cidr"] for line in text.splitlines() if line.strip().startswith('{"cidr"')]
    else:
        values = [line.split("#")[0].strip() for line in text.splitlines()]
        values = [v for v in values if v and not v.startswith(("!", "["))]
    if len(values) > 1_000_000:
        raise ValueError("Threat feed exceeds entry limit")
    if feed["kind"] == "ip":
        result = set()
        for value in values:
            addr = ipaddress.ip_address(value.split()[0])
            if not addr.is_global:
                raise ValueError("Non-public address in public feed")
            result.add(int(addr))
        return result
    if feed["kind"] == "cidr":
        ranges = []
        for value in values:
            net = ipaddress.ip_network(value, strict=False)
            if net.prefixlen < 8 or not net.network_address.is_global:
                raise ValueError("Implausible network in public feed")
            ranges.append((int(net.network_address), int(net.broadcast_address)))
        ranges.sort()
        return [r[0] for r in ranges], [r[1] for r in ranges]
    hashes = array.array("Q", sorted({domain_hash(v.lower().rstrip(".")) for v in values if "." in v and len(v) <= 253}))
    return hashes

class Intelligence:
    def __init__(self, directory, disabled=()):
        self.directory = Path(directory) / "feeds"; self.directory.mkdir(parents=True, exist_ok=True)
        self.data = {}; self.updated = {}; self.errors = {}; self.counts = {}
        self.disabled = set(disabled); self.lock = threading.Lock(); self.cache = {}
        for feed in FEEDS:
            self.load(feed)

    def load(self, feed):
        path = self.directory / (feed["id"] + ".txt"); meta = self.directory / (feed["id"] + ".json")
        try:
            info = json.loads(meta.read_text(encoding="utf-8"))
            self.install(feed, parse(feed, path.read_bytes()), float(info["updated"]))
        except (OSError, ValueError, KeyError, TypeError):
            pass

    def install(self, feed, structure, updated):
        size = len(structure[0]) if feed["kind"] == "cidr" else len(structure)
        self.data[feed["id"]] = structure; self.updated[feed["id"]] = updated; self.counts[feed["id"]] = size
        self.cache = {}

    def fetch(self, feed):
        request = urllib.request.Request(feed["url"], headers={"User-Agent": USER_AGENT})
        prefix = feed["url"].split("/", 3)
        with urllib.request.urlopen(request, timeout=30) as response:
            if not response.url.startswith("/".join(prefix[:3]) + "/"):
                raise ValueError("Unexpected feed redirect")
            raw = response.read(feed["limit"] + 1)
        if len(raw) > feed["limit"]:
            raise ValueError("Threat feed exceeds size limit")
        structure = parse(feed, raw); updated = time.time()
        path = self.directory / (feed["id"] + ".txt"); tmp = path.with_suffix(".tmp")
        tmp.write_bytes(raw); os.replace(tmp, path)
        (self.directory / (feed["id"] + ".json")).write_text(json.dumps({"updated": updated}), encoding="utf-8")
        self.install(feed, structure, updated); self.errors.pop(feed["id"], None)

    def refresh(self, only_due=False):
        """Download enabled feeds sequentially. One failed feed keeps its previous cache."""
        if not self.lock.acquire(blocking=False):
            raise ValueError("A feed refresh is already running")
        try:
            now = time.time()
            for feed in FEEDS:
                if feed["id"] in self.disabled or (only_due and now - self.updated.get(feed["id"], 0) < feed["refresh"]):
                    continue
                try:
                    self.fetch(feed)
                except Exception as exc:
                    self.errors[feed["id"]] = str(exc)[:300]
                    logging.getLogger("beaver").warning("Feed %s failed: %s", feed["id"], exc)
            if not only_due and self.errors and len(self.errors) == len(FEEDS) - len(self.disabled):
                raise ValueError("No threat feed could be refreshed: " + next(iter(self.errors.values())))
        finally:
            self.lock.release()
        return self.status()

    def fresh_ids(self, now=None):
        now = now or time.time()
        return [f["id"] for f in FEEDS if f["id"] not in self.disabled and f["id"] in self.data
                and now - self.updated[f["id"]] <= f["max_age"]]

    def fresh(self):
        return bool(self.fresh_ids())

    def status(self):
        now = time.time(); fresh = set(self.fresh_ids(now))
        feeds = [{"id": f["id"], "name": f["name"], "kind": f["kind"], "category": f["category"], "home": f["home"],
                  "points": f["points"], "entries": self.counts.get(f["id"], 0), "updated": self.updated.get(f["id"]),
                  "fresh": f["id"] in fresh, "enabled": f["id"] not in self.disabled, "error": self.errors.get(f["id"])} for f in FEEDS]
        updated = [f["updated"] for f in feeds if f["updated"]]
        return {"source": "Public threat feeds", "url": FEEDS[0]["home"], "updated": max(updated) if updated else None,
                "entries": sum(f["entries"] for f in feeds if f["fresh"]), "fresh": bool(fresh),
                "error": "; ".join(f["name"] + ": " + f["error"] for f in feeds if f["error"] and f["enabled"]) or None,
                "refreshing": self.lock.locked(), "feeds": feeds}

    def hit(self, feed, value):
        return {"feed": feed["id"], "name": feed["name"], "category": feed["category"], "points": feed["points"],
                "source": feed["home"], "malware": feed["category"], "value": value}

    def match(self, ip):
        """All fresh feed hits for an IP, strongest first. Cached per IP until the next feed change."""
        if ip in self.cache:
            return self.cache[ip]
        hits = []
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            addr = None
        if addr is not None and addr.is_global:
            value = int(addr); fresh = set(self.fresh_ids())
            for feed in FEEDS:
                structure = self.data.get(feed["id"])
                if feed["id"] not in fresh or feed["kind"] == "domain":
                    continue
                if feed["kind"] == "ip" and value in structure:
                    hits.append(self.hit(feed, ip))
                elif feed["kind"] == "cidr":
                    starts, ends = structure; i = bisect.bisect_right(starts, value) - 1
                    if i >= 0 and value <= ends[i]:
                        hits.append(self.hit(feed, ip))
            hits.sort(key=lambda h: -h["points"])
        if len(self.cache) > 20000:
            self.cache = {}
        self.cache[ip] = hits
        return hits

    def match_domain(self, domain):
        if not domain:
            return []
        labels = domain.lower().rstrip(".").split(".")
        candidates = {domain_hash(".".join(labels[i:])) for i in range(len(labels) - 1)}
        hits = []
        for feed_id in self.fresh_ids():
            feed = next(f for f in FEEDS if f["id"] == feed_id)
            if feed["kind"] != "domain":
                continue
            structure = self.data[feed_id]
            for value in candidates:
                i = bisect.bisect_left(structure, value)
                if i < len(structure) and structure[i] == value:
                    hits.append(self.hit(feed, domain)); break
        return hits

    def set_disabled(self, disabled):
        self.disabled = set(disabled); self.cache = {}

class Geolocation:
    def __init__(self):
        self.reader = None; self.path = ""; self.error = None; self.cache = {}

    def configure(self, path):
        if path == self.path:
            return
        self.close(); self.path = path; self.error = None; self.cache = {}
        if path:
            try:
                import maxminddb
                self.reader = maxminddb.open_database(path)
            except Exception as exc:
                self.error = str(exc)[:200]

    def lookup(self, ip):
        if not self.reader or not ipaddress.ip_address(ip).is_global:
            return None
        if ip in self.cache:
            return self.cache[ip]
        result = None
        try:
            r = self.reader.get(ip) or {}
            where = r.get("location") or {}; country = r.get("country") or {}
            if where.get("latitude") is not None and where.get("longitude") is not None:
                result = {"country": (country.get("names") or {}).get("en") or "Unknown", "code": country.get("iso_code") or "??",
                          "lat": where["latitude"], "lon": where["longitude"],
                          "city": ((r.get("city") or {}).get("names") or {}).get("en"), "accuracy_km": where.get("accuracy_radius")}
        except Exception:
            pass
        if len(self.cache) > 10000:
            self.cache.clear()
        self.cache[ip] = result
        return result

    def close(self):
        if self.reader:
            self.reader.close(); self.reader = None
