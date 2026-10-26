"""Background executable inspection: SHA-256, Authenticode status (Windows) and install location.
Results are cached per path+size+mtime, so each binary version is hashed and verified once."""
import base64
import hashlib
import json
import logging
import os
import platform
import queue
import subprocess
import threading
import time

MAX_HASH_BYTES = 512 * 1024 * 1024
WINDOWS_SYSTEM = ("c:/windows/system32/", "c:/windows/syswow64/", "c:/windows/winsxs/", "c:/windows/")
WINDOWS_MANAGED = ("c:/program files/", "c:/program files (x86)/", "c:/programdata/microsoft/windows defender/")
LINUX_MANAGED = ("/usr/", "/bin/", "/sbin/", "/lib/", "/lib64/", "/opt/", "/snap/", "/var/lib/flatpak/", "/nix/store/", "/app/")

SIGNATURE_SCRIPT = (
    "$ErrorActionPreference='SilentlyContinue';"
    "$paths=[Console]::In.ReadToEnd()|ConvertFrom-Json;"
    "$out=@(foreach($p in $paths){$s=Get-AuthenticodeSignature -LiteralPath $p;"
    "[pscustomobject]@{path=$p;status=[string]$s.Status;subject=[string]$s.SignerCertificate.Subject;"
    "os=[bool]$s.IsOSBinary}});"
    "ConvertTo-Json -InputObject $out -Compress")

def normalized(path):
    return (path or "").replace("\\", "/").lower()

def location(path, system=None):
    """Classify where an executable lives; user-writable staging folders are a classic malware trait."""
    system = system or platform.system(); p = normalized(path)
    if system == "Windows":
        if any(s in p for s in ("/appdata/local/temp/", "/windows/temp/", "/$recycle.bin/", "/users/public/", "/downloads/")):
            return "staging"
        if p.startswith(WINDOWS_MANAGED) or p.startswith(WINDOWS_SYSTEM):
            return "system"
        return "user"
    if p.startswith("/dev/shm/"):
        return "memory"
    if p.startswith(("/tmp/", "/var/tmp/")) or "/downloads/" in p or "/.cache/" in p:
        return "staging"
    if p.startswith(LINUX_MANAGED):
        return "system"
    return "user"

def publisher(subject):
    for part in (subject or "").split(","):
        part = part.strip()
        if part.startswith("CN="):
            return part[3:].strip('"')[:200]
    return None

def sha256(path):
    digest = hashlib.sha256(); size = 0
    with open(path, "rb") as handle:
        while block := handle.read(1024 * 1024):
            size += len(block)
            if size > MAX_HASH_BYTES:
                return None
            digest.update(block)
    return digest.hexdigest()

class Binaries:
    def __init__(self, store, runner=subprocess.run):
        self.store = store; self.runner = runner; self.system = platform.system()
        self.cache = {}; self.pending = set(); self.queue = queue.Queue(); self.lock = threading.Lock()
        self.thread = None; self.error = None

    def key(self, path):
        try:
            st = os.stat(path)
            return (path, st.st_size, int(st.st_mtime))
        except OSError:
            return None

    def info(self, path):
        """Return cached inspection, or schedule one and return a pending record. Never blocks sampling."""
        if not path:
            return None
        with self.lock:
            cached = self.cache.get(path)
            if cached:
                return cached
            stored = self.store.binary(path)
            if stored:
                self.cache[path] = stored
                return stored
            if path not in self.pending:
                self.pending.add(path); self.queue.put(path)
                if not self.thread or not self.thread.is_alive():
                    self.thread = threading.Thread(target=self.work, name="beaver-binaries", daemon=True); self.thread.start()
        return {"path": path, "state": "pending", "location": location(path, self.system)}

    def forget_missing(self, alive_paths):
        with self.lock:
            if len(self.cache) > 2000:
                self.cache = {k: v for k, v in self.cache.items() if k in alive_paths}

    def work(self):
        while True:
            try:
                batch = [self.queue.get(timeout=30)]
            except queue.Empty:
                return
            time.sleep(0.5)  # coalesce a startup burst into one verification process
            while len(batch) < 40:
                try:
                    batch.append(self.queue.get_nowait())
                except queue.Empty:
                    break
            try:
                self.inspect(batch)
            except Exception as exc:
                self.error = str(exc)[:300]
                logging.getLogger("beaver").warning("Executable inspection failed: %s", exc)
            with self.lock:
                self.pending.difference_update(batch)

    def signatures(self, paths):
        if self.system != "Windows" or not paths:
            return {}
        encoded = base64.b64encode(SIGNATURE_SCRIPT.encode("utf-16-le")).decode("ascii")
        result = self.runner(["powershell.exe", "-NoProfile", "-NonInteractive", "-EncodedCommand", encoded],
                             input=json.dumps(paths), capture_output=True, text=True, timeout=120, creationflags=0x08000000)
        if result.returncode:
            raise RuntimeError("Signature verification failed: " + (result.stderr or "")[-200:])
        rows = json.loads(result.stdout or "[]")
        return {row["path"]: row for row in (rows if isinstance(rows, list) else [rows])}

    def inspect(self, paths):
        keys = {p: self.key(p) for p in paths}
        present = [p for p, k in keys.items() if k]
        signatures = self.signatures(present)
        for path in paths:
            record = {"path": path, "state": "inspected", "location": location(path, self.system), "inspected": time.time()}
            if not keys[path]:
                record |= {"state": "unavailable", "detail": "The executable could not be read for inspection."}
            else:
                record["size"] = keys[path][1]; record["mtime"] = keys[path][2]
                try:
                    record["sha256"] = sha256(path)
                except OSError as exc:
                    record["sha256"] = None; record["detail"] = str(exc)[:200]
                sig = signatures.get(path)
                if self.system != "Windows":
                    record["signature"] = None
                elif sig:
                    status = sig.get("status") or "UnknownError"
                    record["signature"] = {"Valid": "valid", "NotSigned": "unsigned", "HashMismatch": "tampered",
                                           "NotTrusted": "untrusted"}.get(status, "unknown")
                    record["signature_status"] = status; record["publisher"] = publisher(sig.get("subject"))
                    record["os_binary"] = bool(sig.get("os"))
                else:
                    record["signature"] = "unknown"
            first = self.store.put_binary(record)
            record["first_seen"] = first
            with self.lock:
                self.cache[path] = record

