"""Bounded, local SQLite persistence. No payloads or credentials are recorded."""
import json
import os
import sqlite3
import threading
import time
from pathlib import Path

DEFAULTS = {"notifications": True, "notify_medium": False, "feed_updates": True, "capture": False,
            "retention_days": 7, "geoip_path": "", "close_to_tray": True, "start_at_login": False,
            "snoozed_until": 0, "disabled_feeds": [], "remote_alerts": True, "active_protection": False,
            "notify_new_apps": True, "onboarded": False, "auto_update": True}
BOOLEANS = ("notifications", "notify_medium", "feed_updates", "capture", "close_to_tray", "start_at_login",
            "remote_alerts", "active_protection", "notify_new_apps", "onboarded", "auto_update")
LEARNING_SECONDS = 600  # after first install, record existing apps silently instead of alerting on each
DEDUP_SECONDS = 12 * 3600

class Store:
    def __init__(self, directory):
        self.directory = Path(directory)
        self.directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.lock = threading.RLock()
        self.db = sqlite3.connect(self.directory / "beaver.sqlite3", check_same_thread=False)
        self.db.row_factory = sqlite3.Row
        self.db.executescript("""
            PRAGMA journal_mode=WAL; PRAGMA busy_timeout=5000; PRAGMA synchronous=NORMAL;
            CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY, value TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS connections(id TEXT PRIMARY KEY, app_id TEXT, first_seen REAL,
                last_seen REAL, ended REAL, data TEXT NOT NULL);
            CREATE INDEX IF NOT EXISTS conn_app_time ON connections(app_id,last_seen DESC);
            CREATE INDEX IF NOT EXISTS conn_time ON connections(last_seen);
            CREATE TABLE IF NOT EXISTS alerts(id TEXT PRIMARY KEY, app_id TEXT, created REAL,
                acknowledged INTEGER DEFAULT 0, data TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS rules(id TEXT PRIMARY KEY, data TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS allowlist(id TEXT PRIMARY KEY, kind TEXT, target TEXT);
            CREATE TABLE IF NOT EXISTS binaries(path TEXT PRIMARY KEY, first_seen REAL, data TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS apps(path TEXT PRIMARY KEY, first_internet REAL NOT NULL);
            CREATE TABLE IF NOT EXISTS meta(key TEXT PRIMARY KEY, value REAL NOT NULL);
        """)
        self.db.execute("INSERT OR IGNORE INTO meta VALUES ('installed_at', ?)", (time.time(),))
        self.installed_at = self.db.execute("SELECT value FROM meta WHERE key='installed_at'").fetchone()[0]
        self.known_apps = {r[0] for r in self.db.execute("SELECT path FROM apps")}
        if "key" not in {r["name"] for r in self.db.execute("PRAGMA table_info(alerts)")}:
            self.db.execute("ALTER TABLE alerts ADD COLUMN key TEXT")
        self.db.execute("CREATE INDEX IF NOT EXISTS alert_key ON alerts(key,created)")
        self.db.execute("UPDATE connections SET ended=last_seen WHERE ended IS NULL")
        self.db.commit()
        self.cached_settings = None

    def settings(self):
        with self.lock:
            if self.cached_settings is None:
                self.cached_settings = DEFAULTS | {r["key"]: json.loads(r["value"]) for r in self.db.execute("SELECT * FROM settings")}
            return dict(self.cached_settings)

    def set_settings(self, patch):
        from .intelligence import FEED_IDS
        for key, value in patch.items():
            if key not in DEFAULTS:
                raise ValueError("Unknown setting")
            if key in BOOLEANS and type(value) is not bool:
                raise ValueError("Expected true or false")
            if key == "retention_days" and (type(value) is not int or not 1 <= value <= 30):
                raise ValueError("Retention must be 1–30 days")
            if key == "geoip_path" and (not isinstance(value, str) or len(value) > 4096):
                raise ValueError("Invalid database path")
            if key == "snoozed_until" and (type(value) not in (int, float) or not 0 <= value <= time.time() + 7 * 86400):
                raise ValueError("Notifications can be paused for at most seven days")
            if key == "disabled_feeds" and (not isinstance(value, list) or not set(value) <= FEED_IDS):
                raise ValueError("Unknown threat feed")
        with self.lock, self.db:
            self.db.executemany("INSERT OR REPLACE INTO settings VALUES (?,?)", [(k, json.dumps(v)) for k, v in patch.items()])
            self.cached_settings = None
        return self.settings()

    def connections(self, records, ended):
        """records: new or checkpointed live connections. ended: (id, last observed time)."""
        with self.lock, self.db:
            self.db.executemany("INSERT OR REPLACE INTO connections VALUES (?,?,?,?,NULL,?)",
                [(r["id"], r["app_id"], r["first_seen"], r["last_seen"], json.dumps(r)) for r in records])
            self.db.executemany("UPDATE connections SET ended=?,last_seen=? WHERE id=?", [(seen, seen, i) for i, seen in ended])

    def history(self, app_id, offset=0, limit=50):
        offset = max(0, min(int(offset), 100000)); limit = max(1, min(int(limit), 100))
        with self.lock:
            total = self.db.execute("SELECT count(*) FROM connections WHERE app_id=?", (app_id,)).fetchone()[0]
            rows = self.db.execute("SELECT * FROM connections WHERE app_id=? ORDER BY last_seen DESC LIMIT ? OFFSET ?", (app_id, limit, offset)).fetchall()
        return {"total": total, "items": [json.loads(r["data"]) | {"last_seen": r["last_seen"], "ended": r["ended"]} for r in rows]}

    def add_alert(self, alert):
        """Same application + same evidence rules within the dedup window is one alert; new evidence escalates."""
        key = alert.get("key") or alert["app_id"]
        with self.lock, self.db:
            recent = self.db.execute("SELECT 1 FROM alerts WHERE key=? AND created>?", (key, time.time() - DEDUP_SECONDS)).fetchone()
            if recent:
                return False
            self.db.execute("INSERT INTO alerts(id,app_id,created,data,key) VALUES (?,?,?,?,?)",
                            (alert["id"], alert["app_id"], alert["created"], json.dumps(alert), key))
        return True

    def learning(self):
        return time.time() - self.installed_at < LEARNING_SECONDS

    def first_internet(self, path):
        """True exactly once per executable path: the first time it reaches the internet."""
        if path in self.known_apps:
            return False
        with self.lock, self.db:
            self.db.execute("INSERT OR IGNORE INTO apps VALUES (?,?)", (path, time.time()))
        self.known_apps.add(path)
        return True

    def update_alert(self, alert):
        with self.lock, self.db:
            self.db.execute("UPDATE alerts SET data=? WHERE id=?", (json.dumps(alert), alert["id"]))

    def alerts(self, limit=200):
        with self.lock:
            return [json.loads(r["data"]) | {"acknowledged": bool(r["acknowledged"])}
                    for r in self.db.execute("SELECT * FROM alerts ORDER BY created DESC LIMIT ?", (limit,))]

    def alert_counts(self):
        with self.lock:
            rows = self.db.execute("SELECT json_extract(data,'$.level') level, count(*) n FROM alerts WHERE acknowledged=0 GROUP BY level").fetchall()
        return {r["level"]: r["n"] for r in rows}

    def acknowledge(self, alert_id):
        with self.lock, self.db:
            if alert_id == "*":
                self.db.execute("UPDATE alerts SET acknowledged=1 WHERE acknowledged=0")
            else:
                self.db.execute("UPDATE alerts SET acknowledged=1 WHERE id=?", (alert_id,))

    def rules(self):
        with self.lock:
            return [json.loads(r[0]) for r in self.db.execute("SELECT data FROM rules")]

    def put_rule(self, rule):
        with self.lock, self.db:
            self.db.execute("INSERT OR REPLACE INTO rules VALUES (?,?)", (rule["id"], json.dumps(rule)))

    def delete_rule(self, rule_id):
        with self.lock, self.db:
            self.db.execute("DELETE FROM rules WHERE id=?", (rule_id,))

    def allowlist(self):
        with self.lock:
            return [dict(r) for r in self.db.execute("SELECT * FROM allowlist")]

    def allow(self, entry, enabled):
        with self.lock, self.db:
            if enabled:
                self.db.execute("INSERT OR REPLACE INTO allowlist VALUES (?,?,?)", (entry["id"], entry["kind"], entry["target"]))
            else:
                self.db.execute("DELETE FROM allowlist WHERE id=?", (entry["id"],))

    def binary(self, path):
        with self.lock:
            row = self.db.execute("SELECT * FROM binaries WHERE path=?", (path,)).fetchone()
        if not row:
            return None
        record = json.loads(row["data"]) | {"first_seen": row["first_seen"]}
        try:
            st = os.stat(path)
            if (st.st_size, int(st.st_mtime)) != (record.get("size"), record.get("mtime")):
                return None  # replaced binary: inspect the new version
        except OSError:
            pass
        return record

    def put_binary(self, record):
        with self.lock, self.db:
            row = self.db.execute("SELECT first_seen FROM binaries WHERE path=?", (record["path"],)).fetchone()
            first = row["first_seen"] if row else time.time()
            self.db.execute("INSERT OR REPLACE INTO binaries VALUES (?,?,?)", (record["path"], first, json.dumps(record)))
            self.db.execute("DELETE FROM binaries WHERE path IN (SELECT path FROM binaries ORDER BY first_seen DESC LIMIT -1 OFFSET 20000)")
        return first

    def prune(self):
        cutoff = time.time() - self.settings()["retention_days"] * 86400
        with self.lock, self.db:
            self.db.execute("DELETE FROM connections WHERE last_seen<?", (cutoff,))
            self.db.execute("DELETE FROM alerts WHERE created<?", (cutoff,))
            self.db.execute("DELETE FROM connections WHERE id IN (SELECT id FROM connections ORDER BY last_seen DESC LIMIT -1 OFFSET 100000)")
            self.db.execute("DELETE FROM alerts WHERE id IN (SELECT id FROM alerts ORDER BY created DESC LIMIT -1 OFFSET 10000)")

    def close(self):
        with self.lock:
            self.db.close()
