//! Bounded, local SQLite persistence. Same schema as the Python service, so existing data carries over.
use crate::intel::{now, FEEDS};
use crate::model::{Binary, Conn};
use rusqlite::{params, Connection, OptionalExtension};
use serde_json::{json, Map, Value};
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

pub const DEDUP_SECONDS: f64 = 12.0 * 3600.0;
pub const LEARNING_SECONDS: f64 = 600.0;
const BOOLEANS: [&str; 11] = ["notifications", "notify_medium", "feed_updates", "capture", "close_to_tray", "start_at_login",
                              "remote_alerts", "active_protection", "notify_new_apps", "onboarded", "auto_update"];

pub fn defaults() -> Map<String, Value> {
    json!({ "notifications": true, "notify_medium": false, "feed_updates": true, "capture": false, "retention_days": 7,
            "geoip_path": "", "close_to_tray": true, "start_at_login": false, "snoozed_until": 0, "disabled_feeds": [],
            "remote_alerts": true, "active_protection": false, "notify_new_apps": true, "onboarded": false, "auto_update": true })
    .as_object()
    .unwrap()
    .clone()
}

pub struct Store {
    pub directory: PathBuf,
    db: Mutex<Connection>,
    cached: Mutex<Option<Map<String, Value>>>,
    pub installed_at: Mutex<f64>,
    pub known_apps: Mutex<HashSet<String>>,
}

type R<T> = Result<T, String>;
fn e(err: rusqlite::Error) -> String {
    err.to_string()
}

impl Store {
    pub fn open(directory: &Path) -> R<Store> {
        std::fs::create_dir_all(directory).map_err(|e| e.to_string())?;
        let db = Connection::open(directory.join("beaver.sqlite3")).map_err(e)?;
        db.execute_batch(
            "PRAGMA journal_mode=WAL; PRAGMA busy_timeout=5000; PRAGMA synchronous=NORMAL;
             CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY, value TEXT NOT NULL);
             CREATE TABLE IF NOT EXISTS connections(id TEXT PRIMARY KEY, app_id TEXT, first_seen REAL, last_seen REAL, ended REAL, data TEXT NOT NULL);
             CREATE INDEX IF NOT EXISTS conn_app_time ON connections(app_id,last_seen DESC);
             CREATE INDEX IF NOT EXISTS conn_time ON connections(last_seen);
             CREATE TABLE IF NOT EXISTS alerts(id TEXT PRIMARY KEY, app_id TEXT, created REAL, acknowledged INTEGER DEFAULT 0, data TEXT NOT NULL);
             CREATE TABLE IF NOT EXISTS rules(id TEXT PRIMARY KEY, data TEXT NOT NULL);
             CREATE TABLE IF NOT EXISTS allowlist(id TEXT PRIMARY KEY, kind TEXT, target TEXT);
             CREATE TABLE IF NOT EXISTS binaries(path TEXT PRIMARY KEY, first_seen REAL, data TEXT NOT NULL);
             CREATE TABLE IF NOT EXISTS apps(path TEXT PRIMARY KEY, first_internet REAL NOT NULL);
             CREATE TABLE IF NOT EXISTS meta(key TEXT PRIMARY KEY, value REAL NOT NULL);",
        )
        .map_err(e)?;
        let has_key: bool = db.prepare("SELECT 1 FROM pragma_table_info('alerts') WHERE name='key'").map_err(e)?.exists([]).map_err(e)?;
        if !has_key {
            db.execute("ALTER TABLE alerts ADD COLUMN key TEXT", []).map_err(e)?;
        }
        db.execute_batch("CREATE INDEX IF NOT EXISTS alert_key ON alerts(key,created); UPDATE connections SET ended=last_seen WHERE ended IS NULL;").map_err(e)?;
        db.execute("INSERT OR IGNORE INTO meta VALUES ('installed_at', ?1)", [now()]).map_err(e)?;
        let installed: f64 = db.query_row("SELECT value FROM meta WHERE key='installed_at'", [], |r| r.get(0)).map_err(e)?;
        let known: HashSet<String> = db.prepare("SELECT path FROM apps").map_err(e)?.query_map([], |r| r.get(0)).map_err(e)?.flatten().collect();
        Ok(Store { directory: directory.to_path_buf(), db: Mutex::new(db), cached: Mutex::new(None), installed_at: Mutex::new(installed), known_apps: Mutex::new(known) })
    }

    pub fn settings(&self) -> Map<String, Value> {
        let mut cached = self.cached.lock().unwrap();
        if cached.is_none() {
            let mut s = defaults();
            let db = self.db.lock().unwrap();
            if let Ok(mut q) = db.prepare("SELECT key, value FROM settings") {
                for (k, v) in q.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))).into_iter().flatten().flatten() {
                    if let Ok(v) = serde_json::from_str(&v) {
                        s.insert(k, v);
                    }
                }
            }
            *cached = Some(s);
        }
        cached.clone().unwrap()
    }

    pub fn set_settings(&self, patch: &Map<String, Value>) -> R<Map<String, Value>> {
        let d = defaults();
        for (k, v) in patch {
            if !d.contains_key(k) {
                return Err("Unknown setting".into());
            }
            if BOOLEANS.contains(&k.as_str()) && !v.is_boolean() {
                return Err("Expected true or false".into());
            }
            match k.as_str() {
                "retention_days" if !v.as_i64().is_some_and(|n| (1..=30).contains(&n)) || v.is_f64() => return Err("Retention must be 1–30 days".into()),
                "geoip_path" if !v.as_str().is_some_and(|s| s.len() <= 4096) => return Err("Invalid database path".into()),
                "snoozed_until" if !v.as_f64().is_some_and(|n| n >= 0.0 && n <= now() + 7.0 * 86400.0) => {
                    return Err("Notifications can be paused for at most seven days".into())
                }
                "disabled_feeds" => {
                    let ok = v.as_array().is_some_and(|a| a.iter().all(|x| x.as_str().is_some_and(|s| FEEDS.iter().any(|f| f.id == s))));
                    if !ok {
                        return Err("Unknown threat feed".into());
                    }
                }
                _ => {}
            }
        }
        {
            let mut db = self.db.lock().unwrap();
            let tx = db.transaction().map_err(e)?;
            for (k, v) in patch {
                tx.execute("INSERT OR REPLACE INTO settings VALUES (?1, ?2)", params![k, v.to_string()]).map_err(e)?;
            }
            tx.commit().map_err(e)?;
        }
        *self.cached.lock().unwrap() = None;
        Ok(self.settings())
    }

    /// records: new or checkpointed live connections. ended: (id, last observed time).
    pub fn connections(&self, records: &[&Conn], ended: &[(String, f64)]) -> R<()> {
        let mut db = self.db.lock().unwrap();
        let tx = db.transaction().map_err(e)?;
        {
            let mut ins = tx.prepare_cached("INSERT OR REPLACE INTO connections VALUES (?1,?2,?3,?4,NULL,?5)").map_err(e)?;
            for r in records {
                ins.execute(params![r.id, r.app_id, r.first_seen, r.last_seen, serde_json::to_string(r).unwrap()]).map_err(e)?;
            }
            let mut end = tx.prepare_cached("UPDATE connections SET ended=?1, last_seen=?1 WHERE id=?2").map_err(e)?;
            for (id, seen) in ended {
                end.execute(params![seen, id]).map_err(e)?;
            }
        }
        tx.commit().map_err(e)
    }

    pub fn history(&self, app_id: &str, offset: i64, limit: i64) -> R<Value> {
        let (offset, limit) = (offset.clamp(0, 100_000), limit.clamp(1, 100));
        let db = self.db.lock().unwrap();
        let total: i64 = db.query_row("SELECT count(*) FROM connections WHERE app_id=?1", [app_id], |r| r.get(0)).map_err(e)?;
        let mut q = db.prepare("SELECT data, last_seen, ended FROM connections WHERE app_id=?1 ORDER BY last_seen DESC LIMIT ?2 OFFSET ?3").map_err(e)?;
        let items: Vec<Value> = q
            .query_map(params![app_id, limit, offset], |r| Ok((r.get::<_, String>(0)?, r.get::<_, f64>(1)?, r.get::<_, Option<f64>>(2)?)))
            .map_err(e)?
            .flatten()
            .filter_map(|(d, seen, ended)| {
                let mut v: Value = serde_json::from_str(&d).ok()?;
                v["last_seen"] = json!(seen);
                v["ended"] = json!(ended);
                Some(v)
            })
            .collect();
        Ok(json!({ "total": total, "items": items }))
    }

    /// Same application + same evidence rules within the dedup window is one alert; new evidence escalates.
    pub fn add_alert(&self, alert: &Value) -> R<bool> {
        let key = alert["key"].as_str().or(alert["app_id"].as_str()).unwrap_or("").to_string();
        let db = self.db.lock().unwrap();
        let recent = db.prepare("SELECT 1 FROM alerts WHERE key=?1 AND created>?2").map_err(e)?.exists(params![key, now() - DEDUP_SECONDS]).map_err(e)?;
        if recent {
            return Ok(false);
        }
        db.execute("INSERT INTO alerts(id,app_id,created,data,key) VALUES (?1,?2,?3,?4,?5)",
                   params![alert["id"].as_str(), alert["app_id"].as_str(), alert["created"].as_f64(), alert.to_string(), key])
            .map_err(e)?;
        Ok(true)
    }

    pub fn update_alert(&self, alert: &Value) -> R<()> {
        self.db.lock().unwrap().execute("UPDATE alerts SET data=?1 WHERE id=?2", params![alert.to_string(), alert["id"].as_str()]).map(|_| ()).map_err(e)
    }

    pub fn alerts(&self, limit: i64) -> Vec<Value> {
        let db = self.db.lock().unwrap();
        let Ok(mut q) = db.prepare("SELECT data, acknowledged FROM alerts ORDER BY created DESC LIMIT ?1") else { return vec![] };
        q.query_map([limit], |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?)))
            .into_iter()
            .flatten()
            .flatten()
            .filter_map(|(d, ack)| {
                let mut v: Value = serde_json::from_str(&d).ok()?;
                v["acknowledged"] = json!(ack != 0);
                Some(v)
            })
            .collect()
    }

    pub fn alert_counts(&self) -> Map<String, Value> {
        let db = self.db.lock().unwrap();
        let mut out = Map::new();
        if let Ok(mut q) = db.prepare("SELECT json_extract(data,'$.level'), count(*) FROM alerts WHERE acknowledged=0 GROUP BY 1") {
            for (level, n) in q.query_map([], |r| Ok((r.get::<_, Option<String>>(0)?, r.get::<_, i64>(1)?))).into_iter().flatten().flatten() {
                out.insert(level.unwrap_or_default(), json!(n));
            }
        }
        out
    }

    pub fn acknowledge(&self, id: &str) -> R<()> {
        let db = self.db.lock().unwrap();
        if id == "*" {
            db.execute("UPDATE alerts SET acknowledged=1 WHERE acknowledged=0", [])
        } else {
            db.execute("UPDATE alerts SET acknowledged=1 WHERE id=?1", [id])
        }
        .map(|_| ())
        .map_err(e)
    }

    pub fn rules(&self) -> Vec<Value> {
        let db = self.db.lock().unwrap();
        let Ok(mut q) = db.prepare("SELECT data FROM rules") else { return vec![] };
        q.query_map([], |r| r.get::<_, String>(0)).into_iter().flatten().flatten().filter_map(|d| serde_json::from_str(&d).ok()).collect()
    }

    pub fn put_rule(&self, rule: &Value) -> R<()> {
        self.db.lock().unwrap().execute("INSERT OR REPLACE INTO rules VALUES (?1,?2)", params![rule["id"].as_str(), rule.to_string()]).map(|_| ()).map_err(e)
    }

    pub fn delete_rule(&self, id: &str) -> R<()> {
        self.db.lock().unwrap().execute("DELETE FROM rules WHERE id=?1", [id]).map(|_| ()).map_err(e)
    }

    pub fn allowlist(&self) -> Vec<Value> {
        let db = self.db.lock().unwrap();
        let Ok(mut q) = db.prepare("SELECT id, kind, target FROM allowlist") else { return vec![] };
        q.query_map([], |r| Ok(json!({ "id": r.get::<_, String>(0)?, "kind": r.get::<_, String>(1)?, "target": r.get::<_, String>(2)? })))
            .into_iter()
            .flatten()
            .flatten()
            .collect()
    }

    pub fn allow(&self, id: &str, kind: &str, target: &str, enabled: bool) -> R<()> {
        let db = self.db.lock().unwrap();
        if enabled {
            db.execute("INSERT OR REPLACE INTO allowlist VALUES (?1,?2,?3)", params![id, kind, target])
        } else {
            db.execute("DELETE FROM allowlist WHERE id=?1", [id])
        }
        .map(|_| ())
        .map_err(e)
    }

    /// Cached inspection, or None when missing or the file was replaced since.
    pub fn binary(&self, path: &str) -> Option<Binary> {
        let row: Option<(f64, String)> = self
            .db
            .lock()
            .unwrap()
            .query_row("SELECT first_seen, data FROM binaries WHERE path=?1", [path], |r| Ok((r.get(0)?, r.get(1)?)))
            .optional()
            .ok()
            .flatten();
        let (first, data) = row?;
        let mut b: Binary = serde_json::from_str(&data).ok()?;
        b.first_seen = Some(first);
        if let Ok(m) = std::fs::metadata(path) {
            if (Some(m.len()), Some(crate::binaries::mtime(&m))) != (b.size, b.mtime) {
                return None;
            }
        }
        Some(b)
    }

    pub fn put_binary(&self, b: &Binary) -> R<f64> {
        let db = self.db.lock().unwrap();
        let first: f64 = db
            .query_row("SELECT first_seen FROM binaries WHERE path=?1", [&b.path], |r| r.get(0))
            .optional()
            .map_err(e)?
            .unwrap_or_else(now);
        db.execute("INSERT OR REPLACE INTO binaries VALUES (?1,?2,?3)", params![b.path, first, serde_json::to_string(b).unwrap()]).map_err(e)?;
        db.execute("DELETE FROM binaries WHERE path IN (SELECT path FROM binaries ORDER BY first_seen DESC LIMIT -1 OFFSET 20000)", []).map_err(e)?;
        Ok(first)
    }

    pub fn learning(&self) -> bool {
        now() - *self.installed_at.lock().unwrap() < LEARNING_SECONDS
    }

    /// True exactly once per executable path: the first time it reaches the internet.
    pub fn first_internet(&self, path: &str) -> bool {
        if !self.known_apps.lock().unwrap().insert(path.to_string()) {
            return false;
        }
        let _ = self.db.lock().unwrap().execute("INSERT OR IGNORE INTO apps VALUES (?1,?2)", params![path, now()]);
        true
    }

    pub fn is_known(&self, path: &str) -> bool {
        self.known_apps.lock().unwrap().contains(path)
    }

    pub fn prune(&self) -> R<()> {
        let days = self.settings().get("retention_days").and_then(Value::as_f64).unwrap_or(7.0);
        let cutoff = now() - days * 86400.0;
        let db = self.db.lock().unwrap();
        db.execute("DELETE FROM connections WHERE last_seen<?1", [cutoff]).map_err(e)?;
        db.execute("DELETE FROM alerts WHERE created<?1", [cutoff]).map_err(e)?;
        db.execute_batch(
            "DELETE FROM connections WHERE id IN (SELECT id FROM connections ORDER BY last_seen DESC LIMIT -1 OFFSET 100000);
             DELETE FROM alerts WHERE id IN (SELECT id FROM alerts ORDER BY created DESC LIMIT -1 OFFSET 10000);",
        )
        .map_err(e)
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;

    pub fn temp() -> (Store, PathBuf) {
        let dir = std::env::temp_dir().join(format!("bv-store-{}-{}", std::process::id(), rand_suffix()));
        (Store::open(&dir).unwrap(), dir)
    }
    fn rand_suffix() -> u128 {
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
    }

    #[test]
    fn settings_validation() {
        let (s, dir) = temp();
        assert_eq!(s.set_settings(json!({"retention_days": 3}).as_object().unwrap()).unwrap()["retention_days"], 3);
        for bad in [json!({"retention_days": 0}), json!({"capture": "true"}), json!({"unknown": true}), json!({"retention_days": true}),
                    json!({"disabled_feeds": ["nope"]}), json!({"snoozed_until": now() + 30.0 * 86400.0}), json!({"active_protection": 1})] {
            assert!(s.set_settings(bad.as_object().unwrap()).is_err(), "{bad}");
        }
        assert_eq!(s.settings()["remote_alerts"], true);
        drop(s);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn alerts_dedup_escalation_ack() {
        let (s, dir) = temp();
        let a = json!({"id": "first", "app_id": "a", "created": now(), "key": "a|Medium|beaconing", "level": "Medium"});
        assert!(s.add_alert(&a).unwrap());
        let mut b = a.clone();
        b["id"] = json!("second");
        assert!(!s.add_alert(&b).unwrap());
        let mut c = a.clone();
        c["id"] = json!("third");
        c["key"] = json!("a|High|known-c2");
        c["level"] = json!("High");
        assert!(s.add_alert(&c).unwrap());
        assert_eq!(s.alert_counts().len(), 2);
        s.acknowledge("*").unwrap();
        assert!(s.alerts(200).iter().all(|a| a["acknowledged"] == true));
        assert!(s.first_internet("C:\\a.exe") && !s.first_internet("C:\\a.exe") && s.learning());
        drop(s);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn history_is_parameterized() {
        let (s, dir) = temp();
        let conns: Vec<Conn> = (0..5)
            .map(|i| Conn { id: i.to_string(), app_id: "app' OR 1=1--".into(), pid: None, process_created: None, local_ip: "x".into(), local_port: 1,
                            remote_ip: None, remote_port: None, protocol: "TCP".into(), status: "LISTEN".into(), source: "s".into(),
                            first_seen: now(), last_seen: now(), domain: None, geo: None, threat: None })
            .collect();
        let refs: Vec<&Conn> = conns.iter().collect();
        s.connections(&refs, &[("0".into(), now())]).unwrap();
        assert_eq!(s.history("app' OR 1=1--", 0, 2).unwrap()["total"], 5);
        assert_eq!(s.history("other", 0, 50).unwrap()["total"], 0);
        drop(s);
        let _ = std::fs::remove_dir_all(dir);
    }
}
