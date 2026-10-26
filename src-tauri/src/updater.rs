//! Updates from GitHub Releases. Windows: download the installer, verify it against the release's
//! SHA256SUMS.txt, install silently on request. Linux: point to the release (package managers own upgrades).
use crate::{log, notify, state};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::time::Duration;
use tauri::{AppHandle, Emitter, Manager};

const LATEST: &str = "https://api.github.com/repos/AmoghShukla06/Beaver/releases/latest";

fn version(v: &str) -> Vec<u64> {
    v.trim_start_matches('v').split('.').map(|p| p.chars().take_while(char::is_ascii_digit).collect::<String>().parse().unwrap_or(0)).collect()
}

fn agent() -> ureq::Agent {
    ureq::Agent::config_builder().timeout_global(Some(Duration::from_secs(300))).build().into()
}

fn get(url: &str, limit: u64) -> Result<Vec<u8>, String> {
    let mut r = agent().get(url).header("User-Agent", "Beaver-updater").header("Accept", "application/octet-stream, application/json").call().map_err(|e| e.to_string())?;
    r.body_mut().with_config().limit(limit).read_to_vec().map_err(|e| e.to_string())
}

fn set(app: &AppHandle, value: Value) {
    let st = state(app);
    let mut u = st.update.lock().unwrap();
    if let (Some(cur), Some(new)) = (u.as_object_mut(), value.as_object()) {
        for (k, v) in new {
            cur.insert(k.clone(), v.clone());
        }
    }
    let snapshot = u.clone();
    drop(u);
    if let Some(w) = app.get_webview_window("main") {
        let _ = w.emit("beaver:update", snapshot);
    }
}

pub fn check(app: &AppHandle) {
    if state(app).update.lock().unwrap()["state"] == "ready" {
        return;
    }
    set(app, json!({ "state": "checking", "error": null }));
    let result = (|| -> Result<(), String> {
        let release: Value = serde_json::from_slice(&get(LATEST, 2_000_000)?).map_err(|e| e.to_string())?;
        let tag = release["tag_name"].as_str().ok_or("No release found")?;
        let current = app.package_info().version.to_string();
        if version(tag) <= version(&current) {
            set(app, json!({ "state": "latest", "checked_at": crate::now() }));
            return Ok(());
        }
        let latest = tag.trim_start_matches('v').to_string();
        let assets = release["assets"].as_array().cloned().unwrap_or_default();
        let url_of = |pred: &dyn Fn(&str) -> bool| assets.iter().find(|a| a["name"].as_str().is_some_and(|n| pred(n))).and_then(|a| a["browser_download_url"].as_str().map(String::from));
        if !cfg!(windows) {
            set(app, json!({ "state": "available", "version": latest, "url": release["html_url"] }));
            return Ok(());
        }
        let installer = url_of(&|n: &str| n.ends_with("-setup.exe")).ok_or("Release has no Windows installer")?;
        let sums = url_of(&|n: &str| n == "SHA256SUMS.txt").ok_or("Release has no checksums")?;
        let name = installer.rsplit('/').next().unwrap_or("Beaver-setup.exe").to_string();
        let expected = String::from_utf8_lossy(&get(&sums, 100_000)?)
            .lines()
            .find(|l| l.trim_end().ends_with(&name))
            .and_then(|l| l.split_whitespace().next().map(str::to_lowercase))
            .ok_or("Installer is missing from the checksums")?;
        set(app, json!({ "state": "downloading", "version": latest, "percent": 0 }));
        let bytes = get(&installer, 400_000_000)?;
        let actual: String = Sha256::digest(&bytes).iter().map(|b| format!("{b:02x}")).collect();
        if actual != expected {
            return Err("Downloaded installer failed verification".into());
        }
        let file = std::env::temp_dir().join(&name);
        std::fs::write(&file, bytes).map_err(|e| e.to_string())?;
        set(app, json!({ "state": "ready", "version": latest, "file": file.to_string_lossy() }));
        log(&format!("update downloaded and verified: {latest}"));
        notify(app, &format!("Beaver {latest} is ready"), "Restart Beaver to finish updating. Monitoring resumes automatically.", false,
               json!({ "page": "settings" }), vec![crate::Action { label: "Restart now", id: "update".into() }], None);
        Ok(())
    })();
    if let Err(e) = result {
        log(&format!("update check failed: {e}"));
        set(app, json!({ "state": "error", "error": "Could not reach GitHub Releases", "checked_at": crate::now() }));
    }
}

/// Run the verified installer silently and exit; the installer replaces files and relaunches Beaver.
pub fn install(app: &AppHandle) {
    let update = state(app).update.lock().unwrap().clone();
    if cfg!(windows) {
        let Some(file) = update["file"].as_str() else { return };
        log("installing update");
        if std::process::Command::new(file).args(["/S", "/UPDATE", "/R"]).spawn().is_ok() {
            crate::quit(app);
        }
    } else if let Some(url) = update["url"].as_str() {
        use tauri_plugin_opener::OpenerExt;
        let _ = app.opener().open_url(url, None::<&str>);
    }
}

/// Checks 30 s after start and every 6 hours while automatic updates are on.
pub fn schedule(app: &AppHandle) {
    if cfg!(debug_assertions) {
        return;
    }
    set(app, json!({ "state": "idle" }));
    let app = app.clone();
    std::thread::spawn(move || {
        std::thread::sleep(Duration::from_secs(30));
        loop {
            if state(&app).shell.lock().unwrap().settings["auto_update"] != false {
                check(&app);
            }
            std::thread::sleep(Duration::from_secs(6 * 3600));
        }
    });
}

#[cfg(test)]
mod tests {
    #[test]
    fn versions() {
        assert!(super::version("v2.0.1") > super::version("2.0.0"));
        assert!(super::version("v2.10.0") > super::version("2.9.9"));
    }
}
