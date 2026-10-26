// End-to-end tests against the real Tauri desktop app and Rust service, with a temporary data directory.
// Usage: node scripts/test-tauri.cjs [path-to-beaver.exe]   (build with: npm run tauri:debug)
const { spawn, execFileSync } = require("node:child_process");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { attach, wait } = require("./cdp.cjs");
const root = path.resolve(__dirname, "..");
const exe = process.argv[2] || path.join(root, "target", "debug", process.platform === "win32" ? "beaver.exe" : "beaver");
const output = process.env.BEAVER_QA_OUTPUT || path.join(os.tmpdir(), "beaver-qa");
const passed = [];
const PORT = 9341;

(async () => {
  fs.mkdirSync(output, { recursive: true });
  const data = fs.mkdtempSync(path.join(os.tmpdir(), "beaver-tauri-test-"));
  const env = { ...process.env, BEAVER_TEST_DATA: data, WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS: `--remote-debugging-port=${PORT}` };
  const app = spawn(exe, [], { env, stdio: "ignore" });
  let page;
  try {
    page = await attach(PORT);
    await page.until(() => document.querySelector("dialog.onboarding")?.open, 40000);
    assert.equal(await page.eval(() => typeof window.beaver.snapshot), "function");
    assert.equal(await page.eval(() => typeof window.require + typeof window.process), "undefinedundefined");
    passed.push("Tauri bridge exposes the Beaver API; no Node globals in the page");

    const axe = fs.readFileSync(require.resolve("axe-core/axe.min.js"), "utf8");
    await page.send("Runtime.evaluate", { expression: axe });
    const scan = async (name) => {
      const v = await page.eval(async () => (await window.axe.run(document)).violations.map((x) => x.id));
      assert.deepEqual(v, [], name + ": " + v.join(", "));
    };
    await scan("setup wizard");
    await page.click("Continue");
    await page.until(() => document.body.innerText.includes("See which website every app talks to"));
    await page.click("Continue");
    await page.click("Start protecting");
    await page.until(async () => (await window.beaver.snapshot()).settings.onboarded === true);
    await page.until(() => !document.querySelector("dialog.onboarding"));
    passed.push("First-run setup completes and is accessible");

    await page.until(() => document.body.innerText.includes("Live monitoring"), 30000);
    const live = await page.eval(() => window.beaver.snapshot());
    assert(live.apps.length > 0 && live.connections.length > 0);
    passed.push(`Real OS connections render (${live.apps.length} apps, ${live.connections.length} sockets)`);
    await scan("overview");
    passed.push("Overview accessibility scan");
    await page.screenshot(path.join(output, "tauri-overview.png"));

    await page.click("Applications");
    await page.until(() => document.querySelector("input[aria-label^='Search applications']"));
    await page.type("input[aria-label^='Search applications']", "this-app-does-not-exist-beaver");
    await page.until(() => document.body.innerText.includes("No matching applications"));
    await page.type("input[aria-label^='Search applications']", "");
    passed.push("Application search and empty state");
    await page.until(() => document.querySelector("button.app-name"));
    await page.eval(() => document.querySelector("button.app-name").click());
    await page.until(() => document.body.innerText.includes("Why this risk level?") && document.body.innerText.includes("Connection history"));
    passed.push("Investigation with local history");
    await page.click("All applications");

    await page.click("Remote shield");
    await page.until(() => document.body.innerText.includes("Remote access & data-theft shield"));
    await scan("remote shield");
    passed.push("Remote shield renders and passes accessibility scan");

    await page.click("Connections");
    await page.until(() => document.querySelector(".connection-table, .empty"));
    await page.click("All");
    await page.until(() => document.querySelectorAll(".connection-table tbody tr").length > 0);
    passed.push("Connection search lists real sockets");

    await page.click("World map");
    await page.until(() => document.querySelectorAll(".country").length > 170, 30000);
    passed.push("Offline political map renders");

    await page.click("Settings");
    await page.eval(() => window.beaver.settings({ patch: { retention_days: 3 } }));
    assert.equal((await page.eval(() => window.beaver.snapshot())).settings.retention_days, 3);
    passed.push("Settings persist through the Rust service");
    const feed = await page.eval(() => window.beaver.refresh_feed().then((s) => s, (e) => ({ error: String(e) })));
    assert(feed.entries > 0 || feed.error, JSON.stringify(feed).slice(0, 300));
    passed.push(feed.entries ? `Real HTTPS threat feeds downloaded (${feed.entries} indicators)` : "Feed failure displayed: " + feed.error);
    await page.eval(() => window.beaver.settings({ patch: { capture: true } }));
    const capture = await page.until(async () => {
      const c = (await window.beaver.snapshot()).coverage.capture;
      return c.active || c.error ? c : false;
    }, 20000);
    passed.push("Capture capability truthful: " + (capture.active ? `active on ${capture.interfaces} interfaces` : capture.error));
    await page.eval(() => window.beaver.settings({ patch: { capture: false } }));
    assert.deepEqual(await page.eval(() => window.beaver.test_notification()), { ok: true });
    passed.push("Native notification invoked");
    const info = await page.eval(() => window.beaver.app_info());
    assert(info.version && info.runtime.startsWith("Tauri"));
    passed.push(`About: Beaver ${info.version} on ${info.runtime}`);
    await page.eval(() => window.beaver.copy_diagnostics());
    if (process.platform === "win32") {
      const clip = execFileSync("powershell.exe", ["-NoProfile", "-Command", "Get-Clipboard -Raw"]).toString();
      assert(clip.includes("## Beaver diagnostics"));
      assert(!clip.toLowerCase().includes(os.userInfo().username.toLowerCase()), "diagnostics leaked the username");
      passed.push("Diagnostics copied with the username redacted");
    }
    await page.screenshot(path.join(output, "tauri-settings.png"));
    await scan("settings");
    passed.push("Settings accessibility scan");
    const icons = await page.eval(() => window.beaver.snapshot().then((s) => s.apps.find((a) => a.path)?.path)).then((p) => page.eval((p) => window.beaver.icon({ path: p }), p));
    if (process.platform === "win32") {
      assert(String(icons).startsWith("data:image/png;base64,"));
      passed.push("Real executable icons are served");
    }

    assert.deepEqual(page.errors, []);
    passed.push("No renderer exceptions");

    // Close to tray: the webview is destroyed but the shell and service keep running; relaunching restores it.
    // Native close (title-bar X); page-level window.close() would only close the webview.
    if (process.platform === "win32")
      execFileSync("powershell.exe", ["-NoProfile", "-ExecutionPolicy", "Bypass", "-File", path.join(__dirname, "close-window.ps1"), "-ProcessId", String(app.pid)]);
    else await page.eval(() => window.close());
    page.close();
    await wait(2500);
    const left = await fetch(`http://127.0.0.1:${PORT}/json/list`).then((r) => r.json()).catch(() => []);
    assert.equal(left.length, 0, "the webview should be destroyed when closed to the tray");
    assert.equal(app.exitCode, null, "the shell must keep running in the tray");
    const again = spawn(exe, [], { env, stdio: "ignore" });
    page = await attach(PORT, undefined, 30000);
    await page.until(() => document.body.innerText.includes("Live monitoring"), 30000);
    again.kill();
    passed.push("Close-to-tray unloads the window; launching again reopens it from the running app");

    console.log(JSON.stringify({ passed }, null, 2));
    fs.writeFileSync(path.join(output, "tauri-results.json"), JSON.stringify({ passed, errors: page.errors }, null, 2));
  } finally {
    page?.close();
    app.kill();
    await wait(1500);
    fs.rmSync(data, { recursive: true, force: true });
  }
})().catch((error) => {
  console.error(error);
  console.error("Completed:", passed);
  process.exitCode = 1;
});
