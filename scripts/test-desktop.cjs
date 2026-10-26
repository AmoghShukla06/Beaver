const { _electron: electron, chromium } = require("playwright");
const AxeBuilder = require("@axe-core/playwright").default;
const assert = require("node:assert/strict");
const fs = require("node:fs/promises");
const path = require("node:path");
const os = require("node:os");
const root = path.resolve(__dirname, "..");
const output =
  process.env.BEAVER_QA_OUTPUT || path.join(os.tmpdir(), "beaver-qa");
const passed = [];
// page.waitForFunction treats a returned Promise as truthy, so async predicates are polled here instead.
const until = async (page, predicate, { timeout = 20000 } = {}) => {
  const end = Date.now() + timeout;
  while (Date.now() < end) {
    if (await page.evaluate(predicate)) return;
    await new Promise((resolve) => setTimeout(resolve, 250));
  }
  throw new Error("Timed out waiting for " + predicate);
};
(async () => {
  await fs.mkdir(output, { recursive: true });
  const dataDir = await fs.mkdtemp(path.join(os.tmpdir(), "beaver-test-"));
  const app = await electron.launch({
    args: [root],
    env: { ...process.env, BEAVER_TEST_DATA: dataDir },
    timeout: 30000,
  });
  try {
    const page = await app.firstWindow();
    const errors = [];
    page.on("pageerror", (error) => errors.push(error.message));
    await page.getByRole("heading", { name: "Network overview" }).waitFor();
    await page.waitForFunction(() => Boolean(window.beaver));
    await until(page, async () => (await window.beaver.snapshot()).ready,
      { timeout: 20000 },
    );
    await page.getByText("Live monitoring", { exact: true }).waitFor();
    const live = await page.evaluate(() => window.beaver.snapshot());
    assert(live.apps.length > 0 && live.connections.length > 0);
    passed.push("Real OS connections render in desktop");
    assert.equal(await page.evaluate(() => typeof window.require), "undefined");
    passed.push("Renderer has no Node require");
    const setup = page.getByRole("dialog", { name: "Welcome to Beaver" });
    await setup.waitFor();
    await page.evaluate(require("axe-core").source);
    const setupAxe = await page.evaluate(() => window.axe.run(document));
    assert.equal(setupAxe.violations.length, 0, setupAxe.violations.map((v) => v.id).join(", "));
    await setup.getByRole("button", { name: "Continue" }).click();
    await page.getByRole("heading", { name: "See which website every app talks to" }).waitFor();
    await page.getByRole("button", { name: "Continue" }).click();
    await page.getByRole("button", { name: "Start protecting" }).click();
    await until(page, async () => (await window.beaver.snapshot()).settings.onboarded === true);
    await page.locator("dialog.onboarding").waitFor({ state: "detached" });
    passed.push("First-run setup wizard completes and is accessible");
    await page.screenshot({
      path: path.join(output, "overview.png"),
      fullPage: true,
    });
    let axe = await (async () => {
      await page.evaluate(require("axe-core").source);
      return page.evaluate(() => window.axe.run(document));
    })();
    await fs.writeFile(
      path.join(output, "axe-overview.json"),
      JSON.stringify(axe.violations, null, 2),
    );
    assert.equal(
      axe.violations.length,
      0,
      axe.violations.map((v) => v.id + ": " + v.nodes.length).join(", "),
    );
    passed.push("Overview accessibility scan");
    await page
      .getByRole("button", { name: "Applications", exact: true })
      .click();
    const search = page.getByRole("textbox", {
      name: "Search applications, paths, or process IDs",
    });
    await search.fill("this-app-does-not-exist-beaver");
    await page
      .getByRole("heading", { name: "No matching applications" })
      .waitFor();
    passed.push("Search empty state");
    await page.getByRole("button", { name: "Clear search" }).click();
    assert.equal(await search.inputValue(), "");
    passed.push("Search clear and restoration");
    await page.getByRole("combobox").selectOption("Unknown");
    assert((await page.getByText("Unknown risk", { exact: true }).count()) > 0);
    passed.push("Risk filtering");
    await page.getByRole("combobox").selectOption("All");
    const withPath = live.apps.find((a) => a.path);
    assert(withPath);
    await search.fill(withPath.name);
    await page
      .getByRole("button", {
        name: "Investigate " + withPath.name,
        exact: true,
      })
      .first()
      .click();
    await page.getByRole("heading", { name: "Why this risk level?" }).waitFor();
    await page
      .getByRole("heading", { name: "Connection history", exact: true })
      .waitFor();
    await page.screenshot({
      path: path.join(output, "investigation.png"),
      fullPage: true,
    });
    passed.push("Investigation and local history");
    const block = page.getByRole("button", {
      name: "Block application",
      exact: true,
    });
    if (await block.isEnabled()) {
      await block.click();
      await page.getByRole("dialog").waitFor();
      assert.equal(
        await page.evaluate(() => document.activeElement.textContent),
        "Cancel",
      );
      await page.keyboard.press("Escape");
      assert.equal(await page.getByRole("dialog").count(), 0);
      passed.push("Blocking confirmation, safe initial focus and Escape");
    }
    const allow = page.getByRole("button", {
      name: "Allowlist application",
      exact: true,
    });
    if (await allow.isEnabled()) {
      await allow.click();
      await page
        .getByRole("dialog")
        .getByRole("button", { name: "Allowlist", exact: true })
        .click();
      await page
        .getByRole("button", { name: "Remove allowlist", exact: true })
        .waitFor();
      await page.getByRole("button", { name: "Firewall", exact: true }).click();
      await page
        .getByRole("button", { name: "Remove exception", exact: true })
        .click();
      await page
        .getByRole("dialog")
        .getByRole("button", { name: "Remove exception", exact: true })
        .click();
      await page
        .getByRole("heading", { name: "No allowlist exceptions" })
        .waitFor();
      passed.push("Persistent allowlist create and remove");
    }
    await page.getByRole("button", { name: "Remote shield", exact: true }).click();
    await page
      .getByRole("heading", { name: "Remote access & data-theft shield" })
      .waitFor();
    await page.getByRole("heading", { name: "Remote control", exact: true }).waitFor();
    assert(
      await page
        .getByRole("button", { name: /remote access lockdown/ })
        .isVisible(),
    );
    axe = await page.evaluate(() => window.axe.run(document));
    assert.equal(axe.violations.length, 0, axe.violations.map((v) => v.id).join(", "));
    passed.push("Remote shield renders with lockdown control and passes accessibility scan");
    await page.getByRole("button", { name: "Connections", exact: true }).click();
    await page.getByRole("heading", { name: "Live connections", exact: true }).first().waitFor();
    await page.getByRole("button", { name: "All", exact: true }).click();
    assert((await page.locator(".connection-table tbody tr").count()) > 0);
    passed.push("Global connection search lists real sockets");
    await page.getByRole("button", { name: "World map", exact: true }).click();
    await page
      .getByRole("heading", { name: "Add a local GeoIP database" })
      .waitFor();
    assert((await page.locator(".country").count()) > 170);
    await page.getByRole("button", { name: "Zoom in", exact: true }).click();
    assert(
      (await page.locator(".world-map > g").getAttribute("transform")).includes(
        "1.5",
      ),
    );
    await page.getByRole("button", { name: "Reset map", exact: true }).click();
    await page.screenshot({
      path: path.join(output, "map.png"),
      fullPage: true,
    });
    passed.push("Offline political map, truthful empty state, zoom");
    await page.getByRole("button", { name: "Settings", exact: true }).click();
    await page
      .getByRole("combobox", { name: "Local history retention" })
      .selectOption("3");
    await until(page, async () =>
        (await window.beaver.snapshot()).settings.retention_days === 3,
    );
    passed.push("Settings persisted through native IPC");
    await page
      .getByRole("button", { name: "Refresh threat intelligence", exact: true })
      .click();
    await until(page, async () => {
        const s = await window.beaver.snapshot();
        return s.coverage.intel.fresh || Boolean(s.coverage.intel.error);
      },
      { timeout: 35000 },
    );
    const feed = await page.evaluate(
      async () => (await window.beaver.snapshot()).coverage.intel,
    );
    if (feed.fresh)
      passed.push(
        "Real HTTPS threat feed downloaded and parsed (" +
          feed.entries +
          " entries)",
      );
    else passed.push("Feed failure displayed: " + feed.error);
    await page.getByRole("switch", { name: "Packet metadata capture" }).click();
    await until(page, async () => (await window.beaver.snapshot()).settings.capture === true,
    );
    await until(page, async () => {
        const c = (await window.beaver.snapshot()).coverage.capture;
        return c.active || Boolean(c.error);
      },
      { timeout: 20000 },
    );
    const capture = await page.evaluate(
      async () => (await window.beaver.snapshot()).coverage.capture,
    );
    assert(capture.active || capture.error, JSON.stringify(capture));
    passed.push(
      "Capture capability truthful: " +
        (capture.active ? "active" : capture.error),
    );
    await page.getByRole("switch", { name: "Packet metadata capture" }).click();
    await page
      .getByRole("button", { name: "Send test notification", exact: true })
      .click();
    await page
      .getByRole("status")
      .filter({ hasText: "Test notification requested" })
      .waitFor();
    passed.push("Native notification API invocation");
    await page.getByRole("heading", { name: "About Beaver" }).waitFor();
    await page.getByRole("button", { name: "Copy diagnostics" }).click();
    await page.getByText("Diagnostics copied").waitFor();
    const report = await app.evaluate(({ clipboard }) => clipboard.readText());
    assert(report.includes("## Beaver diagnostics") && report.includes('"feeds"'));
    assert(!report.toLowerCase().includes(os.userInfo().username.toLowerCase()), "diagnostics leaked the username");
    passed.push("About panel copies redacted diagnostics");
    await page.screenshot({
      path: path.join(output, "settings.png"),
      fullPage: true,
    });
    axe = await (async () => {
      await page.evaluate(require("axe-core").source);
      return page.evaluate(() => window.axe.run(document));
    })();
    await fs.writeFile(
      path.join(output, "axe-settings.json"),
      JSON.stringify(axe.violations, null, 2),
    );
    assert.equal(
      axe.violations.length,
      0,
      axe.violations.map((v) => v.id).join(", "),
    );
    passed.push("Settings accessibility scan");
    assert.deepEqual(errors, []);
    await app.evaluate(({ BrowserWindow }) => {
      BrowserWindow.getAllWindows()[0].close();
    });
    await page.waitForEvent("close");
    assert.equal(
      await app.evaluate(({ BrowserWindow }) => BrowserWindow.getAllWindows().length),
      0,
    );
    const reopened = app.waitForEvent("window");
    await app.evaluate(({ app }) => app.emit("second-instance"));
    const second = await reopened;
    await second.getByText("Live monitoring", { exact: true }).waitFor({ timeout: 20000 });
    passed.push("Close-to-tray unloads the renderer; reopening reconnects to the running service");
    passed.push("No renderer exceptions");
    console.log(
      JSON.stringify({ passed, feed, capture, screenshots: output }, null, 2),
    );
    await fs.writeFile(
      path.join(output, "desktop-results.json"),
      JSON.stringify({ passed, feed, capture, errors }, null, 2),
    );
  } finally {
    await app.close();
  }
})().catch((error) => {
  console.error(error);
  console.error("Completed:", passed);
  process.exitCode = 1;
});
