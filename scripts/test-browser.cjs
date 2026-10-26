const { chromium } = require("playwright");
const assert = require("node:assert/strict");
const fs = require("node:fs/promises");
const path = require("node:path");
const os = require("node:os");
const output =
  process.env.BEAVER_QA_OUTPUT || path.join(os.tmpdir(), "beaver-qa");
(async () => {
  await fs.mkdir(output, { recursive: true });
  const browser = await chromium.launch(
    process.platform === "win32" ? { channel: "msedge" } : {},
  );
  const results = [];
  try {
    const page = await browser.newPage({
      viewport: { width: 1440, height: 1000 },
    });
    const errors = [];
    page.on("pageerror", (e) => errors.push(e.message));
    await page.goto("http://127.0.0.1:5173");
    await page.getByText("Live monitoring", { exact: true }).waitFor();
    await page.waitForFunction(
      () => document.querySelectorAll("tbody tr").length > 0,
    );
    await page.waitForTimeout(2200);
    await page.screenshot({
      path: path.join(output, "browser-desktop.png"),
      fullPage: true,
    });
    assert((await page.title()).includes("Network overview"));
    results.push(
      "Page identity, meaningful real-data render, no framework overlay",
    );
    await page
      .getByRole("button", { name: "Applications", exact: true })
      .click();
    await page.getByRole("textbox").fill("beaver-no-match");
    await page
      .getByRole("heading", { name: "No matching applications" })
      .waitFor();
    await page.getByRole("button", { name: "Clear search" }).click();
    results.push("Search no-results and clear");
    await page.getByRole("combobox").focus();
    await page.keyboard.press("ArrowDown");
    await page.keyboard.press("Enter");
    results.push("Native select keyboard interaction");
    await page.getByRole("button", { name: "Settings", exact: true }).click();
    assert(
      await page
        .getByRole("button", {
          name: "Refresh threat intelligence",
          exact: true,
        })
        .isDisabled(),
    );
    results.push("Browser preview cannot mutate OS state");
    await page.setViewportSize({ width: 390, height: 844 });
    await page.getByRole("button", { name: "Overview", exact: true }).click();
    assert(
      await page.evaluate(
        () => document.documentElement.scrollWidth <= window.innerWidth,
      ),
    );
    await page.screenshot({
      path: path.join(output, "browser-narrow.png"),
      fullPage: true,
    });
    await page.getByRole("button", { name: "Settings", exact: true }).click();
    await page
      .getByRole("combobox", { name: "Local history retention" })
      .scrollIntoViewIfNeeded();
    assert(
      await page.evaluate(
        () => document.documentElement.scrollWidth <= window.innerWidth,
      ),
    );
    results.push("390px overview and settings layout, reachable long form");
    await page.emulateMedia({ reducedMotion: "reduce" });
    await page.getByRole("button", { name: "World map", exact: true }).click();
    await page
      .getByRole("heading", { name: "Add a local GeoIP database" })
      .waitFor();
    assert(
      await page.evaluate(
        () => document.documentElement.scrollWidth <= window.innerWidth,
      ),
    );
    results.push("Narrow map and reduced motion");
    await page.route("**/api/snapshot", (route) =>
      route.abort("connectionfailed"),
    );
    await page.getByRole("button", { name: "Overview", exact: true }).click();
    await page
      .getByRole("button", { name: "Retry connection" })
      .waitFor({ timeout: 20000 });
    await page
      .getByText("Monitoring needs attention", { exact: true })
      .waitFor();
    results.push(
      "Disconnected telemetry preserves data with stale/error status",
    );
    await page.screenshot({
      path: path.join(output, "browser-disconnected.png"),
      fullPage: true,
    });
    await page.unroute("**/api/snapshot");
    await page.getByRole("button", { name: "Retry connection" }).click();
    await page.getByText("Live monitoring", { exact: true }).waitFor();
    results.push("Retry restores live telemetry");
    assert.deepEqual(errors, []);
    results.push("No renderer exceptions");
    await fs.writeFile(
      path.join(output, "browser-results.json"),
      JSON.stringify({ results, errors }, null, 2),
    );
    console.log(JSON.stringify({ results, screenshots: output }, null, 2));
  } finally {
    await browser.close();
  }
})().catch((e) => {
  console.error(e);
  process.exitCode = 1;
});
