// Minimal Chrome DevTools Protocol client for driving the Tauri WebView2 page in end-to-end tests.
// (Playwright's connectOverCDP attaches to a stale about:blank context on WebView2 with custom protocols.)
const fs = require("node:fs");
const wait = (ms) => new Promise((r) => setTimeout(r, ms));

async function attach(port, match = (t) => t.type === "page" && /^https?:\/\/tauri\.localhost/.test(t.url), timeout = 40000) {
  const end = Date.now() + timeout;
  while (Date.now() < end) {
    const targets = await fetch(`http://127.0.0.1:${port}/json/list`).then((r) => r.json()).catch(() => []);
    const target = targets.find(match);
    if (target) return connect(target.webSocketDebuggerUrl);
    await wait(300);
  }
  throw new Error("No matching DevTools page target");
}

function connect(url) {
  return new Promise((resolve, reject) => {
    const ws = new WebSocket(url);
    let id = 0;
    const pending = new Map();
    const listeners = [];
    ws.onmessage = (m) => {
      const msg = JSON.parse(m.data);
      if (msg.id && pending.has(msg.id)) {
        const { ok, fail } = pending.get(msg.id);
        pending.delete(msg.id);
        msg.error ? fail(new Error(msg.error.message)) : ok(msg.result);
      } else if (msg.method) listeners.forEach((l) => l(msg));
    };
    ws.onerror = (e) => reject(e);
    ws.onopen = async () => {
      const send = (method, params = {}) =>
        new Promise((ok, fail) => {
          pending.set(++id, { ok, fail });
          ws.send(JSON.stringify({ id, method, params }));
        });
      const page = {
        errors: [],
        send,
        close: () => ws.close(),
        async eval(fn, ...args) {
          // DOM nodes cannot be returned by value; report them as `true` so `until(() => el)` works.
          const expr = `(async () => { const r = await (${fn.toString()})(...${JSON.stringify(args)}); return r instanceof Node ? true : r; })()`;
          const r = await send("Runtime.evaluate", { expression: expr, awaitPromise: true, returnByValue: true });
          if (r.exceptionDetails) throw new Error(r.exceptionDetails.exception?.description || r.exceptionDetails.text);
          return r.result.value;
        },
        async until(fn, timeout = 20000, ...args) {
          const end = Date.now() + timeout;
          let last;
          while (Date.now() < end) {
            last = await page.eval(fn, ...args).catch((e) => (last = e.message, false));
            if (last) return last;
            await wait(250);
          }
          throw new Error("Timed out waiting for " + fn.toString().slice(0, 120));
        },
        /** Click the first visible button/link/switch whose accessible text or aria-label matches exactly. */
        click(label) {
          return page.eval((label) => {
            const els = [...document.querySelectorAll("button, a, [role=switch], [role=button]")].filter((e) => e.offsetParent !== null || e.closest("dialog[open]"));
            const el = els.find((e) => (e.getAttribute("aria-label") || e.textContent || "").trim() === label) ||
                       els.find((e) => (e.getAttribute("aria-label") || e.textContent || "").trim().startsWith(label));
            if (!el) throw new Error("No control labelled " + label);
            el.click();
            return true;
          }, label);
        },
        type(selector, text) {
          return page.eval((selector, text) => {
            const el = document.querySelector(selector);
            const set = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value").set;
            set.call(el, text);
            el.dispatchEvent(new Event("input", { bubbles: true }));
            return true;
          }, selector, text);
        },
        async screenshot(file) {
          const r = await send("Page.captureScreenshot", { format: "png" });
          fs.writeFileSync(file, Buffer.from(r.data, "base64"));
        },
      };
      await send("Runtime.enable");
      await send("Page.enable");
      listeners.push((m) => {
        if (m.method === "Runtime.exceptionThrown") page.errors.push(m.params.exceptionDetails.exception?.description || m.params.exceptionDetails.text);
        if (m.method === "Runtime.consoleAPICalled" && m.params.type === "error") page.errors.push(m.params.args.map((a) => a.value ?? a.description).join(" "));
      });
      resolve(page);
    };
  });
}

module.exports = { attach, wait };
