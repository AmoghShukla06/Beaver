const { spawn } = require("node:child_process");
const { createInterface } = require("node:readline");
const path = require("node:path");
const fs = require("node:fs");
class Backend {
  constructor({ directory, resources, packaged = false, onEvent, onExit, log }) {
    this.pending = new Map();
    this.sequence = 0;
    this.error = null;
    this.onEvent = onEvent || (() => {});
    const root = path.resolve(__dirname, "..");
    const executable = packaged
      ? path.join(
          resources,
          "backend",
          "beaver-service",
          process.platform === "win32"
            ? "beaver-service.exe"
            : "beaver-service",
        )
      : path.join(
          root,
          ".venv",
          process.platform === "win32" ? "Scripts/python.exe" : "bin/python",
        );
    if (!fs.existsSync(executable))
      throw new Error(
        "Telemetry service is missing. Run the documented setup or reinstall Beaver.",
      );
    const args = packaged ? [] : ["-m", "backend.service"];
    this.child = spawn(executable, [...args, "--data-dir", directory], {
      cwd: packaged ? path.dirname(executable) : root,
      windowsHide: true,
      stdio: ["pipe", "pipe", "pipe"],
    });
    // Tracebacks go to the local log file only (never the console), so crashes can be diagnosed.
    this.child.stderr.on("data", (chunk) => log?.("service stderr: " + String(chunk).slice(0, 4000)));
    createInterface({ input: this.child.stdout, crlfDelay: Infinity }).on(
      "line",
      (line) => {
        if (line.length > 32 * 1024 * 1024)
          return this.fail("Telemetry response exceeds the safety limit");
        let message;
        try {
          message = JSON.parse(line);
        } catch {
          return this.fail("Invalid telemetry response");
        }
        if (message.event) return this.onEvent(message.event, message.data);
        const pending = this.pending.get(message.id);
        if (!pending) return;
        clearTimeout(pending.timer);
        this.pending.delete(message.id);
        message.error
          ? pending.reject(new Error(message.error))
          : pending.resolve(message.result);
      },
    );
    this.child.on("error", (err) => this.fail(err.message));
    this.child.on("exit", (code) => {
      this.fail("Telemetry service stopped. Beaver is restarting it.");
      if (!this.closing) log?.("service exited with code " + code);
      onExit?.(code);
    });
    this.child.stdin.on("error", () =>
      this.fail("Telemetry service disconnected."),
    );
  }
  fail(message) {
    this.error = message;
    for (const item of this.pending.values()) {
      clearTimeout(item.timer);
      item.reject(new Error(message));
    }
    this.pending.clear();
  }
  call(method, params = {}) {
    if (this.error) return Promise.reject(new Error(this.error));
    if (this.pending.size >= 32)
      return Promise.reject(new Error("Too many pending requests"));
    return new Promise((resolve, reject) => {
      const id = ++this.sequence;
      const timer = setTimeout(() => {
        this.pending.delete(id);
        reject(
          new Error(
            "The operation timed out. Check the operating-system authorization dialog before retrying.",
          ),
        );
      }, 135000);
      this.pending.set(id, { resolve, reject, timer });
      this.child.stdin.write(JSON.stringify({ id, method, params }) + "\n");
    });
  }
  close() {
    this.closing = true;
    this.child.stdin.end();
    const child = this.child;
    const timer = setTimeout(() => child.kill(), 3000);
    timer.unref();
  }
}
module.exports = { Backend };
