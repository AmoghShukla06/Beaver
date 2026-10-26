// Build the Rust monitoring service and stage it as Tauri's sidecar (src-tauri/binaries/beaver-service-<triple>).
const { execFileSync, spawnSync } = require("node:child_process");
const fs = require("node:fs");
const path = require("node:path");
const root = path.resolve(__dirname, "..");
const built = spawnSync(process.execPath, [path.join(__dirname, "msvc.cjs"), "cargo", "build", "--release", "-p", "beaver-service"], { stdio: "inherit" });
if (built.status !== 0) process.exit(built.status ?? 1);
const triple = /host: (\S+)/.exec(execFileSync("rustc", ["-vV"]).toString())[1];
const ext = process.platform === "win32" ? ".exe" : "";
const dir = path.join(root, "src-tauri", "binaries");
fs.mkdirSync(dir, { recursive: true });
fs.copyFileSync(path.join(root, "target", "release", "beaver-service" + ext), path.join(dir, `beaver-service-${triple}${ext}`));
console.log(`staged beaver-service-${triple}${ext}`);
