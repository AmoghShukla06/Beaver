// Run a build command; on Windows inside the Visual Studio developer environment (see msvc.ps1).
// Usage: node scripts/msvc.cjs cargo test -p beaver-service
const { spawnSync } = require("node:child_process");
const path = require("node:path");
const root = path.resolve(__dirname, "..");
const args = process.argv.slice(2);
const result =
  process.platform === "win32"
    ? spawnSync("powershell.exe", ["-NoProfile", "-ExecutionPolicy", "Bypass", "-File", path.join(__dirname, "msvc.ps1"), ...args], { stdio: "inherit", cwd: root })
    : spawnSync(args[0], args.slice(1), { stdio: "inherit", cwd: root });
process.exitCode = result.status ?? 1;
