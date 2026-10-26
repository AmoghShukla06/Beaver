const { spawnSync } = require("node:child_process");
const path = require("node:path");
const root = path.resolve(__dirname, "..");
const result = spawnSync(
  path.join(
    root,
    ".venv",
    process.platform === "win32" ? "Scripts/python.exe" : "bin/python",
  ),
  ["scripts/build_backend.py"],
  { cwd: root, stdio: "inherit", windowsHide: true },
);
if (result.error) console.error(result.error.message);
process.exit(result.status ?? 1);
