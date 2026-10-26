const { spawn } = require("node:child_process");
const path = require("node:path");
const root = path.resolve(__dirname, "..");
const vite = spawn(
  process.execPath,
  [path.join(root, "node_modules/vite/bin/vite.js"), "--host", "127.0.0.1"],
  { cwd: root, stdio: "inherit", windowsHide: true },
);
let desktop;
const cleanup = () => {
  desktop?.kill();
  vite.kill();
};
process.on("SIGINT", cleanup);
process.on("SIGTERM", cleanup);
(async () => {
  for (let i = 0; i < 60; i++) {
    try {
      const response = await fetch("http://127.0.0.1:5173");
      if (response.ok) break;
    } catch {}
    await new Promise((resolve) => setTimeout(resolve, 500));
  }
  desktop = spawn(require("electron"), ["."], {
    cwd: root,
    env: { ...process.env, BEAVER_DEV_URL: "http://127.0.0.1:5173" },
    stdio: "inherit",
    windowsHide: true,
  });
  desktop.on("exit", (code) => {
    vite.kill();
    process.exit(code || 0);
  });
})();
