import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import { createRequire } from "node:module";
import path from "node:path";
const require = createRequire(import.meta.url);
// Browser preview is read-only, loopback-only, and rejects cross-origin/foreign Host requests.
// Packaged desktop uses private IPC and exposes no HTTP service.
function localPreview() {
  let backend:
    | {
        call: (method: string, params?: object) => Promise<unknown>;
        close: () => void;
      }
    | undefined;
  return {
    name: "beaver-read-only-preview",
    configureServer(server: any) {
      server.middlewares.use("/api/snapshot", async (req: any, res: any) => {
        if (
          req.method !== "GET" ||
          req.headers.host !== "127.0.0.1:5173" ||
          (req.headers.origin &&
            req.headers.origin !== "http://127.0.0.1:5173") ||
          req.headers["sec-fetch-site"] === "cross-site"
        ) {
          res.statusCode = 403;
          res.end("Forbidden");
          return;
        }
        try {
          if (!backend) {
            const { Backend } = require("./desktop/backend.cjs");
            backend = new Backend({
              directory: path.resolve(".qa/preview-data"),
            });
          }
          const snapshot = await backend!.call("snapshot");
          res.setHeader("Content-Type", "application/json");
          res.setHeader("Cache-Control", "no-store");
          res.end(JSON.stringify(snapshot));
        } catch (error) {
          res.statusCode = 503;
          res.end(JSON.stringify({ error: String(error) }));
        }
      });
      server.httpServer?.on("close", () => backend?.close());
    },
  };
}
export default defineConfig({
  base: "./",
  plugins: [react(), localPreview()],
  server: {
    host: "127.0.0.1",
    port: 5173,
    strictPort: true,
    allowedHosts: ["127.0.0.1"],
  },
});
