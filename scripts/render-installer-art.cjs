// Renders NSIS wizard artwork from HTML with the real brand mark and fonts.
// Run: npx electron scripts/render-installer-art.cjs   (writes packaging/*.bmp, committed)
const { app, BrowserWindow } = require("electron");
const fs = require("node:fs");
const path = require("node:path");

app.commandLine.appendSwitch("force-device-scale-factor", "1");
app.disableHardwareAcceleration();
app.on("window-all-closed", () => {}); // windows are created one at a time; keep running between them

const mark = `<svg viewBox="0 0 64 64" width="SIZE" height="SIZE"><path d="M32 5L55 13L53 35Q49 50 32 59Q15 50 11 35L9 13Z" fill="#62dfac"/><path d="M23.5 26H31V39.5Q31 42 28.5 42H26Q23.5 42 23.5 39.5ZM33 26H40.5V39.5Q40.5 42 38 42H35.5Q33 42 33 39.5Z" fill="#f5f0e1"/><path d="M17 25Q32 16 47 25L47 30Q32 22 17 30Z" fill="#0b1018"/></svg>`;
const base = `*{margin:0;box-sizing:border-box}body{font-family:"Segoe UI",system-ui,sans-serif;overflow:hidden}`;

// Welcome/finish sidebar (164x314) and the header image shown on inner pages (150x57, white system header).
const sidebar = (subtitle) => `<style>${base}
  body{width:164px;height:314px;background:linear-gradient(170deg,#132233 0%,#0b1018 62%);color:#edf3fc;padding:34px 18px 18px;display:flex;flex-direction:column}
  h1{font-size:25px;font-weight:700;letter-spacing:-.5px;margin-top:14px}h1 span{color:#62dfac}
  p{font-size:11px;line-height:1.45;color:#9bacc2;margin-top:8px}
  .rule{height:2px;width:34px;background:#62dfac;margin-top:14px;border-radius:1px}
  footer{margin-top:auto;font-size:9.5px;color:#6f839c;line-height:1.5}</style>
  <body>${mark.replace(/SIZE/g, 54)}<h1>Beaver<span>.</span></h1><div class="rule"></div>
  <p>${subtitle}</p><footer>Open source · Apache-2.0<br>No account, no cloud.</footer></body>`;
const header = `<style>${base}
  body{width:150px;height:57px;background:#fff;display:flex;align-items:center;justify-content:flex-end;gap:7px;padding-right:10px}
  b{font-size:17px;color:#0b1018;letter-spacing:-.3px}</style><body><b>Beaver</b>${mark.replace(/SIZE/g, 38)}</body>`;

function bmp(image, file) {
  // 24-bit bottom-up BMP from a BGRA bitmap (what NSIS's MUI expects).
  const { width, height } = image.getSize();
  const bgra = image.toBitmap();
  const stride = Math.ceil((width * 3) / 4) * 4;
  const out = Buffer.alloc(54 + stride * height);
  out.write("BM", 0);
  out.writeUInt32LE(out.length, 2);
  out.writeUInt32LE(54, 10);
  out.writeUInt32LE(40, 14);
  out.writeInt32LE(width, 18);
  out.writeInt32LE(height, 22);
  out.writeUInt16LE(1, 26);
  out.writeUInt16LE(24, 28);
  out.writeUInt32LE(stride * height, 34);
  for (let y = 0; y < height; y++)
    for (let x = 0; x < width; x++) {
      const src = (y * width + x) * 4;
      const dst = 54 + (height - 1 - y) * stride + x * 3;
      out[dst] = bgra[src];
      out[dst + 1] = bgra[src + 1];
      out[dst + 2] = bgra[src + 2];
    }
  fs.writeFileSync(file, out);
}

async function render(html, width, height, file) {
  const win = new BrowserWindow({ width, height, show: false, useContentSize: true, frame: false, webPreferences: { offscreen: true } });
  await win.loadURL("data:text/html;charset=utf-8," + encodeURIComponent(html));
  await new Promise((resolve) => setTimeout(resolve, 300));
  const image = (await win.webContents.capturePage({ x: 0, y: 0, width, height })).resize({ width, height, quality: "best" });
  bmp(image, file);
  fs.writeFileSync(file.replace(/\.bmp$/, ".preview.png"), image.toPNG());
  win.destroy();
}

app.whenReady().then(async () => {
  const dir = path.join(__dirname, "..", "packaging");
  await render(sidebar("Network security for Windows and Linux. See every connection, stop remote access and data theft."), 164, 314, path.join(dir, "installer-sidebar.bmp"));
  await render(header, 150, 57, path.join(dir, "installer-header.bmp"));
  app.quit();
});
