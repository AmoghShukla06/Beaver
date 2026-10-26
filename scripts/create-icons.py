"""Deterministic code-native shield icons; no runtime image dependency. Run: python scripts/create-icons.py"""
import struct, zlib
from pathlib import Path

SHIELD = [(.5, .06), (.88, .2), (.85, .56), (.73, .76), (.5, .94), (.27, .76), (.15, .56), (.12, .2)]
CHECK = [(.29, .47), (.37, .4), (.46, .51), (.65, .3), (.73, .38), (.46, .67)]
MINT, INK, ROSE = (98, 223, 172), (11, 16, 24), (255, 99, 120)

def inside(x, y, poly):
    result = False; j = len(poly) - 1
    for i in range(len(poly)):
        xi, yi = poly[i]; xj, yj = poly[j]
        if (yi > y) != (yj > y) and x < (xj - xi) * (y - yi) / (yj - yi) + xi:
            result = not result
        j = i
    return result

def render(size, badge=False, ss=3):
    """RGBA rows, supersampled ss×ss for anti-aliased edges."""
    rows = []
    for py in range(size):
        row = bytearray()
        for px in range(size):
            acc = [0, 0, 0, 0]
            for sy in range(ss):
                for sx in range(ss):
                    x = (px + (sx + .5) / ss) / size; y = (py + (sy + .5) / ss) / size
                    color = None
                    if badge and (x - .76) ** 2 + (y - .76) ** 2 < .23 ** 2:
                        color = INK if (x - .76) ** 2 + (y - .76) ** 2 > .19 ** 2 else ROSE
                    elif inside(x, y, SHIELD):
                        color = INK if inside(x, y, CHECK) else MINT
                    if color:
                        acc[0] += color[0]; acc[1] += color[1]; acc[2] += color[2]; acc[3] += 255
            n = ss * ss; alpha = acc[3] / n
            row.extend((round(acc[0] / (acc[3] / 255)) if acc[3] else 0, round(acc[1] / (acc[3] / 255)) if acc[3] else 0,
                        round(acc[2] / (acc[3] / 255)) if acc[3] else 0, round(alpha)))
        rows.append(bytes(row))
    return rows

def png(size, badge=False):
    rows = render(size, badge)
    raw = b"".join(b"\0" + r for r in rows)
    chunk = lambda kind, data: struct.pack(">I", len(data)) + kind + data + struct.pack(">I", zlib.crc32(kind + data) & 0xffffffff)
    return b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", size, size, 8, 6, 0, 0, 0)) + chunk(b"IDAT", zlib.compress(raw, 9)) + chunk(b"IEND", b"")

def ico(images):
    header = struct.pack("<HHH", 0, 1, len(images)); offset = 6 + 16 * len(images); entries = b""; data = b""
    for size, blob in images:
        entries += struct.pack("<BBBBHHII", size % 256, size % 256, 0, 0, 1, 32, len(blob), offset + len(data)); data += blob
    return header + entries + data

out = Path("assets"); out.mkdir(exist_ok=True)
(out / "beaver.png").write_bytes(png(512))
(out / "beaver.ico").write_bytes(ico([(s, png(s)) for s in (16, 24, 32, 48, 64, 128, 256)]))
(out / "tray.png").write_bytes(png(32))
(out / "tray-alert.png").write_bytes(png(32, True))
