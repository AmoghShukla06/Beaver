"""Deterministic code-native brand icons (shield with beaver teeth); no runtime image dependency.
Run: python scripts/create-icons.py. Geometry matches the Brand SVG in src/components.tsx (64x64 units)."""
import struct, zlib
from pathlib import Path

def quad(p0, p1, p2, steps=12):
    return [((1-t)**2*p0[0]+2*(1-t)*t*p1[0]+t*t*p2[0], (1-t)**2*p0[1]+2*(1-t)*t*p1[1]+t*t*p2[1])
            for t in (i/steps for i in range(1, steps+1))]

def scale(points):
    return [(x/64, y/64) for x, y in points]

# Shield: M32 5 L55 13 L53 35 Q49 50 32 59 Q15 50 11 35 L9 13 Z
SHIELD = scale([(32, 5), (55, 13), (53, 35)] + quad((53, 35), (49, 50), (32, 59)) + quad((32, 59), (15, 50), (11, 35)) + [(9, 13)])
# Upper lip: M17 25 Q32 16 47 25 L47 30 Q32 22 17 30 Z
LIP = scale([(17, 25)] + quad((17, 25), (32, 16), (47, 25)) + [(47, 30)] + quad((47, 30), (32, 22), (17, 30)))
def tooth(x0, x1, y0=26, y1=45, r=2.5):
    bottom = quad((x1, y1-r), (x1, y1), (x1-r, y1), 4) + quad((x0+r, y1), (x0, y1), (x0, y1-r), 4)
    return scale([(x0, y0), (x1, y0)] + bottom)
TEETH = [tooth(23.5, 31, 26, 42), tooth(33, 40.5, 26, 42)]
MINT, INK, CREAM, ROSE = (98, 223, 172), (11, 16, 24), (245, 240, 225), (255, 99, 120)

def inside(x, y, poly):
    result = False; j = len(poly) - 1
    for i in range(len(poly)):
        xi, yi = poly[i]; xj, yj = poly[j]
        if (yi > y) != (yj > y) and x < (xj - xi) * (y - yi) / (yj - yi) + xi:
            result = not result
        j = i
    return result

def color_at(x, y, badge):
    if badge and (x - .76) ** 2 + (y - .76) ** 2 < .23 ** 2:
        return INK if (x - .76) ** 2 + (y - .76) ** 2 > .19 ** 2 else ROSE
    if not inside(x, y, SHIELD):
        return None
    if inside(x, y, LIP):
        return INK
    if any(inside(x, y, t) for t in TEETH):
        return CREAM
    return MINT

def render(size, badge=False, ss=3):
    rows = []
    for py in range(size):
        row = bytearray()
        for px in range(size):
            acc = [0, 0, 0, 0]
            for sy in range(ss):
                for sx in range(ss):
                    c = color_at((px + (sx + .5) / ss) / size, (py + (sy + .5) / ss) / size, badge)
                    if c:
                        acc[0] += c[0]; acc[1] += c[1]; acc[2] += c[2]; acc[3] += 255
            n = acc[3] / 255
            row.extend((round(acc[0] / n) if n else 0, round(acc[1] / n) if n else 0, round(acc[2] / n) if n else 0, round(acc[3] / (ss * ss))))
        rows.append(bytes(row))
    return rows

def png(size, badge=False):
    raw = b"".join(b"\0" + r for r in render(size, badge))
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
