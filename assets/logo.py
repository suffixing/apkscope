"""Draw the apkscope logo: a rounded blue-violet tile with a white magnifier over `</>`.

usage: python assets/logo.py
writes assets/logo.svg, assets/apkscope.ico (16-256 px) and assets/icon64.rgba (window icon).
The shapes are defined once (unit square) and both rasterized here and emitted as SVG.
"""
import math
import os
import struct
import zlib

HERE = os.path.dirname(os.path.abspath(__file__))
C1, C2 = (37, 99, 235), (124, 58, 237)  # gradient, top-left to bottom-right
RING = (0.43, 0.42, 0.25, 0.075)  # cx, cy, radius, stroke width
HANDLE = ((0.61, 0.60), (0.80, 0.79), 0.085)
# `<` and `>` inside the lens, as two strokes each
BRACKETS = [((0.395, 0.355), (0.335, 0.42)), ((0.335, 0.42), (0.395, 0.485)), ((0.465, 0.355), (0.525, 0.42)), ((0.525, 0.42), (0.465, 0.485))]
BRACKET_W = 0.035
CORNER = 0.22


def seg_dist(px, py, a, b):
    (ax, ay), (bx, by) = a, b
    dx, dy = bx - ax, by - ay
    t = max(0.0, min(1.0, ((px - ax) * dx + (py - ay) * dy) / (dx * dx + dy * dy)))
    return math.hypot(px - ax - t * dx, py - ay - t * dy)


def tile_dist(x, y):
    # rounded square from 0.04 to 0.96
    lo, hi = 0.04 + CORNER, 0.96 - CORNER
    qx = max(lo - x, 0, x - hi)
    qy = max(lo - y, 0, y - hi)
    return math.hypot(qx, qy) - CORNER


def white(x, y):
    cx, cy, r, w = RING
    if abs(math.hypot(x - cx, y - cy) - r) < w / 2:
        return True
    a, b, hw = HANDLE
    if seg_dist(x, y, a, b) < hw / 2:
        return True
    return any(seg_dist(x, y, a, b) < BRACKET_W / 2 for a, b in BRACKETS)


def pixel(x, y):
    """RGBA of one sample at unit coordinates."""
    if tile_dist(x, y) > 0:
        return (0, 0, 0, 0)
    if white(x, y):
        return (255, 255, 255, 255)
    t = (x + y) / 2
    return tuple(round(C1[i] + (C2[i] - C1[i]) * t) for i in range(3)) + (255,)


def render(size, ss=4):
    out = bytearray()
    for j in range(size):
        for i in range(size):
            acc = [0, 0, 0, 0]
            for sj in range(ss):
                for si in range(ss):
                    p = pixel((i + (si + 0.5) / ss) / size, (j + (sj + 0.5) / ss) / size)
                    a = p[3]
                    for k in range(3):
                        acc[k] += p[k] * a
                    acc[3] += a
            n = ss * ss
            a = acc[3] / n
            out += bytes([round(acc[k] / acc[3]) if acc[3] else 0 for k in range(3)] + [round(a)])
    return bytes(out)


def png(size, rgba):
    raw = b"".join(b"\x00" + rgba[y * size * 4:(y + 1) * size * 4] for y in range(size))
    def chunk(t, d):
        return struct.pack(">I", len(d)) + t + d + struct.pack(">I", zlib.crc32(t + d) & 0xFFFFFFFF)
    return b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", size, size, 8, 6, 0, 0, 0)) + chunk(b"IDAT", zlib.compress(raw, 9)) + chunk(b"IEND", b"")


def ico(images):
    head = struct.pack("<HHH", 0, 1, len(images))
    offset = 6 + 16 * len(images)
    dirs, blobs = b"", b""
    for size, data in images:
        dirs += struct.pack("<BBBBHHII", size % 256, size % 256, 0, 0, 1, 32, len(data), offset + len(blobs))
        blobs += data
    return head + dirs + blobs


def svg():
    cx, cy, r, w = RING
    (ax, ay), (bx, by), hw = HANDLE
    s = 512
    br = "".join(f'<line x1="{a[0]*s:.1f}" y1="{a[1]*s:.1f}" x2="{b[0]*s:.1f}" y2="{b[1]*s:.1f}"/>' for a, b in BRACKETS)
    return (f'<svg xmlns="http://www.w3.org/2000/svg" width="{s}" height="{s}" viewBox="0 0 {s} {s}">'
            f'<defs><linearGradient id="g" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stop-color="rgb{C1}"/><stop offset="1" stop-color="rgb{C2}"/></linearGradient></defs>'
            f'<rect x="{0.04*s:.1f}" y="{0.04*s:.1f}" width="{0.92*s:.1f}" height="{0.92*s:.1f}" rx="{CORNER*s:.1f}" fill="url(#g)"/>'
            f'<g fill="none" stroke="#fff" stroke-linecap="round">'
            f'<circle cx="{cx*s:.1f}" cy="{cy*s:.1f}" r="{r*s:.1f}" stroke-width="{w*s:.1f}"/>'
            f'<line x1="{ax*s:.1f}" y1="{ay*s:.1f}" x2="{bx*s:.1f}" y2="{by*s:.1f}" stroke-width="{hw*s:.1f}"/>'
            f'<g stroke-width="{BRACKET_W*s:.1f}" stroke-linejoin="round">{br}</g></g></svg>\n')


def main():
    open(os.path.join(HERE, "logo.svg"), "w").write(svg())
    images = [(n, png(n, render(n, 4 if n <= 64 else 2))) for n in (16, 24, 32, 48, 64, 128, 256)]
    open(os.path.join(HERE, "apkscope.ico"), "wb").write(ico(images))
    open(os.path.join(HERE, "icon64.rgba"), "wb").write(render(64, 4))
    open(os.path.join(HERE, "logo-256.png"), "wb").write(images[-1][1])
    print("wrote logo.svg, apkscope.ico, icon64.rgba, logo-256.png")


if __name__ == "__main__":
    main()
