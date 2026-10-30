"""Draw the README benchmark charts from bench/results.json.

usage: python bench/charts.py            -> docs/bench-*.svg

results.json: {"<chart id>": {"title": str, "subtitle": str, "unit": str,
                              "bars": [[label, value, "apkscope"|"jadx"|"other"], ...]}}
Only measured numbers belong in results.json; this script just draws them.
"""
import json
import os

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "..", "docs")
COLORS = {"apkscope": "#3b82f6", "jadx": "#9ca3af", "other": "#a78bfa"}
TEXT = "#6b7280"
STRONG = "#111827"


def fmt(v, unit):
    if unit == "s":
        if v >= 60:
            m, s = divmod(round(v), 60)
            return f"{m} min {s:02d} s"
        return f"{v:.1f} s" if v >= 1 else f"{v * 1000:.0f} ms"
    if unit == "MB":
        return f"{v / 1024:.1f} GB" if v >= 1024 else f"{v:,.0f} MB"
    return f"{v:,}{unit}"


def chart(c):
    bars = c["bars"]
    w, left, right, top, row = 760, 210, 120, 64, 34
    h = top + row * len(bars) + 16
    vmax = max(b[1] for b in bars) or 1
    span = w - left - right
    css = (f".t{{font:600 17px -apple-system,Segoe UI,Helvetica,Arial,sans-serif;fill:{STRONG}}}"
           f".s{{font:12px -apple-system,Segoe UI,Helvetica,Arial,sans-serif;fill:{TEXT}}}"
           f".l{{font:13px -apple-system,Segoe UI,Helvetica,Arial,sans-serif;fill:{TEXT}}}"
           f".v{{font:600 13px -apple-system,Segoe UI,Helvetica,Arial,sans-serif;fill:{STRONG}}}"
           f"@media (prefers-color-scheme:dark){{.t,.v{{fill:#f3f4f6}}.s,.l{{fill:#9ca3af}}}}")
    out = [f'<svg xmlns="http://www.w3.org/2000/svg" width="{w}" height="{h}" viewBox="0 0 {w} {h}">',
           f"<style>{css}</style>",
           f'<text class="t" x="0" y="24">{c["title"]}</text>',
           f'<text class="s" x="0" y="44">{c.get("subtitle", "")}</text>']
    for i, (label, v, who) in enumerate(bars):
        y = top + i * row
        bw = max(3, span * v / vmax)
        out.append(f'<text class="l" x="{left - 12}" y="{y + 17}" text-anchor="end">{label}</text>')
        out.append(f'<rect x="{left}" y="{y + 4}" width="{bw:.1f}" height="20" rx="5" fill="{COLORS[who]}"/>')
        out.append(f'<text class="v" x="{left + bw + 8:.1f}" y="{y + 19}">{fmt(v, c["unit"])}</text>')
    out.append("</svg>")
    return "\n".join(out) + "\n"


def main():
    data = json.load(open(os.path.join(HERE, "results.json"), encoding="utf-8"))
    os.makedirs(OUT, exist_ok=True)
    for key, c in data.items():
        path = os.path.join(OUT, f"bench-{key}.svg")
        open(path, "w", encoding="utf-8").write(chart(c))
        print("wrote", os.path.relpath(path))


if __name__ == "__main__":
    main()
