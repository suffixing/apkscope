//! `--format svg`: one grouped horizontal bar chart per APK and metric, written to
//! `docs/bench-<apk>-{time,ram}.svg` — hand-written SVG, no rendering dependency.

use std::{fs, path::Path};

use super::{Bench, fmt_time};
use crate::column::Column;
use crate::measure::Cell;
use crate::util::slug;

const COLORS: &[&str] = &[
    "#2563eb", "#dc2626", "#16a34a", "#d97706", "#7c3aed", "#0e7490", "#be185d", "#4d7c0f",
];

pub(super) fn emit(bench: &Bench) -> Result<(), String> {
    for r in bench.results {
        let stem = r
            .apk
            .file_stem()
            .map(|s| s.to_string_lossy())
            .unwrap_or_default()
            .into_owned();
        let base = slug(&stem);
        for (metric, file, pick) in [
            ("wall time", "time", pick_time as fn(&Cell) -> Option<f64>),
            ("peak RSS", "ram", pick_rss as fn(&Cell) -> Option<f64>),
        ] {
            let path = Path::new("docs").join(format!("bench-{base}-{file}.svg"));
            let rows: Vec<(&str, Vec<(usize, f64)>)> = r
                .cases
                .iter()
                .filter(|case| case.cells.iter().any(|c| !c.absent && pick(c).is_some()))
                .map(|case| {
                    (
                        case.def.label,
                        case.cells
                            .iter()
                            .enumerate()
                            .filter(|(_, c)| !c.absent)
                            .filter_map(|(i, c)| pick(c).map(|v| (i, v)))
                            .collect(),
                    )
                })
                .collect();
            if rows.iter().all(|(_, v)| v.is_empty()) {
                continue;
            }
            let title = format!("apkscope bench — {stem}: {metric} (median)");
            let svg = chart(&rows, bench.columns, &title, metric);
            fs::create_dir_all("docs").map_err(|e| format!("docs/: {e}"))?;
            fs::write(&path, svg).map_err(|e| format!("{}: {e}", path.display()))?;
            println!("wrote {}", path.display());
        }
    }
    Ok(())
}

fn pick_time(c: &Cell) -> Option<f64> {
    c.median_s
}

fn pick_rss(c: &Cell) -> Option<f64> {
    c.peak_rss.map(|b| b as f64 / 1_048_576.0)
}

/// Grouped horizontal bars: one row per case, one bar per column, all bars scaled by the
/// chart's maximum. Hand-written SVG — no rendering dependency.
fn chart(
    rows: &[(&str, Vec<(usize, f64)>)],
    columns: &[Column],
    title: &str,
    metric: &str,
) -> String {
    const W: f64 = 940.0;
    const MARGIN_L: f64 = 250.0;
    const MARGIN_R: f64 = 130.0;
    const MARGIN_T: f64 = 70.0;
    const BAR_H: f64 = 12.0;
    const BAR_DY: f64 = 17.0;
    const ROW_GAP: f64 = 12.0;
    let vmax = rows
        .iter()
        .flat_map(|(_, v)| v.iter().map(|(_, x)| *x))
        .fold(0.0_f64, f64::max);
    let plot_w = W - MARGIN_L - MARGIN_R;
    let row_h = |bars: usize| bars as f64 * BAR_DY + ROW_GAP;
    let height = MARGIN_T + rows.iter().map(|(_, v)| row_h(v.len())).sum::<f64>() + 14.0;
    let mut s = String::with_capacity(4096);
    s.push_str(&format!(
        "<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"{W:.0}\" height=\"{height:.0}\" \
         font-family=\"ui-sans-serif, system-ui, sans-serif\">\n"
    ));
    s.push_str("<rect width=\"100%\" height=\"100%\" fill=\"white\"/>\n");
    s.push_str(&format!(
        "<text x=\"16\" y=\"24\" font-size=\"15\" font-weight=\"bold\" fill=\"#111827\">{}</text>\n",
        esc(title)
    ));
    for (i, col) in columns.iter().enumerate() {
        let x = 16.0 + i as f64 * 190.0;
        s.push_str(&format!(
            "<rect x=\"{x:.0}\" y=\"34\" width=\"10\" height=\"10\" fill=\"{}\"/>\n",
            color(i)
        ));
        s.push_str(&format!(
            "<text x=\"{:.0}\" y=\"43\" font-size=\"12\" fill=\"#374151\">{}</text>\n",
            x + 14.0,
            esc(&col.name)
        ));
    }
    let mut y = MARGIN_T;
    for (label, bars) in rows {
        let label: String = label.trim_matches('`').to_string();
        let block = row_h(bars.len());
        s.push_str(&format!(
            "<text x=\"{}\" y=\"{:.0}\" font-size=\"12\" fill=\"#111827\" \
             text-anchor=\"end\">{}</text>\n",
            MARGIN_L - 8.0,
            y + BAR_DY * 0.75,
            esc(&label)
        ));
        for (j, (col, v)) in bars.iter().enumerate() {
            let by = y + j as f64 * BAR_DY;
            let w = (v / vmax * plot_w).max(1.0);
            s.push_str(&format!(
                "<rect x=\"{:.0}\" y=\"{by:.0}\" width=\"{w:.0}\" height=\"{BAR_H:.0}\" \
                 fill=\"{}\"/>\n",
                MARGIN_L,
                color(*col)
            ));
            s.push_str(&format!(
                "<text x=\"{:.0}\" y=\"{:.0}\" font-size=\"11\" fill=\"#374151\">{}</text>\n",
                MARGIN_L + w + 6.0,
                by + BAR_H - 1.0,
                esc(&fmt_value(*v, metric))
            ));
        }
        y += block;
        s.push_str(&format!(
            "<line x1=\"16\" y1=\"{y:.0}\" x2=\"{}\" y2=\"{y:.0}\" stroke=\"#e5e7eb\"/>\n",
            W - 16.0
        ));
    }
    s.push_str("</svg>\n");
    s
}

fn color(i: usize) -> &'static str {
    COLORS[i % COLORS.len()]
}

fn fmt_value(v: f64, metric: &str) -> String {
    if metric == "peak RSS" {
        format!("{v:.0} MB")
    } else {
        fmt_time(v)
    }
}

fn esc(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}
