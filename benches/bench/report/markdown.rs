//! `--format markdown` (the default): the PR-shaped table — a column per build, a row
//! per case — one per APK, the `--hash` table when it ran, and the column legend.

use crate::column::{ColKind, Column};
use crate::measure::{CaseBench, Cell};

use super::{Bench, fmt_rss, fmt_time};

pub(super) fn emit(bench: &Bench) -> Result<(), String> {
    for r in bench.results {
        println!();
        println!(
            "### {}",
            r.apk
                .file_name()
                .map(|s| s.to_string_lossy())
                .unwrap_or_default()
        );
        println!();
        table(&r.cases, bench.columns, cell_text);
        if bench.opts.hash {
            println!();
            println!("#### Output hashes (`--hash`)");
            println!();
            table(&r.cases, bench.columns, hash_cell_text);
        }
    }
    println!();
    println!(
        "Columns: {}",
        bench
            .columns
            .iter()
            .map(column_desc)
            .collect::<Vec<_>>()
            .join(" · ")
    );
    println!(
        "Median of {} runs; apkscope runs are cold (`-q --no-cache`); cells are wall time, peak \
         RSS. The whole-APK row: `apkscope decompile <apk>` for apkscope, `<tool> <apk>` for tools.",
        bench.opts.runs
    );
    if bench.opts.hash {
        println!();
        let n_refs = bench.columns.iter().filter(|c| c.is_apkscope()).count();
        if n_refs == 0 {
            println!(
                "`--hash`: no apkscope columns given; digests are shown but there is nothing to compare."
            );
        } else if n_refs == 1 {
            println!(
                "`--hash`: only one apkscope column ({}); add a second --compare, --pr or --bin to detect output changes between builds.",
                bench
                    .columns
                    .iter()
                    .find(|c| c.is_apkscope())
                    .map(|c| c.name.as_str())
                    .unwrap_or_default()
            );
        } else if bench.diffs.is_empty() {
            println!("`--hash`: outputs identical across all compared refs.");
        } else {
            println!(
                "**`--hash`: {} case(s) produce different output across the compared refs**",
                bench.diffs.len()
            );
            for d in bench.diffs {
                println!();
                println!(
                    "- {} — {}: {}",
                    d.label,
                    d.apk,
                    d.cols
                        .iter()
                        .map(|(c, h)| format!("{c} = {}", &h[..h.len().min(12)]))
                        .collect::<Vec<_>>()
                        .join(", ")
                );
            }
        }
    }
    Ok(())
}

/// The PR-table shape: first cell empty, columns as columns, cases as rows.
fn table(cases: &[CaseBench], columns: &[Column], cell: fn(&Cell) -> String) {
    let heads: Vec<String> = columns.iter().map(|c| format!(" {} ", c.name)).collect();
    println!("|  |{}|", heads.join("|"));
    let dashes: Vec<&str> = std::iter::repeat_n(" --- ", columns.len() + 1).collect();
    println!("|{}|", dashes.join("|"));
    for case in cases {
        if case.cells.iter().all(|c| c.absent) {
            continue;
        }
        let cells: Vec<String> = case
            .cells
            .iter()
            .map(|c| format!(" {} ", cell(c)))
            .collect();
        println!("| {} |{}|", case.def.label, cells.join("|"));
    }
}

fn cell_text(c: &Cell) -> String {
    if c.absent {
        return "—".to_string();
    }
    if let Some(e) = &c.err {
        return one_line(&format!("FAILED ({e})"));
    }
    match (c.median_s, c.peak_rss) {
        (Some(t), Some(r)) => format!("{}, {}", fmt_time(t), fmt_rss(r)),
        (Some(t), None) => fmt_time(t),
        (None, _) => "n/a".to_string(),
    }
}

fn hash_cell_text(c: &Cell) -> String {
    match (&c.hash, c.absent) {
        (Some(h), _) => format!("`{}`", &h[..h.len().min(12)]),
        (None, true) => "—".to_string(),
        (None, _) => "n/a".to_string(),
    }
}

fn column_desc(c: &Column) -> String {
    match &c.kind {
        ColKind::Apkscope { sha } => format!(
            "{} = apkscope {} ({})",
            c.name,
            &sha[..sha.len().min(7)],
            c.exe.display()
        ),
        ColKind::Bin { version } => format!(
            "{} = {} (apkscope {}, given with --bin)",
            c.name,
            c.exe.display(),
            version
        ),
        ColKind::Tool => format!("{} = {} (external tool)", c.name, c.exe.display()),
    }
}

/// keep the table intact: no pipes, no line breaks
fn one_line(s: &str) -> String {
    s.chars()
        .map(|c| {
            if c == '|' || c == '\n' || c == '\r' {
                ' '
            } else {
                c
            }
        })
        .collect()
}
