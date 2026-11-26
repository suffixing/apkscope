//! `--format json`: the same measurements machine-readably — per column: name, exe,
//! commit sha (built refs) or `--version` line (`--bin`); per cell: median seconds,
//! peak RSS bytes, digest, error.

use serde_json::json;

use super::Bench;
use crate::column::ColKind;

pub(super) fn emit(bench: &Bench) -> Result<(), String> {
    let v = json!({
        "runs": bench.opts.runs,
        "columns": bench
            .columns
            .iter()
            .map(|c| json!({
                "name": c.name,
                "kind": if c.is_apkscope() { "apkscope" } else { "tool" },
                "exe": c.exe.display().to_string(),
                "sha": match &c.kind {
                    ColKind::Apkscope { sha } => json!(sha),
                    ColKind::Bin { .. } | ColKind::Tool => json!(null),
                },
                "version": match &c.kind {
                    // the `--version` line of a --bin column; null for built refs and tools
                    ColKind::Bin { version } => json!(version),
                    ColKind::Apkscope { .. } | ColKind::Tool => json!(null),
                },
            }))
            .collect::<Vec<_>>(),
        "apks": bench
            .results
            .iter()
            .map(|r| json!({
                "apk": r.apk.display().to_string(),
                "class": r.class,
                "cases": r
                    .cases
                    .iter()
                    .map(|case| json!({
                        "case": case.def.id,
                        "label": case.def.label,
                        "cells": case
                            .cells
                            .iter()
                            .map(|c| json!({
                                "median_s": c.median_s,
                                "peak_rss_bytes": c.peak_rss,
                                "hash": c.hash,
                                "error": c.err,
                                "absent": c.absent,
                            }))
                            .collect::<Vec<_>>(),
                    }))
                    .collect::<Vec<_>>(),
            }))
            .collect::<Vec<_>>(),
    });
    println!(
        "{}",
        serde_json::to_string_pretty(&v).map_err(|e| e.to_string())?
    );
    Ok(())
}
