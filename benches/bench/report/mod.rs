//! The output formats: one file per format, dispatched on `cli::Format`.
//!
//! To add a format, add a variant to `Format` (`cli.rs`), a file here with a
//! `pub(super) fn emit(&Bench) -> Result<(), String>`, and a match arm in `emit`
//! below. Everything a format may need travels in [`Bench`], so no format reaches
//! into the pipeline. The value formatters `fmt_time`/`fmt_rss` are shared by the
//! markdown table and the svg charts, so one place keeps the units honest.

mod json;
mod markdown;
mod svg;

use crate::cli::{Format, Opts};
use crate::column::Column;
use crate::digest::HashDiff;
use crate::measure::ApkBench;

/// One finished bench, ready to report: what was measured, under which columns, with
/// which options, and which `--hash` differences were found.
pub(crate) struct Bench<'a> {
    pub(crate) results: &'a [ApkBench],
    pub(crate) columns: &'a [Column],
    pub(crate) opts: &'a Opts,
    pub(crate) diffs: &'a [HashDiff],
}

/// Print the bench in the asked-for format.
pub(crate) fn emit(format: Format, bench: &Bench) -> Result<(), String> {
    match format {
        Format::Markdown => markdown::emit(bench),
        Format::Json => json::emit(bench),
        Format::Svg => svg::emit(bench),
    }
}

/// `211 ms`, `12.8 s`, `3 min 12 s` — the unit follows the value: milliseconds under
/// a second — where cold-query differences live — seconds above it, minutes past a
/// minute.
pub(crate) fn fmt_time(s: f64) -> String {
    if s >= 60.0 {
        format!(
            "{} min {} s",
            s as u64 / 60,
            s.rem_euclid(60.0).round() as u64
        )
    } else if s >= 10.0 {
        format!("{s:.1} s")
    } else if s >= 1.0 {
        format!("{s:.2} s")
    } else if s >= 0.1 {
        format!("{:.0} ms", s * 1000.0)
    } else {
        format!("{:.1} ms", s * 1000.0)
    }
}

/// Peak RSS in MB, the unit every table and chart prints it in.
pub(crate) fn fmt_rss(b: u64) -> String {
    format!("{} MB", (b as f64 / 1_048_576.0).round() as u64)
}
