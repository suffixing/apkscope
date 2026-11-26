//! The command line. Every flag the harness takes lives here; `Format` doubles as the
//! report dispatch — an output format is a variant below, a file under `report/`, and
//! a match arm in `report::emit`.

use std::path::PathBuf;

use clap::{Parser, ValueEnum};

#[derive(Parser)]
#[command(
    name = "apkscope-bench",
    bin_name = "cargo bench --",
    about = "build apkscope at git refs or take given binaries, measure its subcommands on APKs, print the PR table",
    after_help = "run as: cargo bench -- [OPTIONS]  (the -- passes OPTIONS to this harness)"
)]
pub(crate) struct Opts {
    /// git ref to build and measure; repeatable — one column each, the first is the
    /// baseline. `HEAD` (or `.`) builds the working tree, uncommitted changes included.
    /// Default: the working tree alone — unless `--bin` or `--pr` name other columns.
    #[arg(long, value_name = "REF")]
    pub(crate) compare: Vec<String>,

    /// ready-made apkscope binary to measure as-is, no build; repeatable — two local
    /// builds to race, or a real install next to an `apkscope-pr-<N>` preview from
    /// `scripts/preview-pr.sh`
    #[arg(long, value_name = "PATH")]
    pub(crate) bin: Vec<PathBuf>,

    /// pull request to compare against its base: fetch GitHub's merge ref for PR N —
    /// the same merge CI builds — into `refs/bench/pr-N` and bench it as a `pr-N`
    /// column; repeatable. Without `--compare`, the base ref (`--base`) comes first
    #[arg(long = "pr", value_name = "N", value_parser = clap::value_parser!(u64).range(1..))]
    pub(crate) pr: Vec<u64>,

    /// the ref the `--pr` columns are judged against — the first column when `--pr`
    /// runs without `--compare`; default `origin/main`, the tip GitHub merges them into
    #[arg(long, value_name = "REF", default_value = "origin/main")]
    pub(crate) base: String,

    /// APK to measure; repeatable. Default: every app in bench/apps/ (APKs are not
    /// committed, so usually this is passed explicitly).
    #[arg(long, value_name = "PATH")]
    pub(crate) apk: Vec<PathBuf>,

    /// external tool to race apkscope against, found on PATH (or an absolute path);
    /// repeatable. Runs `<TOOL> <APK>` in a scratch directory — the whole-APK row only.
    #[arg(long, value_name = "NAME")]
    pub(crate) tool: Vec<String>,

    /// output format: the Markdown table (default), JSON on stdout, or SVG bar charts
    /// into docs/
    #[arg(long, value_name = "FMT", default_value = "markdown")]
    pub(crate) format: Format,

    /// digest every run's output with SHA-256 and, across the apkscope columns
    /// (--compare, --pr, --bin alike), report (and exit 3 on) any case whose output
    /// differs between builds. The `build` case hashes the rebuilt APK's entry list
    /// and CRCs instead of stdout.
    #[arg(long)]
    pub(crate) hash: bool,

    /// runs per case and column; the median lands in the table
    #[arg(long, value_name = "N", default_value_t = 3)]
    pub(crate) runs: usize,

    /// only these cases (repeatable): info, classes, strings, decompile, smali, build,
    /// whole, fingerprint (the last only on refs that have the command, e.g. #51's)
    #[arg(long = "case", value_name = "NAME")]
    pub(crate) only_cases: Vec<String>,

    /// cargo's own bench-mode marker, injected when `cargo bench` runs this binary:
    /// accepted and ignored so plain `cargo bench -- <flags>` works
    #[arg(long, hide = true)]
    bench: bool,
}

#[derive(Clone, Copy, ValueEnum)]
pub(crate) enum Format {
    Markdown,
    Json,
    Svg,
}
