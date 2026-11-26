//! The `cargo bench` target (#64): build apkscope at one or more git refs — or take
//! ready-made binaries — run its subcommands on a set of APKs as fresh processes, and
//! print the Markdown comparison table that PR bodies paste by hand — replacing what
//! the retired `bench/*.ps1` and `bench/*.py` scripts measured, without Python,
//! PowerShell or a JDK on the benching machine.
//!
//! ```text
//! cargo bench -- --compare main --compare HEAD --apk bench/apps/TikTok.apk
//! cargo bench -- --pr 79 --apk Telegram.apk
//! cargo bench -- --bin ~/bin/apkscope --bin ~/.local/bin/apkscope-pr-79 --apk Telegram.apk
//! ```
//!
//! The `--` matters: `--compare` is this harness's flag, not cargo's, so it goes after
//! cargo's own separator. Plain `cargo bench` also works and measures the working tree
//! alone. Columns are the refs (built under `target/bench/`, worktrees under
//! `target/bench/wt/`), the pull requests `--pr` fetches (GitHub's merge ref, kept
//! under `refs/bench/`), the ready-made binaries `--bin` points at (measured as given,
//! no build — two apkscope builds to race, e.g. an `apkscope-pr-<N>` preview from
//! `scripts/preview-pr.sh`), and any `--tool` binaries found on PATH. Rows are the case
//! set `BENCHMARKS.md` reports: `info`, `classes`, `strings`, `decompile` (one class),
//! `smali` (one class), `build`, and the whole-APK row. Every cell is `time, peak RSS`,
//! the median of `--runs` cold runs (`-q --no-cache`); times below a second print in
//! milliseconds, above it in seconds.
//!
//! `--hash` adds an output-equivalence check: each run's stdout — for `build`, the
//! rebuilt APK's entry list and CRCs — is digested with SHA-256, and when several refs
//! are compared, differing digests are reported and the bench exits 3, so a PR that
//! changes output while chasing speed is caught next to the numbers.
//!
//! `--format json` dumps the same measurements machine-readably; `--format svg` writes
//! bar charts to `docs/bench-<apk>-{time,ram}.svg`.
//!
//! Exit codes: 0 = every run succeeded; 1 = a run failed; 2 = setup error; 3 = `--hash`
//! found differing outputs (cargo reports that as a failed bench — that is the point).
//!
//! The harness is split the way `src/commands/` is: this file is the pipeline — parse
//! the flags, resolve the APKs, build the columns, measure, report — and every stage
//! owns a file next to it:
//!
//! ```text
//! bench/main.rs     this pipeline: main → run → resolve_apks
//! bench/cli.rs      the command line: Opts, Format
//! bench/case.rs     the case set — one CaseDef per row; add cases here
//! bench/column.rs   --compare/--pr/--bin/--tool → runnable Column binaries
//! bench/exec.rs     one timed subprocess: wall time, peak RSS, stdout
//! bench/measure.rs  cases × columns × runs → Cell medians
//! bench/digest.rs   --hash: SHA-256 digests and the cross-column comparison
//! bench/report/     the output formats: markdown, json, svg — one file each
//! bench/util.rs     git, slugs, tails: shared plumbing
//! ```

mod case;
mod cli;
mod column;
mod digest;
mod exec;
mod measure;
mod report;
mod util;

use std::{
    fs,
    path::{Path, PathBuf},
};

use clap::Parser as _;

use cli::Opts;

fn main() -> std::process::ExitCode {
    let opts = Opts::parse();
    match run(&opts) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("error: {e}");
            std::process::ExitCode::from(2)
        }
    }
}

fn run(opts: &Opts) -> Result<std::process::ExitCode, String> {
    let repo = util::repo_root()?;
    let apks = resolve_apks(&repo, opts)?;
    let columns = column::build_columns(&repo, opts)?;
    let results = measure::measure(opts, &repo, &columns, &apks)?;
    let failed = results
        .iter()
        .flat_map(|r| r.cases.iter())
        .flat_map(|c| c.cells.iter())
        .any(|c| c.err.is_some());
    let diffs = if opts.hash {
        digest::hash_diffs(&results, &columns)
    } else {
        Vec::new()
    };
    report::emit(
        opts.format,
        &report::Bench {
            results: &results,
            columns: &columns,
            opts,
            diffs: &diffs,
        },
    )?;
    if !diffs.is_empty() {
        for d in &diffs {
            eprintln!(
                "output differs: {} on {}: {}",
                d.label,
                d.apk,
                d.cols
                    .iter()
                    .map(|(c, h)| format!("{c} {}", &h[..h.len().min(12)]))
                    .collect::<Vec<_>>()
                    .join(" vs ")
            );
        }
        eprintln!("--hash: {} case(s) differ; exit 3", diffs.len());
        return Ok(std::process::ExitCode::from(3));
    }
    if failed {
        eprintln!("a run failed; exit 1");
        return Ok(std::process::ExitCode::from(1));
    }
    Ok(std::process::ExitCode::SUCCESS)
}

/// The APKs to measure: `--apk` as given, or every app in `bench/apps/` — a
/// convention: APKs are not committed, so the explicit list is the usual path.
fn resolve_apks(repo: &Path, opts: &Opts) -> Result<Vec<PathBuf>, String> {
    if !opts.apk.is_empty() {
        for p in &opts.apk {
            if !p.is_file() {
                return Err(format!("{}: no such file", p.display()));
            }
        }
        return Ok(opts.apk.clone());
    }
    let dir = repo.join("bench/apps");
    let mut apks: Vec<PathBuf> = fs::read_dir(&dir)
        .into_iter()
        .flatten()
        .flatten()
        .map(|e| e.path())
        .filter(|p| {
            matches!(
                p.extension()
                    .and_then(|e| e.to_str())
                    .map(|s| s.to_ascii_lowercase())
                    .as_deref(),
                Some("apk" | "xapk" | "apks" | "apkm" | "jar" | "dex")
            )
        })
        .collect();
    apks.sort();
    if apks.is_empty() {
        return Err(format!(
            "no --apk given and {} holds no APKs; APKs are not committed, so pass --apk \
             <path> (repeatable)",
            dir.display()
        ));
    }
    Ok(apks)
}
