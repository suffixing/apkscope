//! The run loops: every case against every column, `--runs` times, folded into
//! [`Cell`] medians. This is the only place that decides what a cell records; cases
//! and columns arrive as data, so the loop never changes when either grows.

use std::{
    fs,
    path::{Path, PathBuf},
};

use crate::case::{self, CaseDef, CaseInput};
use crate::cli::Opts;
use crate::column::Column;
use crate::digest::{apk_digest, digest_hex};
use crate::exec::run_once;
use crate::util::slug;

pub(crate) struct Cell {
    /// median wall time over the successful runs
    pub(crate) median_s: Option<f64>,
    /// median peak RSS over the successful runs, in bytes
    pub(crate) peak_rss: Option<u64>,
    /// SHA-256 of the first successful run's output (with `--hash`)
    pub(crate) hash: Option<String>,
    /// set when every run failed: what to print in the cell
    pub(crate) err: Option<String>,
    /// the case does not apply to this column (`--tool` on an apkscope-only case)
    pub(crate) absent: bool,
}

pub(crate) struct CaseBench {
    pub(crate) def: &'static CaseDef,
    pub(crate) cells: Vec<Cell>,
}

pub(crate) struct ApkBench {
    pub(crate) apk: PathBuf,
    /// the class the `decompile`/`smali` cases use, picked from `classes` output
    pub(crate) class: Option<String>,
    pub(crate) cases: Vec<CaseBench>,
}

pub(crate) fn measure(
    opts: &Opts,
    repo: &Path,
    columns: &[Column],
    apks: &[PathBuf],
) -> Result<Vec<ApkBench>, String> {
    let cases: Vec<&'static CaseDef> = if opts.only_cases.is_empty() {
        // the default set skips opt-in rows: their command is not on every ref
        // (the fingerprint command lands with #51), so a default run against
        // `origin/main` — the `--pr` base — would fail them
        case::all_cases().iter().filter(|c| !c.opt_in).collect()
    } else {
        let mut v = Vec::new();
        for name in &opts.only_cases {
            v.push(case::case_def(name).ok_or_else(|| {
                format!(
                    "unknown case {name}; valid: {}",
                    case::all_cases()
                        .iter()
                        .map(|c| c.id)
                        .collect::<Vec<_>>()
                        .join(", ")
                )
            })?);
        }
        v
    };
    if opts.runs == 0 {
        return Err("--runs must be at least 1".into());
    }
    let first_ref = columns.iter().position(|c| c.is_apkscope());
    let mut results = Vec::new();
    for apk in apks {
        // the class every column decompiles: picked once, from the first ref, so the
        // outputs (and their --hash digests) are comparable across columns
        let class = if cases.iter().any(|c| c.needs_class) {
            match first_ref.map(|i| pick_class(&columns[i].exe, apk)) {
                Some(Some(c)) => Some(c),
                Some(None) => {
                    eprintln!(
                        "{}: no class found; the decompile/smali cases will read n/a",
                        apk.display()
                    );
                    None
                }
                None => None,
            }
        } else {
            None
        };
        eprintln!(
            "{}: {} cases × {} columns × {} runs",
            apk.display(),
            cases.len(),
            columns.len(),
            opts.runs
        );
        let mut case_benches = Vec::new();
        for def in &cases {
            let mut cells = Vec::new();
            for col in columns {
                cells.push(measure_cell(opts, repo, def, col, apk, class.as_deref()));
            }
            case_benches.push(CaseBench { def, cells });
        }
        results.push(ApkBench {
            apk: apk.clone(),
            class,
            cases: case_benches,
        });
    }
    Ok(results)
}

fn measure_cell(
    opts: &Opts,
    repo: &Path,
    def: &CaseDef,
    col: &Column,
    apk: &Path,
    class: Option<&str>,
) -> Cell {
    if !col.is_apkscope() && def.apkscope_only {
        return Cell {
            median_s: None,
            peak_rss: None,
            hash: None,
            err: None,
            absent: true,
        };
    }
    if def.needs_class && class.is_none() {
        return Cell {
            median_s: None,
            peak_rss: None,
            hash: None,
            err: None,
            absent: false,
        };
    }
    // every column gets its own scratch dir: tools may drop files next to their output
    // (`jadx app.apk` writes an `app/` folder), and `build` writes out.apk per column
    let apk_slug = slug(
        &apk.file_name()
            .map(|s| s.to_string_lossy())
            .unwrap_or_default(),
    );
    let out_dir = repo
        .join("target/bench/out")
        .join(apk_slug)
        .join(slug(&col.name));
    let out_apk = out_dir.join("out.apk");
    let _ = fs::create_dir_all(&out_dir);
    let input = CaseInput {
        apk,
        class,
        out: Some(&out_apk),
    };
    let (args, cwd) = if col.is_apkscope() {
        (def.argv(&input), None)
    } else {
        (vec![apk.display().to_string()], Some(out_dir.as_path()))
    };
    let mut times: Vec<f64> = Vec::new();
    let mut rss: Vec<u64> = Vec::new();
    let mut hash = None;
    let mut fail = None;
    let mut failed_runs = 0;
    for _ in 0..opts.runs {
        match run_once(&col.exe, &args, cwd) {
            Ok(ro) if ro.exit == 0 => {
                times.push(ro.seconds);
                if let Some(b) = ro.peak_rss {
                    rss.push(b);
                }
                if opts.hash && hash.is_none() {
                    // a failed digest disables the comparison for this cell (hash stays
                    // None) instead of failing the run that produced the output
                    let digest = if def.id == "build" {
                        apk_digest(&out_apk)
                    } else {
                        Ok(digest_hex(&ro.stdout))
                    };
                    hash = match digest {
                        Ok(h) => Some(h),
                        Err(e) => {
                            eprintln!("warning: {} on {}: {e}", def.label, col.name);
                            None
                        }
                    };
                }
            }
            Ok(ro) => {
                failed_runs += 1;
                fail = Some(fail_msg(ro.exit, &ro.stderr));
            }
            Err(e) => {
                failed_runs += 1;
                fail = Some(e);
            }
        }
    }
    if failed_runs > 0 {
        // a partially failed cell still reports the median of its successful runs, but
        // never silently
        eprintln!(
            "warning: {failed_runs}/{} runs failed for {} — {} on {}: {}",
            opts.runs,
            col.name,
            def.label,
            apk.display(),
            fail.as_deref().unwrap_or("?")
        );
    }
    if times.is_empty() {
        return Cell {
            median_s: None,
            peak_rss: None,
            hash,
            err: fail,
            absent: false,
        };
    }
    Cell {
        median_s: median_f64(&mut times),
        peak_rss: median_u64(&mut rss),
        hash,
        err: None,
        absent: false,
    }
}

/// The class the one-class rows decompile: the first line of `classes` output.
fn pick_class(exe: &Path, apk: &Path) -> Option<String> {
    let classes = case::case_def("classes").expect("the classes case exists");
    let input = CaseInput {
        apk,
        class: None,
        out: None,
    };
    let out = run_once(exe, &classes.argv(&input), None).ok()?;
    if out.exit != 0 {
        return None;
    }
    let line = String::from_utf8_lossy(&out.stdout)
        .lines()
        .next()?
        .trim()
        .to_string();
    (!line.is_empty()).then_some(line)
}

fn fail_msg(exit: i32, stderr: &str) -> String {
    let first = stderr
        .lines()
        .find(|l| !l.trim().is_empty())
        .unwrap_or_default()
        .trim();
    let mut m = format!("exit {exit}");
    if !first.is_empty() {
        m.push_str(": ");
        m.push_str(&first.chars().take(60).collect::<String>());
    }
    m
}

fn median_f64(v: &mut [f64]) -> Option<f64> {
    if v.is_empty() {
        return None;
    }
    v.sort_by(|a, b| a.total_cmp(b));
    Some(v[v.len() / 2])
}

fn median_u64(v: &mut [u64]) -> Option<u64> {
    if v.is_empty() {
        return None;
    }
    v.sort_unstable();
    Some(v[v.len() / 2])
}
