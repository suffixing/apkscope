//! Columns: the builds the table races. Every way of naming one — `--compare` refs
//! built into worktrees, `--pr` merge refs fetched from origin, `--bin` binaries taken
//! as given, `--tool` executables found on PATH — ends as a [`Column`]: a name, an
//! executable, and what kind of thing it is. To add a source of columns, add a flag
//! in `cli.rs` and a block in `build_columns`; nothing downstream cares where a
//! binary came from.

use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
    time::Instant,
};

use crate::cli::Opts;
use crate::util::{git, slug, tail};

pub(crate) enum ColKind {
    /// an apkscope binary built at a git ref
    Apkscope { sha: String },
    /// an apkscope binary measured exactly as given (`--bin`), its `--version` probed
    /// up front
    Bin { version: String },
    /// an external tool raced in the whole-APK row
    Tool,
}

pub(crate) struct Column {
    pub(crate) name: String,
    pub(crate) kind: ColKind,
    pub(crate) exe: PathBuf,
}

impl Column {
    pub(crate) fn is_apkscope(&self) -> bool {
        matches!(self.kind, ColKind::Apkscope { .. } | ColKind::Bin { .. })
    }
}

fn exe_name() -> &'static str {
    if cfg!(windows) {
        "apkscope.exe"
    } else {
        "apkscope"
    }
}

pub(crate) fn build_columns(repo: &Path, opts: &Opts) -> Result<Vec<Column>, String> {
    // (column name, git ref, is the working tree?) — the name is what the table shows,
    // the ref what gets resolved and built, so `--pr` can display `pr-79` while building
    // the fetched `refs/bench/pr-79`
    let mut specs: Vec<(String, String, bool)> = Vec::new();
    for name in &opts.compare {
        let working_tree = name.eq_ignore_ascii_case("HEAD") || name == "." || name == "@";
        specs.push((name.clone(), name.clone(), working_tree));
    }
    if !opts.pr.is_empty() {
        fetch_prs(repo, &opts.pr)?;
        // with no --compare column to judge against, the base comes first — origin's
        // tip, the same tip GitHub merges the PRs into
        if specs.is_empty() {
            specs.push((opts.base.clone(), opts.base.clone(), false));
        }
        for n in &opts.pr {
            specs.push((format!("pr-{n}"), format!("refs/bench/pr-{n}"), false));
        }
    }
    // plain `cargo bench`: the working tree alone — but with `--bin` columns given, only
    // those are measured (no surprise build of the checkout next to them)
    if specs.is_empty() && opts.bin.is_empty() {
        specs.push(("HEAD".to_string(), "HEAD".to_string(), true));
    }
    let mut columns = Vec::new();
    // sha → already-built binary, so two refs at the same commit build once
    let mut built: Vec<(String, PathBuf)> = Vec::new();
    for (name, refname, working_tree) in specs {
        let sha = if working_tree {
            git(repo, &["rev-parse", "HEAD"])?
        } else {
            git(repo, &["rev-parse", &format!("{refname}^{{commit}}")])?
        };
        let exe = match built.iter().find(|(s, _)| s == &sha) {
            Some((_, exe)) if !working_tree => exe.clone(),
            _ => {
                let exe = build_ref(repo, &name, &sha, working_tree)?;
                if !working_tree {
                    built.push((sha.clone(), exe.clone()));
                }
                exe
            }
        };
        columns.push(Column {
            name,
            kind: ColKind::Apkscope { sha },
            exe,
        });
    }
    for bin in &opts.bin {
        if !bin.is_file() {
            return Err(format!("--bin {}: no such file", bin.display()));
        }
        let version = bin_version(bin)?;
        let stem = bin
            .file_stem()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_default();
        let mut name = if stem.is_empty() {
            "bin".to_string()
        } else {
            stem.clone()
        };
        // same stem twice (./old/apkscope, ./new/apkscope) still needs distinct columns
        // and distinct scratch dirs
        let mut n = 2;
        while columns.iter().any(|c| c.name == name) {
            name = format!("{stem}-{n}");
            n += 1;
        }
        columns.push(Column {
            name,
            kind: ColKind::Bin { version },
            exe: bin.clone(),
        });
    }
    for tool in &opts.tool {
        let exe = find_tool(tool)
            .ok_or_else(|| format!("tool {tool}: not found on PATH (or pass an absolute path)"))?;
        columns.push(Column {
            name: tool.clone(),
            kind: ColKind::Tool,
            exe,
        });
    }
    Ok(columns)
}

/// Build apkscope at one ref into `target/bench/bin/<ref>-<sha>/`. `HEAD` (and `.`)
/// compiles the working tree in place, uncommitted changes included, on every run —
/// cargo's own fingerprinting makes that a no-op when nothing changed; a sha-keyed
/// cache would go stale exactly when a PR is being written. Every other ref is checked
/// out into a worktree under `target/bench/wt/` and cached by sha (a worktree at a
/// given sha always holds the same source, so the cache cannot go stale). Each ref
/// gets its own `CARGO_TARGET_DIR` under `target/bench/build/` — one shared directory
/// would let one ref's binary overwrite another's between the build and the copy.
fn build_ref(repo: &Path, name: &str, sha: &str, working_tree: bool) -> Result<PathBuf, String> {
    let dir =
        repo.join("target/bench/bin")
            .join(format!("{}-{}", slug(name), &sha[..sha.len().min(7)]));
    let exe = dir.join(exe_name());
    if !working_tree && exe.is_file() {
        eprintln!("{name}: apkscope {} (cached)", &sha[..sha.len().min(12)]);
        return Ok(exe);
    }
    let build_dir = repo.join("target/bench/build").join(slug(name));
    let cwd = if working_tree {
        repo.to_path_buf()
    } else {
        let wt = repo.join("target/bench/wt").join(slug(name));
        let at = if wt.is_dir() {
            git(&wt, &["rev-parse", "HEAD"]).ok()
        } else {
            None
        };
        if at.as_deref() != Some(sha) {
            if wt.is_dir() {
                git(
                    repo,
                    &["worktree", "remove", "--force", &wt.display().to_string()],
                )?;
            }
            git(
                repo,
                &[
                    "worktree",
                    "add",
                    "--detach",
                    &wt.display().to_string(),
                    sha,
                ],
            )?;
        }
        wt
    };
    eprintln!(
        "{name}: building apkscope at {}…",
        &sha[..sha.len().min(12)]
    );
    let t0 = Instant::now();
    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_string());
    // the CLI + MCP server the cases exercise; the viewer is not benched
    let out = Command::new(cargo)
        .current_dir(&cwd)
        .env("CARGO_TARGET_DIR", &build_dir)
        .args(["build", "--release", "--no-default-features"])
        .output()
        .map_err(|e| format!("cargo build for {name}: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "cargo build for {name} failed:\n{}",
            tail(&String::from_utf8_lossy(&out.stderr), 25)
        ));
    }
    fs::create_dir_all(&dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    fs::copy(build_dir.join("release").join(exe_name()), &exe)
        .map_err(|e| format!("{}: {e}", exe.display()))?;
    eprintln!("{name}: built in {:.1} s", t0.elapsed().as_secs_f64());
    Ok(exe)
}

/// Fetch the `--pr` pull requests from `origin` into `refs/bench/pr-<N>`. The remote's
/// branches refresh first: GitHub builds each merge ref against the base branch's
/// current tip, so that tip — not a possibly stale local `main` — is the fair baseline.
/// The merge ref is the PR exactly as CI sees it; a PR with conflicts (or a closed one)
/// has none, and falls back to the plain, unmerged head.
fn fetch_prs(repo: &Path, prs: &[u64]) -> Result<(), String> {
    git(repo, &["fetch", "--quiet", "origin"])
        .map_err(|e| format!("fetching origin (needed by --pr): {e}"))?;
    for n in prs {
        let dst = format!("refs/bench/pr-{n}");
        let merge = format!("+pull/{n}/merge:{dst}");
        if git(repo, &["fetch", "--quiet", "origin", &merge]).is_ok() {
            continue;
        }
        let head = format!("+pull/{n}/head:{dst}");
        git(repo, &["fetch", "--quiet", "origin", &head])
            .map_err(|e| format!("fetching pr-{n} from origin: {e} — is PR #{n} open there?"))?;
        eprintln!(
            "pr-{n}: origin holds no merge ref (conflicts? closed?); benching the unmerged head"
        );
    }
    Ok(())
}

/// `--version` of a `--bin` column: proves the file is an apkscope binary before
/// minutes are spent on it, and lands in the table's footer as its build id.
fn bin_version(exe: &Path) -> Result<String, String> {
    let out = Command::new(exe)
        .arg("--version")
        .output()
        .map_err(|e| format!("--bin {}: {e}", exe.display()))?;
    let line = String::from_utf8_lossy(&out.stdout)
        .lines()
        .next()
        .unwrap_or_default()
        .trim()
        .to_string();
    if !out.status.success() || !line.starts_with("apkscope") {
        return Err(format!(
            "--bin {}: not an apkscope binary (`--version` said: {})",
            exe.display(),
            if line.is_empty() { "nothing" } else { &line }
        ));
    }
    Ok(line.strip_prefix("apkscope ").unwrap_or(&line).to_string())
}

/// Resolve a tool name against PATH the way the shell would (absolute paths pass through).
fn find_tool(name: &str) -> Option<PathBuf> {
    if Path::new(name).is_file() {
        return Some(PathBuf::from(name));
    }
    let exts: &[&str] = if cfg!(windows) {
        &["", ".exe", ".cmd", ".bat"]
    } else {
        &[""]
    };
    let path = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path) {
        for ext in exts {
            let cand = dir.join(format!("{name}{ext}"));
            if cand.is_file() {
                return Some(cand);
            }
        }
    }
    None
}
