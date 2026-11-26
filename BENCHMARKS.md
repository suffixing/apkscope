# apkscope benchmarks

apkscope is measured with one tool: the `cargo bench` harness in [`benches/`](benches).
Give it git refs, pull requests or ready-made binaries; it builds them, runs the case set
as cold processes on the APKs you point it at, and prints the comparison table — on Linux,
macOS and Windows, with nothing but the Rust toolchain that builds apkscope itself.
[Back to the README](README.md)

**Jump to:** [Run it](#run-it) · [The case set](#the-case-set) · [Compare git refs](#compare-git-refs) · [Compare binaries](#compare-binaries) · [Compare a pull request](#compare-a-pull-request) · [Race other tools](#race-other-tools) · [Output checking](#output-checking) · [Output formats](#output-formats) · [How the numbers are made](#how-the-numbers-are-made) · [The harness layout](#the-harness-layout) · [Reference run: Telegram](#reference-run-telegram) · [History](#history)

## Run it

```
cargo bench --no-default-features -- --compare main --compare HEAD --apk Telegram.apk
```

The `--` matters: the flags after it belong to the harness, not to cargo. Plain
`cargo bench` measures the working tree alone — `HEAD`, uncommitted changes included.

One Markdown table per APK: a column per build, a row per case, every cell
`wall time, peak RSS` — the median of `--runs` (default 3) cold runs. `--apk` is
repeatable; without it the harness looks in `bench/apps/` (a convention — APKs are not
committed, so it is usually passed explicitly). `--case` (repeatable) and `--runs` trim
the run.

## The case set

| Row | What runs |
|---|---|
| `apkscope info` | the manifest overview of the APK |
| `apkscope classes` | every class in every DEX |
| `apkscope strings` | the whole string pool |
| `apkscope decompile` (one class) | one class as Java — the first class of `classes` output, the same class for every column |
| `apkscope smali` (one class) | the same class as Smali |
| `apkscope build` | rebuild and re-sign the whole APK |
| the whole APK | `apkscope decompile <apk>` — every class, one process |
| `apkscope fingerprint --all --strings` | known SDKs and trackers, both catalogs plus the DEX string-pool scan — opt-in: `--case fingerprint` |

The fingerprint row is opt-in because its command lands with
[#51](https://github.com/suffixing/apkscope/pull/51): a default run against the `--pr`
base (`origin/main`) has no such command and the row would fail. Name it with
`--case fingerprint` on refs that have it — e.g. racing that PR's before and after:

```
cargo bench --no-default-features -- \
  --compare <pr-51-before> --compare <pr-51-after> --case fingerprint --hash --apk Telegram.apk
```

Every run is a fresh process with `-q --no-cache`: no warm cache, no daemon, nothing
carried between runs. `--tool` columns only fill the whole-APK row.

## Compare git refs

`--compare <ref>` (repeatable, the first is the baseline) builds apkscope at each ref
and gives it a column. `HEAD` (or `.`) compiles the working tree in place; every other
ref is checked out into a worktree under `target/bench/wt/` — nothing touches your
checkout — and cached by commit sha, so two refs at one commit build once and a re-run
of the same ref is a cache hit. Each ref builds `--release --no-default-features` into
its own `CARGO_TARGET_DIR` under `target/bench/`.

## Compare binaries

`--bin <path>` (repeatable) measures ready-made apkscope binaries exactly as given — no
build. Race two local builds, or the installed release against a PR preview from
[`scripts/preview-pr.sh`](scripts/preview-pr.sh):

```
./scripts/preview-pr.sh 79
cargo bench --no-default-features \
  -- --bin "$(command -v apkscope)" --bin ~/.local/bin/apkscope-pr-79 --apk Telegram.apk
```

Every `--bin` is probed with `--version` before the first case runs, so a path that is
not an apkscope binary fails in seconds instead of after a failed row; the version it
prints lands in the table's footer next to the built refs' commit shas. With only
`--bin` columns given, the working tree is not built at all.

## Compare a pull request

`--pr <N>` (repeatable) fetches GitHub's merge ref for PR N — the same merge CI builds —
into `refs/bench/pr-N` and benches it as a `pr-N` column:

```
cargo bench --no-default-features -- --pr 79 --apk Telegram.apk
```

Without `--compare`, the base column comes first: `--base <ref>`, default `origin/main`,
refreshed by the same fetch — the tip GitHub merges the PR into, not a possibly stale
local `main`. A PR with conflicts (or a closed PR) has no merge ref; the harness falls
back to the unmerged head and says so on stderr.

`--pr` talks to `origin`, so it needs the network — everything else in the harness is
local. Pull refs live on the repository the PR targets: a clone of `suffixing/apkscope`
can bench every PR; from a fork clone, fetch upstream first or use `--bin` with a
preview from `scripts/preview-pr.sh`.

## Race other tools

`--tool <name>` (repeatable) adds an external tool as a column, found on PATH or given
as an absolute path. It runs `<tool> <apk>` in a scratch directory and fills the
whole-APK row; the apkscope-only rows show `—`.

## Output checking

`--hash` digests every run's output with SHA-256 and turns the bench into an
output-equivalence check across the apkscope columns — built refs, PRs and `--bin`
binaries alike:

- stdout for every case except `build`; for `build`, the rebuilt APK's entry list and
  CRCs, so re-signing or fresh zip timestamps cannot make two identical rebuilds look
  different
- one hash table per APK next to the timing table; every case whose digest differs
  between columns is reported on stdout *and* stderr, and the bench **exits 3**

A perf PR that also changed output says so right next to its numbers, and CI can gate
on the exit code.

## Output formats

`--format markdown` (default) prints the PR-shaped table. `--format json` dumps the same
measurements machine-readably — per column: name, exe, commit sha (built refs) or
`--version` line (`--bin`); per cell: median seconds, peak RSS bytes, digest, error.
`--format svg` writes one bar chart per APK and metric to
`docs/bench-<apk>-{time,ram}.svg`.

Exit codes: 0 = every run succeeded · 1 = a run failed · 2 = setup error · 3 = `--hash`
found differing outputs (cargo reports non-zero as a failed bench — that is the point).

Worktrees, builds, fetched refs' scratch and binaries land under `target/bench/`
(`cargo clean` removes them; `git worktree prune` clears the stale metadata a clean
leaves behind).

## How the numbers are made

- **Cold runs.** Every run is a fresh process with `-q --no-cache`; the table shows the
  median of `--runs` (default 3) — never a single sample, never a warm cache.
- **Peak RSS from the OS.** `wait4(2)`'s `ru_maxrss` on Linux and macOS,
  `GetProcessMemoryInfo` on Windows — read once when the child exits, no polling, no
  race with short-lived processes.
- **The same class everywhere.** The one-class rows decompile the class picked once from
  the first column's `classes` output, so outputs — and `--hash` digests — compare.
- **The binary that ships.** Built refs compile `--release --no-default-features`: the
  CLI + MCP server the cases exercise. The viewer is not benched.
- **Units follow the value.** Times below a second print in milliseconds, above it in
  seconds, past a minute in minutes — each cell in the unit its value calls for.

## The harness layout

The harness is modular: `benches/bench/main.rs` is the pipeline — parse the flags,
resolve the APKs, build the columns, measure, report — and every stage owns a file
next to it:

| File | Owns | Extend it to |
|---|---|---|
| `benches/bench/main.rs` | the pipeline, the exit codes | change the flow |
| `benches/bench/cli.rs` | the flags | add an option |
| `benches/bench/case.rs` | the case set | add a row: one `CaseDef` — id, label, argv |
| `benches/bench/column.rs` | the columns | add a source of binaries |
| `benches/bench/exec.rs` | one timed subprocess | support another OS |
| `benches/bench/measure.rs` | cases × columns × runs | change what a cell records |
| `benches/bench/digest.rs` | `--hash` | change what "same output" means |
| `benches/bench/report/` | markdown, json, svg | add an output format |
| `benches/bench/util.rs` | git, slugs, tails | shared plumbing |

Adding a case or an output format touches one file (plus an enum variant and a match
arm); the run loop, the digests and the other formats pick it up on their own.

## Reference run: Telegram

Measured with the harness itself on Telegram's direct download
(`https://telegram.org/dl/android/apk`, 81.7 MB, 4 DEX files, 22,204 classes), 2026-11-24:

- machine: an Intel Xeon cloud VM (2 cores, 4 GB RAM), Linux 5.10
- command: `cargo bench --no-default-features -- --compare origin/main --compare HEAD --hash --runs 5 --apk Telegram.apk`
- columns: `origin/main` at `a401b62` · `HEAD` — this PR's tree, the one-file-per-stage
  harness included

### Telegram.apk

|  | origin/main | HEAD |
| --- | --- | --- |
| `apkscope info` | 211 ms, 88 MB | 210 ms, 86 MB |
| `apkscope classes` | 34.1 ms, 58 MB | 33.0 ms, 58 MB |
| `apkscope strings` | 43.5 ms, 77 MB | 59.6 ms, 75 MB |
| `apkscope decompile` (one class) | 54.9 ms, 65 MB | 54.8 ms, 65 MB |
| `apkscope smali` (one class) | 105 ms, 52 MB | 106 ms, 52 MB |
| `apkscope build` | 856 ms, 113 MB | 871 ms, 113 MB |
| the whole APK | 12.9 s, 138 MB | 12.8 s, 138 MB |

Columns: `origin/main` = apkscope `a401b62` · `HEAD` = this PR's tree. Median of
5 cold runs; every digest under `--hash` was identical across the two columns (exit 0);
a pass of the same command with `--format svg` wrote the two charts below.

<p>
  <img src="docs/bench-telegram-time.svg" alt="Telegram wall-time bar chart: every case level between origin/main and HEAD, from 33 ms (classes) to 12.9 s (whole APK)" width="760">
  <img src="docs/bench-telegram-ram.svg" alt="Telegram peak-RSS bar chart: every case level between origin/main and HEAD, from 53 MB (smali) to 138 MB (whole APK)" width="760">
</p>

The columns are level — this PR adds a bench target and docs, no apkscope code, and
every `--hash` digest is identical, which is exactly what the table should show. One
row carries its own caveat: on this shared VM, `strings` is position-sensitive —
whichever column is measured first lands near 45 ms and the second near 60 ms, and
re-running with the columns swapped turns the row around (46.5 ms / 60.6 ms). Read
that row as "~45-60 ms, either mode", not as a regression.

## History

Until this page was rewritten, it carried the cross-tool races (JADX, rust_ASC) and the
10- and 14-app cold-query tables measured by the PowerShell/Python scripts under
`bench/` — Windows-first, and a JDK for some cases. [#64](https://github.com/suffixing/apkscope/issues/64)
replaced them with the harness and retired the scripts; their tables and scripts live on
in git history, along with that era's `docs/bench-*.svg` charts (TikTok) — kept as they
were measured, and superseded in the README by the harness's Telegram charts.

[Back to the README](README.md)
