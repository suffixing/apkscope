# apkscope status

Last updated 2026-10-28. Latest engine commit: `0c9315e`.

## Done

**Engine** (`src/dex.rs`, `bytecode.rs`, `cfg.rs`, `ir.rs`, `opt.rs`, `java.rs`)
- Own DEX parser + all Dalvik instructions; no JADX code.
- Structured Java: if/else, while, switch, try/catch/finally, synchronized (both javac and d8 forms),
  inlined expressions, typed/named variables, `&&`/`||`, constant propagation, string `+`, lambdas,
  inline anonymous classes, real enums (names recovered from their strings), imports, annotations,
  `throws`, static field constants, annotation defaults, array literals.
- Gotos cut 39% (Zestle) / 61% (Unciv). Methods whose Java may not match the bytecode get a
  `/* WARNING */` header; methods that fail fall back to Smali in a comment.
- Deobfuscation on by default (`--no-deobf` to disable), with `/* renamed from */` notes (`src/deobf.rs`).

**Export / resources** (`src/export.rs`, `src/res.rs`, `src/imports.rs`)
- `apkscope export app.apk out/` writes a Gradle project: sources (all cores), manifest, decoded `res/`,
  assets, native libs.
- Android framework resource names bundled from AOSP (`src/data/android_public.txt`, Apache 2.0).

**UI**: web UI (`apkscope gui app.apk`, `src/gui.rs` + `src/ui/index.html`): tree, search, resources.
To be replaced (see Priority 2).

**Measured (Zestle, see README)**: full export 14.0 s / 27 MB vs JADX 24.9 s / 2,036 MB.
55.0% of exported files compile with javac (no errors in the file itself).

**Tooling**
- 23 unit tests (`cargo test`)
- `bench/measure.ps1`: time + peak memory
- `bench/regress.py`: quality counters vs `bench/baseline.json`
- `bench/compilecheck.py`: javac compile rate (needs `D:\AndroidSDK\platforms\android-37.0\android.jar`)

## Left

**Priority 1: engine (in progress)**
- Done: `class Object` errors (cause: nested class named like its supertype, `class Factory implements
  Factory`, made javac see a cycle; `src/imports.rs` now qualifies names shadowed by declared classes).
- Done: `variable vN` errors (long/double call arguments passed both registers; `src/ir.rs` keeps one).
- `getClass()` (~1,055) errors are not a separate bug: the class's superclass sits in a file with gotos,
  which the compile check leaves out (e.g. `DefaultItemAnimator` -> `RecyclerView`). Gotos fix them.
- Next: gotos.
- 718 Zestle files still contain `goto` (4,395 gotos; was 9,490).
- Done: `new T` before an `if` with `<init>` in each arm. 21 `x.<init>()` left (19 files): the object reaches
  `<init>` through a variable assigned in several places (branches merging before one constructor call).
- Enums: 467 -> 53 `enum classes may not be instantiated`. Left: constants with a body (anonymous
  subclass, e.g. gson `FieldNamingPolicy`) and `WireFormat$FieldType` (cause not found yet).
- 452 unmatched `monitorEnter` locks (d8's split unlock handler is now matched).

**Priority 2: native UI (Rust + egui/eframe .exe)**
- Remove the web UI completely.
- Dark/light + multiple themes, syntax highlighting.
- Synchronized Java/Smali views; one click from a WARNING to its Smali.
- Fast unified search (code, strings, resources, manifest), cross-references, callers/callees,
  call graphs.
- Persistent rename mappings, bookmarks, navigation history.

**Priority 3: performance**
- Background tasks with cancellation, incremental indexing, lazy-loaded trees for huge APKs.

**Priority 4: release**
- Signed Windows installer, no Android SDK needed.
- README benchmark on TikTok (`D:\APKS\tiktok-47-2-41.apk`).
- Pick a license.

## Notes
- Test APKs: `D:\APKS\Zestle_v0.6.8-prealpha.apk`, `D:\APKS\Unciv.apk` (small; avoid big ones except
  the final TikTok benchmark). JADX for comparison: `D:\Tools\jadx`.
- Dev builds go to `D:\Rust\apkscope-target-dev` (set `CARGO_TARGET_DIR`), because an old
  `apkscope gui` was locking `target\release`.
- Working rule: after each big task, ask whether to continue, until the signed production build.
- `deobf.rs`, `export.rs`, `README.md` and `src/ui/index.html` were changed outside the session after
  the last commit and have not been reviewed.
