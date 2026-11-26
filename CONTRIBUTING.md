# Contributing to apkscope

Thanks for helping. apkscope is a from-scratch Rust tool for Android reverse engineering:
CLI, MCP server and viewer over one engine. These rules keep it fast and trustworthy.

## Before you start

- For anything bigger than a bug fix, open an issue first and say what you plan to build.
  It saves you rebuilding a PR that goes a different way.
- One feature or one refactor per PR. Rebase on current `main` before asking for review.

## What every PR needs

1. **All three surfaces.** A new feature gets a CLI command or flag, an MCP tool (listed in
   `tools()` and handled in `call()` in `src/mcp.rs`), and a menu item or panel in the viewer.
   A test fails if an MCP tool has no handler.
2. **Speed numbers.** Time the affected commands on a large real APK (Telegram, TikTok or similar)
   against `main` and paste the numbers — the harness does it in one command:
   `cargo bench --no-default-features -- --pr <your-PR> --apk <apk>` (before pushing:
   `--compare main --compare HEAD`). A slowdown in a command people run every time
   (`info`, `scan`, `search`) blocks the merge. Make things faster with better algorithms,
   not with caches or extra memory.
3. **Quality on a real app.** Heuristics (secrets, URLs, config, SDK detection) must be checked on
   a real app, not only on a fixture. Report what the false positives look like.
4. **Tests.** Add them under `tests/` using the `#[path]` layout in [tests/README.md](tests/README.md).
5. **Green CI.** Locally:

   ```
   cargo fmt --all -- --check
   cargo clippy --release --no-default-features -- -D warnings
   cargo clippy --release -- -D warnings
   cargo clippy --release --no-default-features --tests -- -D warnings
   cargo test --release --no-default-features
   ```

6. **Let reviewers run it.** CI publishes every PR's build as workflow artifacts. Point
   reviewers and field testers at them: `./scripts/preview-pr.sh <PR>` (Linux/macOS) or
   `./scripts/preview-pr.ps1 -Pr <PR>` (Windows) installs the PR's build side by side as
   `apkscope-pr-<N>` — no Rust toolchain, no checkout, and the real install stays untouched.
   Prefer a preview over "tested locally" claims in the PR description: it is the same binary
   CI built, digest-checked.

## Ground rules

- **Offline only.** apkscope makes no network calls during analysis. The only exception is `upgrade`.
- **No new dependencies** without asking in the issue first.
- **Data with its own license** (tracker lists, signatures) needs maintainer approval and credit in the README.
- **Honest claims.** Numbers in the README must be measured; known gaps go in "Honest limits".
- **No JADX, apktool or smali.** The decompiler and tooling are our own.

## Reporting wrong decompiler output

Open an issue with the APK (or where to get it), the class name, what apkscope prints and what
JADX prints.

## License

By contributing you agree your work is licensed under [Apache 2.0](LICENSE), like the rest of the
project. "apkscope" and its logo are trademarks; see [NOTICE](NOTICE).
