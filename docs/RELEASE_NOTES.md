# apkscope v0.6.0

**Decompiles a class up to 1.8x faster than rust_ASC, as typed Java, with less memory.**
Measured on 10 popular apps (TikTok, Facebook, YouTube, WhatsApp, Telegram, Snapchat, Netflix,
Firefox, Signal, Duolingo) with the retired `bench/asc.ps1` script (kept in git history);
full results in [BENCHMARKS.md](../BENCHMARKS.md) at v0.6.0.

## Faster

- **One-class decompile:** faster than rust_ASC on 8 of 10 apps, level on 2 (it lost on 2 before).
  Import paths and nested classes are now worked out only for what the file prints, not for every
  class in the DEX (25-35 ms saved on big apps).
- **Smarter inflating:** each DEX's layout decides whether to inflate a prefix or the whole file at
  once. d8 / R8 builds keep strings at the end, where a prefix and then a full pass cost up to 1.9x
  one pass. YouTube one-class decompile went from 0.8x to 1.8x rust_ASC's speed.
- **Streaming output:** `methods` and `classes` write each DEX file's lines as soon as it is done.
- **Quicker start:** the viewer's libraries load only when the viewer opens (`--help` 75 ms -> 12 ms).
- Big APKs (40k+ zip entries): only the entries a query needs are read from the directory.
- Deobfuscation setup and method listing allocate less.

## Fixed

- Decompiling some Netflix classes crashed with a stack overflow (a lambda that refers to itself).
- `refs --limit N` could return a different N hits from run to run; it now always returns the first
  N in runtime order, also over MCP.
- Manifests with blanked attribute names (Netflix) lost their `android:` names.
- Apps with two resource packages (Netflix, TikTok) showed raw `@0x7f...` ids instead of names.
- `verify` reported DSA-signed APKs as failed and errored on v1-only APKs; it now says what was and
  wasn't checked.
- Removing the last rename or comment left an empty `<apk>.apkscope.json` behind.

## Agents (MCP)

- A warm session unused for 10 minutes exits and frees its memory; the next call restarts it.

## Benchmarks

- New main set of 10 popular apps; the earlier 14 still run with `-Legacy`.
- The script now alternates the two tools run by run and reads peak memory from the OS, and no
  longer leaves garbage from one run's output to slow the next.

## Install

Windows: download `apkscope.exe` below. From source:

```bash
cargo build --release                          # viewer + CLI + MCP server
cargo build --release --no-default-features    # CLI + MCP only (Linux, macOS, servers)
```

## Known limits

- rust_ASC is still quicker at string xrefs (0.78-0.97x) and a little quicker on most ~50 ms
  listings; those are bound by inflating many DEX files on all cores at once.
- Smali editing (change code, rebuild) is not in this release; `build` edits resources, files and
  the manifest, and signs.
- The viewer is tested on Windows. The CLI and MCP server pass CI on Linux and macOS.
