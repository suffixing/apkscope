# apkscope v0.5.3

**Opens TikTok (346 MB, 436k classes) in 12.4 s with 997 MB of RAM. JADX-GUI takes 2 min 18 s and 9.4 GB.**
Measured on one machine with the scripts in [`bench/`](../bench); full results in [BENCHMARKS.md](../BENCHMARKS.md).

## Key features

1. **Typed Java, from a decompiler written from scratch in Rust.** No JVM, not a JADX fork. Uncertain methods get a `/* WARNING */` header; the rare failure falls back to Smali.
2. **Xrefs with the Java line, in one call.** `apkscope refs app.apk string X-Goog-Api-Key --java` returns the method and the line in 53 ms from a cold start.
3. **MCP server for AI agents with a warm session.** Median call 70 ms vs rust_ASC's 191 ms on TikTok; 39 calls in 3.94 s vs 6.54 s. Replies page and are size-capped.
4. **Reverse-engineering tools:** `callers`, `callgraph`, field `access`, ready-to-run `frida` hooks, a security `scan`, sandboxed string `decrypt`, saved renames and comments, JADX/Enigma mapping import and export.
5. **Native viewer:** security overview, grouped search, go to definition, exact call-site navigation, back/forward, Build & sign (v2 + v3) with undo. 0.5.2 fixed a stack overflow on control-flow-flattened classes and added keyboard and screen reader support.

## Install

Windows: download `apkscope.exe` from [Releases](https://github.com/suffixing/apkscope/releases).

From source:

```bash
cargo build --release                          # viewer + CLI + MCP server
cargo build --release --no-default-features    # CLI + MCP only (Linux, macOS, servers)
```

Add it to an agent:

```bash
claude mcp add apkscope -- /path/to/apkscope mcp
```

## Known limits

- The viewer is tested on Windows. The CLI and MCP server pass CI on Linux and macOS.
- On a cold one-shot query rust_ASC is still a few ms quicker on many apps, and 1.8x quicker at listing TikTok's 436k classes.
- Some complex methods still use `goto` labels (marked with a `WARNING`).
- Opening huge apps takes about 1 GB (TikTok); the first full-code search takes a minute.
- Secret and URL scans are heuristics. String decryption only runs decryptors that compute from constants.
- Callers, call graphs and Frida hooks see direct calls only, not reflection, JNI or dynamic code.
