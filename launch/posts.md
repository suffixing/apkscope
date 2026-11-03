# Launch posts

Repo: https://github.com/suffixing/apkscope

## Show HN

**Title:** Show HN: apkscope – Android decompiler in Rust, opens TikTok 11x faster than JADX

**First comment:**

I wrote apkscope, an Android reverse-engineering tool in Rust: DEX parser, decompiler, deobfuscator, resource decoder, APK signer, MCP server and a native viewer, all from scratch (not a JADX fork, no JVM).

On my machine (i7-10850H, 32 GB, Windows 11) it opens TikTok (346 MB, 53 DEX, 436k classes) in 12.4 s / 997 MB; JADX-GUI takes 2 min 18 s / 9.4 GB. A full Gradle export takes 11 min 31 s vs JADX's 48 min 58 s.

The part I use most is xrefs with the Java line in one stateless call:

    $ apkscope refs app.apk string X-Goog-Api-Key --java
           65: httpURLConnection.setRequestProperty("X-Goog-Api-Key", str2);
    1 refs in 53 ms

It also runs as an MCP server, so an agent can ask an APK questions. In a warm session the median call is 70 ms vs 191 ms for rust_ASC.

Limits: some complex methods still come out with `goto` labels (marked WARNING), rust_ASC is still a few ms quicker on many cold one-shot queries, and the viewer is only tested on Windows (CLI and MCP pass CI on Linux and macOS). Every number comes from scripts in bench/ that you can re-run.

Bug reports with a class name and what JADX shows are very welcome.

## r/ReverseEngineering

**Title:** apkscope: stateless APK xrefs that return the Java line, plus a from-scratch decompiler (Rust, no JVM)

Finding custom TLS trust in AntennaPod (F-Droid build), real output:

```
$ apkscope refs antennapod.apk impl javax.net.ssl.X509TrustManager
classes.dex | Lde/danoeh/antennapod/net/ssl/CompositeX509TrustManager; | matched=Ljavax/net/ssl/X509TrustManager;
1 refs in 36 ms
```

What it does: string, method, field and type xrefs and implementors from the command line; decompile one class or one method as typed Java; `callers`, `callgraph` and field `access`; Frida hook generation; a manifest and security quick-scan; secret and URL scans (also in native `.so`); JNI exports mapped to Java `native` methods; `diff` between versions; edit, rebuild and sign (v2 + v3).

String decryption runs the app's own decryptor in a small sandboxed Dalvik interpreter (no I/O, no reflection, step-limited) and shows the plaintext inline next to the call.

Limits: callers, call graphs and Frida see direct calls only (not reflection, JNI or dynamic code); decryption only handles decryptors that compute from constants; scans are heuristics; some methods still have `goto` labels.

Numbers and scripts: https://github.com/suffixing/apkscope/blob/main/BENCHMARKS.md
Repo: https://github.com/suffixing/apkscope

## r/rust

**Title:** I wrote an Android decompiler from scratch in Rust. It opens TikTok's 436k classes in 12.4 s (JADX: 2 min 18 s)

apkscope is a DEX parser, bytecode decoder, decompiler, deobfuscator, resource decoder, search index, APK signer, MCP server and egui viewer, all written from zero in Rust.

Results from the bench/ scripts (one machine, Windows 11):

- Open TikTok until fully loaded: 12.4 s / 997 MB vs JADX-GUI 2 min 18 s / 9.4 GB
- Full Gradle export: 11 min 31 s / 857 MB vs 48 min 58 s / 2.0 GB
- Decompile one class: faster than rust_ASC (another Rust tool) on 9 of 14 apps, and the output is typed Java rather than pseudocode

Where it still loses: rust_ASC is a few ms quicker on many cold one-shot queries and 1.8x quicker at listing TikTok's classes. A recent bug was a stack overflow on control-flow-flattened classes, fixed in 0.5.2.

`cargo build --release --no-default-features` gives you the CLI and MCP server only (Linux and macOS CI).

Repo: https://github.com/suffixing/apkscope

## X (under 280)

apkscope opens TikTok (436k classes) in 12.4 s with 997 MB RAM. JADX-GUI: 2 min 18 s, 9.4 GB.

Android decompiler written from scratch in Rust, no JVM, with an MCP server for AI agents.

https://github.com/suffixing/apkscope

## Bluesky (under 280)

Android RE in one Rust binary: apkscope opens TikTok in 12.4 s vs JADX's 2 min 18 s, and returns xrefs with the Java line in one call (53 ms cold). From-scratch decompiler, MCP server included.

https://github.com/suffixing/apkscope

## Mastodon (under 280)

apkscope: a from-scratch Android decompiler in Rust. Opens TikTok in 12.4 s / 997 MB vs JADX-GUI's 2 min 18 s / 9.4 GB. Xrefs with Java lines, Frida hooks, MCP for agents.

https://github.com/suffixing/apkscope

#ReverseEngineering #Android #Rust
