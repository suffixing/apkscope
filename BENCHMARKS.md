# apkscope benchmarks

Every number on this page was measured on one machine (i7-10850H, 6 cores / 12 threads, 32 GB,
Windows 11). The scripts are in [`bench/`](bench), so you can re-run them. [Back to the README](README.md)

**Jump to:** [Features](#features-apkscope-vs-rust_asc-vs-jadx) · [TikTok, all three tools](#tiktok-all-three-tools) · [Agent sessions](#agent-sessions-mcp) · [Cold queries, 14 apps](#cold-queries-14-apps) · [How it's measured](#how-its-measured)

## Features: apkscope vs rust_ASC vs JADX

| | JADX 1.5 | rust_ASC | **apkscope** |
|---|:---:|:---:|:---:|
| Runs without a JVM | no | yes | **yes** |
| Typed, structured Java output | yes | no (pseudocode) | **yes** |
| Smali view | yes | no | **yes** |
| Deobfuscation | yes | no | **yes** |
| GUI | yes (Java Swing) | no | **yes** (native) |
| Gradle export | yes | no (one pseudocode file per class) | **yes**, with resources, assets, libs |
| Decoded resources | yes | manifest only | **yes**, all of `res/` |
| Stateless xrefs from the command line | no | yes | **yes** |
| Xref hits with their Java lines, in one call | no | no | **yes** (`--java`) |
| Built-in MCP server for AI agents | no | yes | **yes** |
| Warm session across agent calls | n/a | no (new process per call) | **yes** |
| Subclasses / implementors as a query | no | CLI only | **CLI and MCP** |
| URL / HTTP-call / secret scans, also in native `.so` | no | no | **yes** |
| Manifest security overview | no | no | **yes** |
| JNI exports mapped to Java `native` methods | no | no | **yes** |
| Edit, rebuild, zipalign, sign (v2 + v3), verify | no | no | **yes** |
| JSON output with paging and size caps for agents | JSON export only | no | **yes** |

## TikTok, all three tools

TikTok 47.2.41: a 346 MB APK with 53 DEX files and 436k classes. JADX takes minutes per run, so
it's measured on TikTok only.

| Task | JADX 1.5.6 | rust_ASC | **apkscope** |
|---|---:|---:|---:|
| Open in a GUI until fully loaded | 2 min 18 s / 9.4 GB | no GUI | **12.4 s / 997 MB** |
| Full project export | 48 min 58 s / 2.0 GB | not comparable | **11 min 31 s / 857 MB** |
| One string xref, cold process | no CLI | 213 ms | 227 ms |
| Decompile one class, cold process | no CLI | 86 ms (pseudocode) | 101 ms (Java) |
| List all 436k classes, cold process | no CLI | **89 ms** | 157 ms |
| 39 agent calls through MCP | no MCP | 6.54 s | **3.94 s** |

JADX-GUI ran with its official launcher (Java may use up to 70% of RAM); with `-Xmx24g` it took
2 min 01 s and about 10 GB. JADX's export ran with `-e -Xmx24g` and exited with code 3 (some classes
failed), but still wrote its project. Scripts: `open.ps1`, `tiktok.ps1`, `asc.ps1`, `mcp.py`.

## Agent sessions (MCP)

An agent doesn't run one query, it runs dozens against the same app. This is 8 string xrefs and
5 class decompiles on TikTok, run three times in one MCP session ([`bench/mcp.py`](bench/mcp.py)):

| Server | Round 1 | Round 2 | Round 3 | Total | Failed |
|---|---:|---:|---:|---:|---:|
| rust_ASC `mcp` | 2.29 s (median 199 ms) | 2.13 s (median 192 ms) | 2.12 s (median 191 ms) | 6.54 s | 0 |
| apkscope `mcp`, stateless | 2.49 s (median 220 ms) | 2.48 s (median 222 ms) | 2.55 s (median 232 ms) | 7.51 s | 0 |
| **apkscope `mcp`, warm session (default)** | **1.55 s** (median 72 ms) | **1.25 s** (median 70 ms) | **1.15 s** (median 69 ms) | **3.94 s** | 0 |

With the warm session (the default) the median call takes **70 ms against 191 ms**: 2.7x faster
per call, 1.7x faster in total, with Java instead of pseudocode.

## Cold queries, 14 apps

One query per process: start, read the APK, answer, exit. Median of 7 runs, wall time and peak
memory of the whole process ([`bench/asc.ps1`](bench/asc.ps1)). The F-Droid APKs are the official
builds from `https://f-droid.org/repo/`; their file names and the classes used are in the script.

**Summary of the 98 rows**, counting a row as a win at 10% or more either way. The manifest rows
were re-measured for apkscope after its manifest speedup, the same day on the same machine:

| Query | apkscope faster | level | rust_ASC faster |
|---|---:|---:|---:|
| Decompile one class | **9** | 2 | 3 |
| Method xref | 4 | 5 | 5 |
| List classes | 3 | 5 | 6 |
| List methods | 1 | 8 | 5 |
| List strings | 1 | 9 | 4 |
| String xref | 1 | 6 | 7 |
| Decode manifest | **12** | 1 | 1 |

- **apkscope uses less memory in most rows**, often half (Nextcloud decompile: 75 MB vs 194 MB).
- **apkscope decompiles one class faster on 9 of 14 apps**, and its output is typed Java.
- **rust_ASC is quicker on most other cold queries**, usually by 5–15 ms on small apps, where both
  tools spend most of their time starting a Windows process (~30 ms). On TikTok it still lists
  classes 1.8x faster.
- **apkscope decodes the manifest faster on 12 of 14 apps**, up to 6x (TikTok: 33 ms vs 207 ms). It
  reads only the resource names the manifest needs and one zip entry, not the whole archive index.

Correctness, checked against rust_ASC on TikTok: the same 436,708 classes, 2,016,476 methods and
2,138,305 pool strings, and the same string xrefs except one, where rust_ASC reports a method whose
bytecode has no such string. For method names apkscope matches the whole name (`openConnection`),
while rust_ASC matches substrings; use `--regex` for substrings.

### Zestle


| Query | rust_ASC | apkscope | Speed-up |
|---|---:|---:|---:|
| String xref `https://` | 40 ms / 20 MB | 46 ms / 19 MB | 0.9x |
| Method xref `openConnection` | 38 ms / 20 MB | 46 ms / 18 MB | 0.8x |
| Decompile one class | 78 ms / 43 MB | 81 ms / 26 MB | 1.0x |
| List classes | 40 ms / 19 MB | 41 ms / 20 MB | 1.0x |
| List methods | 61 ms / 30 MB | 64 ms / 31 MB | 1.0x |
| List strings `-f http` | 31 ms / 13 MB | 30 ms / 14 MB | 1.0x |
| Decode manifest | 30 ms / 17 MB | 15 ms / 4 MB | 2.0x |

### Unciv


| Query | rust_ASC | apkscope | Speed-up |
|---|---:|---:|---:|
| String xref `https://` | 47 ms / 43 MB | 54 ms / 39 MB | 0.9x |
| Method xref `openConnection` | 47 ms / 42 MB | 48 ms / 36 MB | 1.0x |
| Decompile one class | 107 ms / 71 MB | 87 ms / 42 MB | 1.2x |
| List classes | 48 ms / 42 MB | 50 ms / 39 MB | 1.0x |
| List methods | 126 ms / 74 MB | 122 ms / 75 MB | 1.0x |
| List strings `-f http` | 44 ms / 37 MB | 44 ms / 37 MB | 1.0x |
| Decode manifest | 31 ms / 33 MB | 15 ms / 4 MB | 2.1x |

### Capital


| Query | rust_ASC | apkscope | Speed-up |
|---|---:|---:|---:|
| String xref `https://` | 44 ms / 57 MB | 46 ms / 31 MB | 1.0x |
| Method xref `openConnection` | 38 ms / 51 MB | 42 ms / 29 MB | 0.9x |
| Decompile one class | 43 ms / 58 MB | 46 ms / 32 MB | 0.9x |
| List classes | 35 ms / 49 MB | 29 ms / 30 MB | 1.2x |
| List methods | 76 ms / 73 MB | 76 ms / 49 MB | 1.0x |
| List strings `-f http` | 29 ms / 48 MB | 29 ms / 29 MB | 1.0x |
| Decode manifest | 43 ms / 57 MB | 28 ms / 11 MB | 1.5x |

### TikTok

<sub>47.2.41, 53 DEX, 436k classes</sub>

| Query | rust_ASC | apkscope | Speed-up |
|---|---:|---:|---:|
| String xref `https://` | 213 ms / 341 MB | 227 ms / 307 MB | 0.9x |
| Method xref `openConnection` | 156 ms / 278 MB | 135 ms / 193 MB | 1.2x |
| Decompile one class | 86 ms / 99 MB | 101 ms / 154 MB | 0.9x |
| List classes | 89 ms / 96 MB | 157 ms / 185 MB | 0.6x |
| List methods | 918 ms / 501 MB | 1,093 ms / 450 MB | 0.8x |
| List strings `-f http` | 180 ms / 323 MB | 122 ms / 178 MB | 1.5x |
| Decode manifest | 207 ms / 339 MB | 33 ms / 41 MB | 6.3x |

### KeePassDX

| Query | rust_ASC | apkscope | Speed-up |
|---|---:|---:|---:|
| String xref `https://` | 46 ms / 40 MB | 48 ms / 37 MB | 1.0x |
| Method xref `openConnection` | 43 ms / 38 MB | 49 ms / 35 MB | 0.9x |
| Decompile one class | 94 ms / 65 MB | 66 ms / 40 MB | 1.4x |
| List classes | 37 ms / 37 MB | 49 ms / 38 MB | 0.8x |
| List methods | 138 ms / 74 MB | 105 ms / 69 MB | 1.3x |
| List strings `-f http` | 35 ms / 34 MB | 43 ms / 35 MB | 0.8x |
| Decode manifest | 31 ms / 23 MB | 16 ms / 12 MB | 1.9x |

### Nextcloud

| Query | rust_ASC | apkscope | Speed-up |
|---|---:|---:|---:|
| String xref `https://` | 57 ms / 152 MB | 54 ms / 79 MB | 1.1x |
| Method xref `openConnection` | 52 ms / 146 MB | 48 ms / 71 MB | 1.1x |
| Decompile one class | 79 ms / 194 MB | 76 ms / 75 MB | 1.0x |
| List classes | 53 ms / 140 MB | 62 ms / 82 MB | 0.9x |
| List methods | 271 ms / 216 MB | 323 ms / 155 MB | 0.8x |
| List strings `-f http` | 54 ms / 133 MB | 52 ms / 72 MB | 1.0x |
| Decode manifest | 65 ms / 99 MB | 31 ms / 17 MB | 2.1x |

### AntennaPod

| Query | rust_ASC | apkscope | Speed-up |
|---|---:|---:|---:|
| String xref `https://` | 31 ms / 22 MB | 46 ms / 27 MB | 0.7x |
| Method xref `openConnection` | 37 ms / 27 MB | 46 ms / 25 MB | 0.8x |
| Decompile one class | 86 ms / 50 MB | 78 ms / 29 MB | 1.1x |
| List classes | 41 ms / 26 MB | 41 ms / 28 MB | 1.0x |
| List methods | 78 ms / 41 MB | 76 ms / 40 MB | 1.0x |
| List strings `-f http` | 31 ms / 19 MB | 31 ms / 25 MB | 1.0x |
| Decode manifest | 32 ms / 24 MB | 16 ms / 4 MB | 2.0x |

### Element

| Query | rust_ASC | apkscope | Speed-up |
|---|---:|---:|---:|
| String xref `https://` | 57 ms / 116 MB | 60 ms / 103 MB | 1.0x |
| Method xref `openConnection` | 57 ms / 109 MB | 58 ms / 95 MB | 1.0x |
| Decompile one class | 111 ms / 162 MB | 91 ms / 98 MB | 1.2x |
| List classes | 61 ms / 105 MB | 77 ms / 107 MB | 0.8x |
| List methods | 490 ms / 215 MB | 495 ms / 213 MB | 1.0x |
| List strings `-f http` | 47 ms / 94 MB | 57 ms / 95 MB | 0.8x |
| Decode manifest | 56 ms / 77 MB | 30 ms / 21 MB | 1.9x |

### OsmAnd

| Query | rust_ASC | apkscope | Speed-up |
|---|---:|---:|---:|
| String xref `https://` | 48 ms / 72 MB | 55 ms / 69 MB | 0.9x |
| Method xref `openConnection` | 51 ms / 71 MB | 47 ms / 63 MB | 1.1x |
| Decompile one class | 103 ms / 101 MB | 81 ms / 64 MB | 1.3x |
| List classes | 56 ms / 64 MB | 61 ms / 64 MB | 0.9x |
| List methods | 193 ms / 128 MB | 202 ms / 114 MB | 1.0x |
| List strings `-f http` | 47 ms / 59 MB | 60 ms / 63 MB | 0.8x |
| Decode manifest | 87 ms / 162 MB | 46 ms / 49 MB | 1.9x |

### Thunderbird

| Query | rust_ASC | apkscope | Speed-up |
|---|---:|---:|---:|
| String xref `https://` | 48 ms / 26 MB | 48 ms / 25 MB | 1.0x |
| Method xref `openConnection` | 51 ms / 26 MB | 47 ms / 23 MB | 1.1x |
| Decompile one class | 106 ms / 58 MB | 98 ms / 34 MB | 1.1x |
| List classes | 42 ms / 25 MB | 41 ms / 25 MB | 1.0x |
| List methods | 73 ms / 38 MB | 80 ms / 38 MB | 0.9x |
| List strings `-f http` | 48 ms / 23 MB | 48 ms / 23 MB | 1.0x |
| Decode manifest | 17 ms / 17 MB | 29 ms / 14 MB | 0.6x |

### Fennec

| Query | rust_ASC | apkscope | Speed-up |
|---|---:|---:|---:|
| String xref `https://` | 48 ms / 57 MB | 62 ms / 51 MB | 0.8x |
| Method xref `openConnection` | 53 ms / 57 MB | 54 ms / 49 MB | 1.0x |
| Decompile one class | 101 ms / 83 MB | 110 ms / 55 MB | 0.9x |
| List classes | 65 ms / 59 MB | 58 ms / 56 MB | 1.1x |
| List methods | 138 ms / 90 MB | 172 ms / 91 MB | 0.8x |
| List strings `-f http` | 49 ms / 47 MB | 49 ms / 48 MB | 1.0x |
| Decode manifest | 73 ms / 131 MB | 29 ms / 26 MB | 2.5x |

### NewPipe

| Query | rust_ASC | apkscope | Speed-up |
|---|---:|---:|---:|
| String xref `https://` | 48 ms / 26 MB | 48 ms / 25 MB | 1.0x |
| Method xref `openConnection` | 49 ms / 26 MB | 49 ms / 23 MB | 1.0x |
| Decompile one class | 98 ms / 53 MB | 79 ms / 30 MB | 1.2x |
| List classes | 42 ms / 23 MB | 42 ms / 23 MB | 1.0x |
| List methods | 78 ms / 40 MB | 78 ms / 37 MB | 1.0x |
| List strings `-f http` | 46 ms / 22 MB | 48 ms / 23 MB | 1.0x |
| Decode manifest | 31 ms / 18 MB | 29 ms / 14 MB | 1.1x |

### VLC

| Query | rust_ASC | apkscope | Speed-up |
|---|---:|---:|---:|
| String xref `https://` | 49 ms / 72 MB | 49 ms / 65 MB | 1.0x |
| Method xref `openConnection` | 46 ms / 68 MB | 47 ms / 61 MB | 1.0x |
| Decompile one class | 83 ms / 99 MB | 65 ms / 63 MB | 1.3x |
| List classes | 58 ms / 68 MB | 52 ms / 67 MB | 1.1x |
| List methods | 133 ms / 113 MB | 188 ms / 117 MB | 0.7x |
| List strings `-f http` | 43 ms / 60 MB | 57 ms / 62 MB | 0.8x |
| Decode manifest | 42 ms / 56 MB | 30 ms / 17 MB | 1.4x |

### Wikipedia

| Query | rust_ASC | apkscope | Speed-up |
|---|---:|---:|---:|
| String xref `https://` | 47 ms / 29 MB | 58 ms / 29 MB | 0.8x |
| Method xref `openConnection` | 49 ms / 29 MB | 64 ms / 27 MB | 0.8x |
| Decompile one class | 118 ms / 62 MB | 95 ms / 35 MB | 1.2x |
| List classes | 41 ms / 26 MB | 48 ms / 28 MB | 0.9x |
| List methods | 85 ms / 41 MB | 83 ms / 43 MB | 1.0x |
| List strings `-f http` | 48 ms / 25 MB | 48 ms / 26 MB | 1.0x |
| Decode manifest | 70 ms / 105 MB | 30 ms / 25 MB | 2.3x |
## How it's measured

- `bench/asc.ps1 <rust_ASC.exe> <apkscope.exe> 7`: the same query through both tools, each run
  in a fresh process; median wall time of 7 runs, peak working set across them.
- `python bench/mcp.py <rust_ASC.exe> <apkscope.exe> <apk>`: one MCP session per server, the same
  13 calls three times.
- rust_ASC was built from source with its own release profile (`lto = "fat"`, `codegen-units = 1`).
  apkscope was built with `cargo build --release --no-default-features`.
- Small-app numbers move by about ±10 ms between runs, so a 0.9x or 1.1x row there is mostly noise.

[Back to the README](README.md)
