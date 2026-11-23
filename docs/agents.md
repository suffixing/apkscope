# Using apkscope from an AI agent

apkscope is one binary for Android reverse engineering: reading, searching, decompiling,
patching, rebuilding and signing an APK. This page is for agents (and people scripting it):
which command answers which question, and how to read the output. Every command here is also
an MCP tool (`apkscope mcp`, see the README) and has examples under `apkscope <command> --help`.

## Calling it

- **`-q`** drops progress and summary lines from stderr. Use it when stderr counts as an error
  (Windows PowerShell 5.1 with `2>&1` marks any stderr line as a failure).
- **Exit codes:** 0 = the command ran, even with no results; 1 = an error, printed as `error: ...`
  on stderr; 2 = bad usage.
- **`--json`** gives JSON where a command lists items (`classes`, `strings`, `consts`, `returns`,
  `size`, ...); `search` has `--format json|csv`.
- **`--limit N` / `--offset N`** page long lists.
- **Class names** work in the shown (deobfuscated) form and the original obfuscated one
  (`a.b.c`). Members: `a.b.C#field`, `a.b.C#method()`.
- **The cache** is keyed by file name, size and modification time, so replacing an APK at the
  same path rebuilds it; `--no-deobf` is not needed for fresh answers.

## Split bundles

`.xapk`, `.apks` and `.apkm` open as their `base.apk`: classes, code, resources and search come
from it. Config splits hold native libraries, densities and languages; `flutter` and `il2cpp` read
native code from the splits too, `size` reads the outer file.

## Which command for which question

| Question | Command |
|---|---|
| What is this app? | `info app.apk` (package, SDKs, permissions, components, native libs with meanings) |
| Quick security pass | `scan app.apk` (`--filter TEXT`, `--limit`/`--offset` to page it) |
| Where does the size go? | `size app.apk` |
| Every class that uses a string | `refs app.apk string "api/v1/login"` (add `--java` for the lines) |
| Who calls a method / reads a field | `refs app.apk method a.b.C#m`, `refs app.apk field a.b.C#f`, `callers`, `access` |
| Who implements an interface | `refs app.apk impl a.b.IProto` (direct), `returns`/`search --impl` (indirect too) |
| Read code | `decompile app.apk a.b.C [--method m]`; many classes: `--classes-file list.txt --out-dir src/` |
| The app's HTTP API | `search app.apk api` (Retrofit endpoints, params, curl lines; works on obfuscated Retrofit) |
| Endpoints, keys, HTTP calls | `search app.apk urls`, `search app.apk secrets`, `search app.apk http` |
| What the server can change | `search app.apk config` |
| Message ids / opcodes per class | `returns app.apk uri --impl a.b.IProtocol` |
| What is the number 405 / 0xB8D0AFDF? | `consts app.apk --value 405` |
| Constants of a class or package | `consts app.apk a.b.Codes`, `consts app.apk a.b.net.*` |
| Search one package only | `search app.apk code "token" --in a.b.net.*` (`--impl T` for subtypes of T) |
| Which layout uses an id | `search app.apk res "@id/login_button"` (file:line) |
| Read a resource | `resource app.apk res/layout/main.xml` |
| What changed between versions / did my patch land | `diff old.apk new.apk --strings` (`--app-only` hides SDK churn) |

## Patching and rebuilding

```
apkscope smali app.apk a.b.C > C.smali          # edit C.smali
apkscope res app.apk decoded/                   # edit decoded/res/..., decoded/AndroidManifest.xml
apkscope build app.apk out.apk --smali C.smali --res decoded/ --ks release.jks --ks-pass env:KS_PASS
apkscope diff app.apk out.apk --strings         # check the change is there
adb install -r out.apk
```

- `build` signs with v2 + v3. Without a key it uses apkscope's own debug key; `--ks` takes a
  JKS or PKCS#12 keystore (`--ks-alias`, `--ks-key-pass`), `--key k.pk8 --cert c.crt` a raw key.
  Passwords: `pass:TEXT`, `env:VAR` or `file:PATH`.
- apkscope does not write a v1 (JAR) signature. For apps whose `minSdkVersion` is below 24,
  `build` warns: Android 5–6 devices refuse the APK.
- `--res` also takes a folder decoded by apktool (`apktool.yml` + `res/`) or APKEditor
  (`resources/package_1/res/`). From those, changed and new files are applied and nothing is
  removed.
- `--put classes7.dex=my.dex` adds or replaces any file; `--delete name` leaves one out.

## Reading the output

- Search hits are `== target:line` followed by the line. The target is a class, a resource path
  or a native library.
- `urls`, `http` and `secrets` show the app's own code first and skip known libraries unless
  `--all` is given; the note at the end says how many library classes were skipped.
- Lines marked `(inferred)` are heuristics (fallback values, models); the rest is read from
  the DEX or the resources as stored.
- `consts` shows only `static final` fields whose value the DEX stores. A constant computed at
  startup (assigned in the static initializer) is left out instead of shown as 0.
