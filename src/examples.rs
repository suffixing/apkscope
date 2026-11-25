//! Examples shown under each command's `--help`, and the recipes under `apkscope --help`.
//! Written for people and for AI agents: each line is a complete command that works as is.

pub const TOP: &str = "\
Recipes (Class = a.b.C, member = a.b.C#field or a.b.C#method()):
  what is this app            apkscope info app.apk;  apkscope scan app.apk;  apkscope size app.apk
  where is this string used   apkscope refs app.apk string \"api/v1/login\"
  who implements X            apkscope refs app.apk impl com.example.Proto
  read a class                apkscope decompile app.apk com.example.Main
  many classes at once        apkscope decompile app.apk --classes-file list.txt --out-dir src/
  the app's HTTP API          apkscope search app.apk api
  message ids / opcodes       apkscope returns app.apk uri --impl com.example.IProtocol
  decode a number             apkscope consts app.apk --value 405
  search one package          apkscope search app.apk code \"token\" --in com.example.net.*
  patch and rebuild           apkscope smali app.apk a.b.C > C.smali; (edit); apkscope build app.apk out.apk --smali C.smali
  whole app as smali          apkscope smali app.apk --out-dir decoded/; (edit); apkscope build app.apk out.apk --smali decoded/
  edit resources / manifest   apkscope res app.apk decoded/; (edit); apkscope build app.apk out.apk --res decoded/
  re-sign / zipalign only     apkscope build app.apk out.apk --ks my.jks --ks-pass pass:secret
  check the signature         apkscope verify out.apk      (v1, v2, v3)
  install on a device         apkscope install out.apk
  check a patch landed        apkscope diff app.apk out.apk --strings

Patching needs no other tool: `smali` writes smali (one class or the whole app, like apktool d /
baksmali), `build` assembles it into the right classesN.dex, zipaligns and signs (like apktool b,
smali.jar, zipalign, apksigner), `verify` checks v1/v2/v3, `install` drives adb.

For scripts and agents: -q drops progress lines from stderr, --json gives JSON where a command
lists items, --limit/--offset page long lists. Exit code 0 = ran fine (even with no results),
1 = error, 2 = bad usage. Every command is also an MCP tool: apkscope mcp.
More: docs/agents.md";

pub const CLASSES: &str = "\
Examples:
  apkscope classes app.apk --prefix com.example
  apkscope classes app.apk --app-only --json";

pub const METHODS: &str = "\
Examples:
  apkscope methods app.apk --class com.example.Main
  apkscope methods app.apk --filter login";

pub const STRINGS: &str = "\
Examples:
  apkscope strings app.apk --filter https://
Tip: to see which classes use a string, use `apkscope refs app.apk string <text>`.";

pub const REFS: &str = "\
Examples:
  apkscope refs app.apk string \"api/v1/login\"           every class that uses this string
  apkscope refs app.apk method com.example.Api#login     who calls it
  apkscope refs app.apk field com.example.Cfg#TOKEN      who reads / writes it
  apkscope refs app.apk type okhttp3.OkHttpClient        who mentions the type
  apkscope refs app.apk impl com.example.IProtocol       direct implementors
  apkscope refs app.apk extends android.app.Activity
  apkscope refs app.apk string token --regex --ignore-case --java   with the decompiled lines";

pub const DECOMPILE: &str = "\
Examples:
  apkscope decompile app.apk com.example.Main
  apkscope decompile app.apk com.example.Main --method onCreate
  apkscope decompile app.apk a.b.C a.b.D --out-dir src/        one file per class
  apkscope decompile app.apk --classes-file list.txt --out-dir src/
  apkscope decompile app.apk com.example.Main --smali
Class names work in the shown (deobfuscated) form and in the original obfuscated form.
To patch a class, take its smali from `apkscope smali` (the format build assembles), not --smali here.";

pub const DIFF: &str = "\
Examples:
  apkscope diff old.apk new.apk                 classes, methods, permissions, changed constants
  apkscope diff old.apk new.apk --strings       also added / removed strings (check that a patch landed)";

pub const CONSTS: &str = "\
Examples:
  apkscope consts app.apk com.example.Codes            every constant of one class
  apkscope consts app.apk com.example.net.*            of a package
  apkscope consts app.apk --value 405                  which constants are 405
  apkscope consts app.apk --name 'result|error' com.example.*
Static final fields with a value stored in the DEX (int, long, String, ...).";

pub const RETURNS: &str = "\
Examples:
  apkscope returns app.apk uri --impl com.example.IProtocol     every message class and its id
  apkscope returns app.apk uri --value 736131                   which class has this id
  apkscope returns app.apk getType --in com.example.msg.*
Finds methods whose whole body is `return <constant>;` (ids, opcodes, type codes).";

pub const SIZE: &str = "\
Examples:
  apkscope size app.apk
  apkscope size app.apk --top 50 --json
Read from the zip directory; duplicates are files with the same CRC and size.";

pub const SEARCH: &str = "\
Scopes:
  code      decompiled Java            string   string literals         usages  xref by name
  class     class names                res      resource XML + manifest (file:line)
  urls      endpoints                  http     HTTP client calls       secrets keys and tokens
  api       Retrofit endpoint table    config   BuildConfig, remote-config defaults, prefs reads
Examples:
  apkscope search app.apk code \"getToken\"
  apkscope search app.apk code 736131 --in com.example.room.*     only one package
  apkscope search app.apk code marshall --impl com.example.IProtocol
  apkscope search app.apk res \"@id/login_button\"                  which layout uses it
  apkscope search app.apk urls --all --format json
  apkscope search app.apk api
urls / http / secrets show app code only by default (--all adds libraries).";

pub const INFO: &str = "\
Examples:
  apkscope info app.apk     package, versions, SDKs, permissions, exported components, native libs";

pub const RESOURCE: &str = "\
Examples:
  apkscope resource app.apk res/layout/activity_main.xml
  apkscope resource app.apk AndroidManifest.xml";

pub const RECON: &str = "\
Examples:
  apkscope callers app.apk com.example.Api login
  apkscope access app.apk com.example.Session token";

pub const CALLGRAPH: &str = "\
Examples:
  apkscope callgraph app.apk com.example.Api login --depth 4";

pub const FRIDA: &str = "\
Examples:
  apkscope frida app.apk com.example.Api login > hook.js; frida -U -f com.example -l hook.js
  apkscope frida app.apk com.example.Api          every method of the class
  apkscope frida --preset http > http.js; frida -U -f com.example -l http.js   all HTTP traffic";

pub const FRIDA_SERVER: &str = "Examples:
  apkscope frida-server                        what the device has and which frida-server file it needs
  apkscope frida-server --push frida-server-17.2.15-android-arm64   push, start and check it
  apkscope frida-server -D emulator-5554
apkscope downloads nothing: it prints the file name and release URL to fetch yourself.";

pub const INSTALL: &str = "Examples:
  apkscope install app.xapk                 base + the ABI split the device needs + density/language splits
  apkscope install app.apk -D emulator-5554
  apkscope install app.xapk --abi arm64-v8a   force an ABI (an arm64-only app on an x86_64 emulator)
It prints the primaryCpuAbi the package manager chose.";

pub const NOTE: &str = "\
Examples:
  apkscope rename app.apk a.b.c com.example.LoginActivity
  apkscope rename app.apk a.b.c#d() checkPassword
  apkscope comment app.apk a.b.c#d() \"returns true when the PIN matches\"
Saved in <apk>.apkscope.json next to the APK; decompile, search and the viewer use the names.";

pub const SMALI: &str = "\
Examples:
  apkscope smali app.apk com.example.Main > Main.smali
  (edit Main.smali)
  apkscope build app.apk out.apk --smali Main.smali
  apkscope install out.apk
  apkscope smali app.apk --out-dir decoded/            every class: decoded/smali/a/b/C.smali,
                                                       decoded/smali_classes2/... (one folder per DEX)
  apkscope smali app.apk a.b.C a.b.D --out-dir decoded/
  apkscope build app.apk out.apk --smali decoded/      applies only the classes you changed
build assembles each class into the classesN.dex it came from: no baksmali, smali.jar or apktool
needed. A nested class is a class of its own (a.b.C$Inner). Deleting a file does not remove its
class. `apkscope res app.apk decoded/` can write the resources into the same folder.";

pub const RES: &str = "\
Examples:
  apkscope res app.apk decoded/
  (edit decoded/res/values/strings.xml or decoded/AndroidManifest.xml)
  apkscope build app.apk out.apk --res decoded/
Also takes a folder decoded by apktool or APKEditor: changed and new files are applied,
nothing is removed.";

pub const BUILD: &str = "\
Examples:
  apkscope build app.apk out.apk --smali Main.smali --smali Login.smali
  apkscope build app.apk out.apk --smali decoded/ --res decoded/   folders from `smali --out-dir` and `res`
  apkscope build app.apk out.apk                   re-sign and zipalign only (debug key)
  apkscope build app.apk out.apk --res decoded/ --string app_name=Patched
  apkscope build app.apk out.apk --put classes7.dex=my.dex --delete META-INF/old.SF
  apkscope build app.apk out.apk --ks release.jks --ks-pass pass:secret --ks-alias key0
  apkscope build app.apk out.apk --ks release.p12 --ks-pass env:KS_PASS
  apkscope build app.apk out.apk --key k.pk8 --cert c.crt
Without a key it signs with apkscope's own debug key. --ks-pass takes pass:TEXT, env:VAR or
file:PATH. Keystores: JKS and PKCS#12 (.jks, .keystore, .p12, .pfx).
No zipalign or apksigner needed: build does both. Then: apkscope verify out.apk;
apkscope install out.apk";

pub const VERIFY: &str = "\
Examples:
  apkscope verify out.apk     v1 (JAR), v2 and v3: verified, not present, or FAILED and why
v1 is checked as Android 5-6 check it: every entry's digest, the manifest, the RSA signature
(a DSA / EC v1 signature: digests only). To sign or re-sign: apkscope build app.apk out.apk.";

pub const EXPORT: &str = "\
Examples:
  apkscope export app.apk project/      a Gradle project of the whole app";

pub const DISASM: &str = "\
Examples:
  apkscope disasm app.apk com.example.Main";

pub const MANIFEST: &str = "\
Examples:
  apkscope manifest app.apk                      the decoded AndroidManifest.xml
  apkscope manifest app.xapk -o manifest.xml     of a bundle's base split, to a file";

pub const DUMP: &str = "\
Examples:
  apkscope dump app.apk out/                    start it under Frida, save the DEX it unpacks
  apkscope dump com.example out/ --attach        join the running app
  apkscope dump app.apk out/ --wait 30           packers that unpack late
Needs frida-tools here and frida-server on a rooted device (see apkscope frida-server).";

pub const IL2CPP: &str = "\
Examples:
  apkscope il2cpp game.apk                          C# methods with their native addresses
  apkscope il2cpp game.apk --uses \"api.example.com\"   which methods use a string
  apkscope il2cpp game.apk --method Login            strings and calls inside a method
  apkscope il2cpp base.apk config.arm64_v8a.apk      a split game: base plus its ABI split";

pub const FLUTTER: &str = "\
Examples:
  apkscope flutter app.apk                   Dart version, native libs, recovered library tree
  apkscope flutter app.apk --api             hosts, routes and model fields
  apkscope flutter app.xapk --strings        every string of libapp.so (bundles read their splits)";

pub const SCAN: &str = "\
Examples:
  apkscope scan app.apk                       endpoints, secrets, HTTP calls, weak crypto: leads to check
  apkscope scan app.apk --filter firebase     only findings that mention firebase
  apkscope scan app.apk --limit 50 --offset 50   page through a big report";

pub const FINGERPRINT: &str = "\
Examples:
  apkscope fingerprint app.apk --all --strings   known SDKs and trackers, with versions and hosts
  apkscope fingerprint app.apk --all --json      the same, machine-readable
  apkscope fingerprint app.apk --diff old.apk    what changed between two builds
  apkscope fingerprint --list                    the catalogs, no APK needed";

pub const DECRYPT: &str = "\
Examples:
  apkscope decrypt app.apk                    every string-decryptor call with constant arguments, run
  apkscope decrypt app.apk --json";

pub const MAP: &str = "\
Examples:
  apkscope map app.apk export names.jobf         the renames, for JADX
  apkscope map app.apk export mapping.txt        as a ProGuard / R8 mapping
  apkscope map app.apk import mapping.txt        names from the app's own R8 mapping";

pub const MCP: &str = "\
Examples:
  apkscope mcp                                  serve the MCP tools over stdio
Claude Code:  claude mcp add apkscope -- apkscope mcp
Other clients: command \"apkscope\", args [\"mcp\"]. Tools take apk_path; see docs/agents.md.";

pub const GUI: &str = "\
Examples:
  apkscope gui app.apk
  apkscope app.apk                              the same: a file alone opens the viewer";

pub const UPGRADE: &str = "\
Examples:
  apkscope upgrade                              the latest stable build
  apkscope upgrade --check                      only say whether there is one
  apkscope upgrade --canary                     the build of the latest commit on main
  apkscope upgrade --version 0.12.0             a given release";
