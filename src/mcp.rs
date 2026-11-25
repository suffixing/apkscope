//! MCP server over stdio (JSON-RPC 2.0, one message per line). Stateless tools run the CLI in
//! a fresh process, so they behave exactly like the command line and many APKs can be open at
//! once. Tools called with `cache: true` go to a warm worker per APK that keeps the session
//! (reference index, disk code cache, whole-APK deobfuscation) loaded between calls.

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Write};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering::Relaxed};
use std::sync::mpsc::{self, Receiver, TryRecvError};
use std::time::Instant;

use serde_json::{Value, json};

use crate::live::Live;

const PROTOCOL: &str = "2025-06-18";
/// default cap on a tool's text, so one call can't flood an agent's context
const MAX_CHARS: usize = 60_000;
/// warm sessions kept at once; a big APK's session holds about 1 GB
const MAX_WORKERS: usize = 4;
/// a warm session unused this long exits and frees its memory; the next request restarts it
const IDLE_SECS: u64 = 600;

fn tools() -> Value {
    let apk = json!({"type": "string", "description": "Absolute path to the .apk, .jar, .apks, .xapk, .apkm or .dex file"});
    let page = |props: Value| {
        let mut p = props;
        p["limit"] = json!({"type": "integer", "description": "At most this many results"});
        p["offset"] = json!({"type": "integer", "description": "Skip this many results (paging)"});
        p["max_chars"] = json!({"type": "integer", "description": "Cut the reply after this many characters (default 60000)"});
        p
    };
    let cache = json!({"type": "boolean", "description": "Default true: answer from a warm session of this APK kept in memory (milliseconds per call, whole-APK deobfuscation, disk code cache). While it loads in the background, calls are answered statelessly, so the first call is never slower. false = always a stateless one-shot process."});
    json!([
        {"name": "list_classes", "description": "List classes of an APK (Java names). Stateless, parallel, no cache.",
         "inputSchema": {"type": "object", "required": ["apk_path"], "properties": page(json!({"apk_path": apk,
            "prefix": {"type": "string", "description": "Only classes under this package / name prefix"},
            "app_only": {"type": "boolean", "description": "Skip known SDKs and libraries (androidx, okhttp, gms...)"},
            "descriptors": {"type": "boolean", "description": "Print Lcom/a/B; descriptors"}}))}},
        {"name": "list_methods", "description": "List defined methods as Lcls;->name(params)Ret, without decompiling.",
         "inputSchema": {"type": "object", "required": ["apk_path"], "properties": page(json!({"apk_path": apk,
            "class_name": {"type": "string", "description": "Exact class (dotted name or descriptor)"},
            "filter": {"type": "string", "description": "Case-insensitive method-name substring"}}))}},
        {"name": "list_strings", "description": "String-pool values of all DEX files, including unreferenced ones.",
         "inputSchema": {"type": "object", "required": ["apk_path"], "properties": page(json!({"apk_path": apk,
            "filter": {"type": "string", "description": "Case-insensitive substring"}}))}},
        {"name": "find_refs", "description": "Cross-references from bytecode: which methods use a string / type / method / field, or which classes extend / implement a type. Optionally returns the decompiled Java lines that mention it.",
         "inputSchema": {"type": "object", "required": ["apk_path", "kind", "query"], "properties": page(json!({"apk_path": apk,
            "kind": {"type": "string", "enum": ["string", "type", "method", "field", "extends", "impl"]},
            "query": {"type": "string", "description": "String text (substring), type name, or member name (exact unless regex)"},
            "class_name": {"type": "string", "description": "Owner class for method / field"},
            "fuzzy_class": {"type": "boolean", "description": "class_name is a descriptor substring"},
            "regex": {"type": "boolean"}, "ignore_case": {"type": "boolean"},
            "with_java": {"type": "boolean", "description": "Also return the decompiled Java lines of each referencing class that mention the query"},
            "json": {"type": "boolean", "description": "Return a JSON array instead of text lines"},
            "cache": cache}))}},
        {"name": "decompile", "description": "Decompile one or more classes to readable Java (or Smali), or just one method of them. Stateless by default (only the needed DEX files are touched). For smali you will edit, use get_smali (the format build_apk assembles).",
         "inputSchema": {"type": "object", "required": ["apk_path", "classes"], "properties": page(json!({"apk_path": apk,
            "classes": {"type": "array", "items": {"type": "string"}, "description": "Class names, e.g. com.example.Main"},
            "method": {"type": "string", "description": "Only return the method(s) with this name"},
            "smali": {"type": "boolean", "description": "Smali instead of Java (for reading; to patch, use get_smali)"},
            "full": {"type": "boolean", "description": "Also decompile methods the deobfuscator would leave out (synthetic / bridge)"},
            "out_dir": {"type": "string", "description": "Write one file per class (a.b.C.java) to this folder instead of returning the text"},
            "cache": cache,
            "deobfuscate": {"type": "boolean", "description": "Rename obfuscated names (default true)"}}))}},
        {"name": "search", "description": "Search decompiled code and resources. Scopes: code (decompiled Java), string (literals), usages (xref by name), class, res (XML resources + manifest), urls (endpoints in code, resources, native libs, text assets and Hermes / React Native bundles), http (Retrofit / OkHttp / HttpURLConnection calls), secrets (API keys, tokens, in the same places as urls, plus a labelled lower-confidence entropy tier of app constants), api (the app's HTTP API: Retrofit endpoints with verb, path, params, base URL and a curl line each), config (what the server can change: BuildConfig defaults, remote-config defaults, reads with fallbacks). Uses the reference index so only classes that can match get decompiled.",
         "inputSchema": {"type": "object", "required": ["apk_path", "scope"], "properties": page(json!({"apk_path": apk,
            "scope": {"type": "string", "enum": ["code", "string", "usages", "class", "res", "urls", "http", "secrets", "api", "config"]},
            "query": {"type": "string", "description": "Optional for urls / http / secrets / api / config"},
            "regex": {"type": "boolean"}, "case_sensitive": {"type": "boolean"},
            "app_only": {"type": "boolean", "description": "Skip known SDKs and libraries"},
            "all": {"type": "boolean", "description": "Include library/SDK code in urls / http / secrets, which default to app code only"},
            "in": {"type": "array", "items": {"type": "string"}, "description": "Only these classes or packages: a.b.C, a.b.*"},
            "impl": {"type": "string", "description": "Only classes that extend / implement this class or interface (directly or not)"},
            "context": {"type": "integer", "description": "Lines of code around each hit"},
            "whole_method": {"type": "boolean", "description": "Return the whole enclosing method of each hit"},
            "format": {"type": "string", "enum": ["txt", "json", "csv"]},
            "cache": {"type": "boolean", "description": "Keep the session warm (default true). false = one-shot process that neither reads nor writes the code cache."}}))}},
        {"name": "apk_info", "description": "Security overview: package, versions, SDK levels, permissions, exported components, deep links, native libraries with meanings, code share by SDK, DEX/class counts.",
         "inputSchema": {"type": "object", "required": ["apk_path"], "properties": {"apk_path": apk, "cache": cache}}},
        {"name": "get_manifest", "description": "Decoded AndroidManifest.xml with resource names.",
         "inputSchema": {"type": "object", "required": ["apk_path"], "properties": {"apk_path": apk}}},
        {"name": "get_resource", "description": "Decoded resource (res/values/strings.xml, res/layout/x.xml...) or a native library report (lib/arm64-v8a/x.so: JNI exports, strings).",
         "inputSchema": {"type": "object", "required": ["apk_path", "path"], "properties": {"apk_path": apk, "path": {"type": "string"}, "cache": cache}}},
        {"name": "export_project", "description": "Write a full Gradle project (all classes decompiled on all cores, decoded resources, assets, native libs) to a directory.",
         "inputSchema": {"type": "object", "required": ["apk_path", "out_dir"], "properties": {"apk_path": apk, "out_dir": {"type": "string"}}}},
        {"name": "verify_signature", "description": "Check the APK's v1 (JAR: every entry's digest, the manifest, the RSA signature), v2 and v3 signatures, one line each: verified, not present or FAILED with the reason (e.g. an entry changed after signing). To sign or re-sign, use build_apk.",
         "inputSchema": {"type": "object", "required": ["apk_path"], "properties": {"apk_path": apk}}},
        {"name": "diff_apks", "description": "What changed between two versions of an app: added / removed classes, methods of classes both have, permissions, changed named constants (a rotated key shows its new value), and optionally strings (new URLs, keys) with likely rotated/renamed pairs. Lines start with + or -.",
         "inputSchema": {"type": "object", "required": ["apk_path", "new_apk_path"], "properties": {"apk_path": apk, "new_apk_path": {"type": "string", "description": "the newer APK"}, "strings": {"type": "boolean", "description": "also diff string-pool values"}, "app_only": {"type": "boolean", "description": "leave out classes of known libraries (SDK churn), with their methods and constants"}, "limit": {"type": "integer"}, "offset": {"type": "integer"}}}},
        {"name": "callers", "description": "Methods that call a given method (or any method of a class): who invokes it, one level up.",
         "inputSchema": {"type": "object", "required": ["apk_path", "class"], "properties": {"apk_path": apk, "class": {"type": "string", "description": "Java class name or descriptor"}, "method": {"type": "string", "description": "Method name; omit for all methods of the class"}}}},
        {"name": "call_graph", "description": "Callers of a method plus the tree of methods it calls, down to a given depth.",
         "inputSchema": {"type": "object", "required": ["apk_path", "class"], "properties": {"apk_path": apk, "class": {"type": "string"}, "method": {"type": "string"}, "depth": {"type": "integer", "description": "Callee-tree depth (default 3)"}}}},
        {"name": "field_access", "description": "Where a field is read or written: each site marked read / write, with the accessing method.",
         "inputSchema": {"type": "object", "required": ["apk_path", "class", "field"], "properties": {"apk_path": apk, "class": {"type": "string"}, "field": {"type": "string", "description": "Field name"}}}},
        {"name": "decrypt_strings", "description": "Run string-decryptor methods on their constant arguments and report the recovered plaintext (the same values shown inline as /* = \"...\" */ in decompiled code).",
         "inputSchema": {"type": "object", "required": ["apk_path"], "properties": {"apk_path": apk}}},
        {"name": "scan", "description": "One-shot security scan as a single report: endpoints / URLs (key-like parameters marked), embedded secrets (API keys, tokens) and HTTP-client calls across code, resources and native libraries.",
         "inputSchema": {"type": "object", "required": ["apk_path"], "properties": {"apk_path": apk, "filter": {"type": "string", "description": "only findings containing this text (case-insensitive), under their section titles"}, "limit": {"type": "integer", "description": "at most this many lines"}, "offset": {"type": "integer", "description": "skip this many lines (paging)"}}}},
        {"name": "fingerprint", "description": "Fingerprint known SDKs, frameworks and trackers in the APK (curated catalog + optional Exodus list): evidence, obfuscation-aware confidence and version pins; --diff for two builds.",
         "inputSchema": {"type": "object", "required": ["apk_path"], "properties": {"apk_path": apk, "strings": {"type": "boolean", "description": "also scan DEX string pools for URLs/banners"}, "exodus": {"type": "boolean", "description": "use the Exodus tracker list instead of the curated catalog"}, "all": {"type": "boolean", "description": "curated + Exodus, curated winning overlaps"}, "category": {"type": "string", "description": "filter: ads|analytics|crash|framework|integrity|license|monetization|network|push|auth|media|storage|di|util|obfuscator"}, "snapshot": {"type": "boolean", "description": "include a stable content hash of the detected set"}}}},
        {"name": "frida_hook_script", "description": "Write a standalone Frida hook script for a method (or every method of a class) that logs arguments, return values and exceptions. For running hooks now, use frida_start + frida_hook instead.",
         "inputSchema": {"type": "object", "required": ["apk_path", "class"], "properties": {"apk_path": apk, "class": {"type": "string"}, "method": {"type": "string", "description": "omit for all methods"}, "live": {"type": "boolean", "description": "event body for live sessions instead of a console.log script"}}}},
        {"name": "dump_app", "description": "Run the app under Frida and save the DEX files it unpacks at runtime and the scripts it decrypts (packed / protected apps). Needs frida-tools here and frida-server on the device.",
         "inputSchema": {"type": "object", "required": ["apk_path", "out_dir"], "properties": {"apk_path": {"type": "string", "description": "APK path or the app's package name"}, "out_dir": {"type": "string"}, "attach": {"type": "boolean", "description": "attach to the running app instead of spawning it"}, "device": {"type": "string", "description": "frida device id"}, "wait": {"type": "integer", "description": "seconds to collect DEX files (default 15)"}, "scripts_for": {"type": "integer", "description": "seconds to collect scripts (default 15)"}}}},
        {"name": "il2cpp", "description": "Unity IL2CPP games: C# methods with their native addresses, which method uses a string, or the strings and calls inside one method.",
         "inputSchema": {"type": "object", "required": ["apk_path"], "properties": page(json!({"apk_path": apk, "extra_paths": {"type": "array", "items": {"type": "string"}, "description": "more APK / split files of the same game"}, "uses": {"type": "string", "description": "methods that use this string"}, "method": {"type": "string", "description": "strings and calls inside this method"}}))}},
        {"name": "flutter", "description": "Flutter apps: Dart snapshot version, native libs and the recovered Dart library tree; api lists hosts, routes and model fields; strings dumps libapp.so strings.",
         "inputSchema": {"type": "object", "required": ["apk_path"], "properties": page(json!({"apk_path": apk, "abi": {"type": "string", "description": "e.g. arm64-v8a"}, "api": {"type": "boolean"}, "strings": {"type": "boolean"}}))}},
        {"name": "rename", "description": "Rename a class or member everywhere apkscope shows it (decompiler, xrefs, GUI, export). Saved in <apk>.apkscope.json next to the APK. An empty new_name removes the rename.",
         "inputSchema": {"type": "object", "required": ["apk_path", "target", "new_name"], "properties": {"apk_path": apk, "target": {"type": "string", "description": "a.b.C, a.b.C#field or a.b.C#method()"}, "new_name": {"type": "string"}}}},
        {"name": "comment", "description": "Attach a comment to a class or member; shown above it in decompiled code. Saved in <apk>.apkscope.json. Empty text removes it.",
         "inputSchema": {"type": "object", "required": ["apk_path", "target", "text"], "properties": {"apk_path": apk, "target": {"type": "string"}, "text": {"type": "string"}}}},
        {"name": "mapping", "description": "Exchange names with other tools: export the renames to, or import them from, a JADX (.jobf), Enigma (.mapping) or ProGuard/R8 (mapping.txt) file. The format follows the file name.",
         "inputSchema": {"type": "object", "required": ["apk_path", "direction", "file"], "properties": {"apk_path": apk, "direction": {"type": "string", "enum": ["import", "export"]}, "file": {"type": "string"}}}},
        {"name": "get_smali", "description": "Editable smali, in the format build_apk assembles (no baksmali or apktool needed). With class: that one class as text (a nested class is its own: a.b.C$Inner); save it to a file, edit, pass the file to build_apk's smali list. With out_dir: one .smali file per class (every class, or those in classes) written as apktool lays them out, smali/ for classes.dex, smali_classes2/ for classes2.dex..., a/b/C.smali; edit any of them, then pass the folder to build_apk's smali list (only changed classes are applied).",
         "inputSchema": {"type": "object", "required": ["apk_path"], "properties": {"apk_path": apk,
            "class": {"type": "string", "description": "one class to return as text"},
            "out_dir": {"type": "string", "description": "write .smali files to this folder instead (every class unless classes is given)"},
            "classes": {"type": "array", "items": {"type": "string"}, "description": "with out_dir: only these classes"}}}},
        {"name": "disassemble", "description": "Raw Dalvik bytecode listing of one class, or of every class when class is omitted.",
         "inputSchema": {"type": "object", "required": ["apk_path"], "properties": page(json!({"apk_path": apk, "class": {"type": "string"}}))}},
        {"name": "decode_resources", "description": "Write the manifest and res/ as editable files to a folder. Edit them, then pass the folder to build_apk's res_dir.",
         "inputSchema": {"type": "object", "required": ["apk_path", "out_dir"], "properties": {"apk_path": apk, "out_dir": {"type": "string"}}}},
        {"name": "build_apk", "description": "Patch, rebuild, zipalign and sign in one step (no smali.jar, apktool, zipalign or apksigner needed). Assembles edited smali files (from get_smali) into the right classesN.dex, applies an edited manifest, a decoded resources folder (decode_resources, apktool or APKEditor) or single string values, replaces / adds / deletes files, then zipaligns and signs (v2+v3, plus v1 when minSdkVersion < 24; apkscope's debug key unless a keystore or key/cert is given). With no edits it just re-signs and re-aligns the APK. Then install_apk.",
         "inputSchema": {"type": "object", "required": ["apk_path", "out_path"], "properties": {"apk_path": apk, "out_path": {"type": "string"},
            "put": {"type": "array", "items": {"type": "string"}, "description": "name=file: store this local file under that entry name"},
            "delete": {"type": "array", "items": {"type": "string"}, "description": "entry names to leave out"},
            "smali": {"type": "array", "items": {"type": "string"}, "description": "edited .smali files, or folders from get_smali out_dir (only classes that differ from the APK are applied)"},
            "manifest": {"type": "string", "description": "edited AndroidManifest.xml (text)"},
            "res_dir": {"type": "string", "description": "a folder from decode_resources"},
            "strings": {"type": "array", "items": {"type": "string"}, "description": "name[@config]=value string-resource edits"},
            "key": {"type": "string", "description": "PKCS#8 .pk8 private key"}, "cert": {"type": "string", "description": "X.509 certificate"},
            "keystore": {"type": "string", "description": "JKS or PKCS#12 keystore (.jks, .keystore, .p12, .pfx) to sign with"},
            "keystore_pass": {"type": "string", "description": "pass:TEXT, env:VAR or file:PATH"},
            "key_pass": {"type": "string", "description": "key password, same forms (default: keystore_pass)"},
            "key_alias": {"type": "string", "description": "which key (default: the only one)"},
            "no_sign": {"type": "boolean"}}}},
        {"name": "consts", "description": "Static final constants (int, long, String...) stored in the DEX, by class / package, value or name. Decodes numbers: value 405 or 0xB8D0AFDF lists every constant with that value.",
         "inputSchema": {"type": "object", "required": ["apk_path"], "properties": page(json!({"apk_path": apk, "classes": {"type": "array", "items": {"type": "string"}, "description": "a.b.C or a.b.* (omitted = all)"}, "value": {"type": "string"}, "name": {"type": "string", "description": "regex on the constant's name"}}))}},
        {"name": "returns", "description": "Methods whose whole body is `return <constant>;`: message ids, opcodes, type codes. E.g. method uri with impl com.example.IProtocol lists every message class and its id; value finds the class for an id.",
         "inputSchema": {"type": "object", "required": ["apk_path"], "properties": page(json!({"apk_path": apk, "method": {"type": "string", "description": "method name (omitted = any)"}, "impl": {"type": "string"}, "in": {"type": "array", "items": {"type": "string"}}, "value": {"type": "string"}}))}},
        {"name": "size", "description": "Where the APK's size goes: share per kind (dex, native libs per ABI, res, assets), the biggest entries and duplicate files (same CRC and size).",
         "inputSchema": {"type": "object", "required": ["apk_path"], "properties": {"apk_path": apk, "top": {"type": "integer", "description": "how many biggest entries (default 25)"}}}},
        {"name": "install_apk", "description": "Install an APK (e.g. build_apk's output) or a split bundle (.xapk/.apks/.apkm) on a device. Drives adb for you (adb must be on PATH), picking the ABI split the device needs (first device ABI the app ships code for, passed as --abi, so arm64-only apps on x86_64 emulators with ARM translation get arm64), all density and language splits, then reports the primaryCpuAbi the package manager chose. Says when the app cannot run on the device's ABIs.",
         "inputSchema": {"type": "object", "required": ["apk_path"], "properties": {"apk_path": apk, "device": {"type": "string", "description": "adb serial (default: the only device)"}, "abi": {"type": "string", "description": "force an ABI (default: auto)"}}}},
        {"name": "frida_start", "description": "Start a live Frida session on a device (needs frida-tools on this machine and frida-server on the device). Spawns the app (or attaches to it), then hooks are added with frida_hook and their calls read with frida_events. One session at a time; starting again replaces it.",
         "inputSchema": {"type": "object", "properties": {"apk_path": {"type": "string", "description": "APK to take the package name from"}, "package": {"type": "string", "description": "app id, instead of apk_path"}, "attach": {"type": "boolean", "description": "attach to the running app instead of spawning it"}, "device": {"type": "string", "description": "frida device id (default: USB)"}}}},
        {"name": "frida_hook", "description": "Hook every overload of a method (or all methods of a class) in the live session: each call logs its arguments, return value or exception. Or load a built-in preset: http logs every OkHttp 3/4 request and response (method, URL, headers, bodies up to 64 KB, status) and HttpURLConnection status, as kind http in frida_events. Takes effect at once, no restart.",
         "inputSchema": {"type": "object", "properties": {"apk_path": apk, "class": {"type": "string", "description": "Java class name or descriptor"}, "method": {"type": "string", "description": "method name (omit for all methods, <init> for constructors)"}, "preset": {"type": "string", "enum": ["http"], "description": "a built-in hook set instead of class/method"}}}},
        {"name": "frida_setup", "description": "Check a device for Frida before frida_start: device ABIs and SDK, this machine's frida version, whether frida-server is on the device, running and the same version. Names the exact frida-server file and release URL to download (apkscope downloads nothing); with push, pushes that downloaded (unpacked) file over adb, starts it as root and checks it. Warns when an x86_64 device would need ARM translation.",
         "inputSchema": {"type": "object", "properties": {"device": {"type": "string", "description": "adb serial (default: the only device)"}, "push": {"type": "string", "description": "path of an unpacked frida-server file to push and start"}}}},
        {"name": "frida_script", "description": "Load your own Frida JavaScript into the live session under a name (same name replaces it). Wrap Java code in Java.perform; call __ev(kind, name, value) to report events that frida_events shows; console.log lines show as kind log.",
         "inputSchema": {"type": "object", "required": ["name", "js"], "properties": {"name": {"type": "string"}, "js": {"type": "string"}}}},
        {"name": "frida_unhook", "description": "Remove a hook or script: a class (all its methods), Class#method, a script name, or * for everything.",
         "inputSchema": {"type": "object", "required": ["key"], "properties": {"key": {"type": "string"}}}},
        {"name": "frida_events", "description": "What the hooks saw: one line per event (#seq thread kind method value), kinds call / ret / throw / error / log. Pass the returned next_since back to get only newer events; summary: true counts calls per method instead.",
         "inputSchema": {"type": "object", "properties": {"since": {"type": "integer"}, "filter": {"type": "string", "description": "substring of method or value"}, "limit": {"type": "integer", "description": "newest events to return (default 200)"}, "summary": {"type": "boolean"}}}},
        {"name": "frida_stop", "description": "End the live session (kills frida; a spawned app keeps running).",
         "inputSchema": {"type": "object", "properties": {}}}
    ])
}

/// A warm session process for one APK. Its replies arrive through `rx`; the first one says
/// the session has loaded.
struct Worker {
    child: Child,
    stdin: ChildStdin,
    rx: Receiver<String>,
    ready: bool,
    used: Instant,
}

impl Drop for Worker {
    fn drop(&mut self) {
        let _ = self.child.kill();
    }
}

fn exe() -> Result<std::path::PathBuf, String> {
    std::env::current_exe().map_err(|e| e.to_string())
}

/// Run the CLI once; returns (stdout + stderr notes, success).
fn run_cli(args: &[String]) -> Result<(String, bool), String> {
    let out = Command::new(exe()?)
        .args(args)
        .stdin(Stdio::null())
        .output()
        .map_err(|e| e.to_string())?;
    let mut text = String::from_utf8_lossy(&out.stdout).into_owned();
    let err = String::from_utf8_lossy(&out.stderr);
    if !err.trim().is_empty() {
        text += &format!("\n[{}]\n", err.trim());
    }
    Ok((text, out.status.success()))
}

/// Ask the APK's warm session; until it has loaded, answer with the stateless `fallback`
/// command instead (requests without one wait for the load).
fn ask_worker(
    workers: &mut HashMap<String, Worker>,
    apk: &str,
    deobf: bool,
    req: &[String],
    fallback: Option<Vec<String>>,
) -> Result<(String, bool), String> {
    let key = format!("{apk}\0{deobf}");
    // a worker that exited on its own (idle timeout) is started again
    if workers
        .get_mut(&key)
        .is_some_and(|w| !matches!(w.child.try_wait(), Ok(None)))
    {
        workers.remove(&key);
    }
    if !workers.contains_key(&key) {
        if workers.len() >= MAX_WORKERS {
            let old = workers.iter().min_by_key(|w| w.1.used).map(|w| w.0.clone());
            old.map(|k| workers.remove(&k));
        }
        let mut cmd = Command::new(exe()?);
        cmd.arg("worker").arg(apk);
        if !deobf {
            cmd.arg("--no-deobf");
        }
        let mut child = cmd
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|e| e.to_string())?;
        let stdin = child.stdin.take().ok_or("no worker stdin")?;
        let stdout = BufReader::new(child.stdout.take().ok_or("no worker stdout")?);
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            for line in stdout.lines().map_while(Result::ok) {
                if tx.send(line).is_err() {
                    break;
                }
            }
        });
        workers.insert(
            key.clone(),
            Worker {
                child,
                stdin,
                rx,
                ready: false,
                used: Instant::now(),
            },
        );
    }
    let w = workers.get_mut(&key).unwrap();
    w.used = Instant::now();
    if !w.ready {
        let first = match &fallback {
            Some(_) => w.rx.try_recv(),
            None => w.rx.recv().map_err(|_| TryRecvError::Disconnected),
        };
        match first {
            Ok(_) => w.ready = true,
            Err(TryRecvError::Empty) => return run_cli(fallback.as_deref().unwrap_or_default()),
            Err(TryRecvError::Disconnected) => {
                workers.remove(&key);
                return match fallback {
                    Some(f) => run_cli(&f),
                    None => Err("the session could not load this APK".into()),
                };
            }
        }
    }
    let sent = writeln!(w.stdin, "{}", json!(req)).and_then(|_| w.stdin.flush());
    let line = match sent.ok().and_then(|_| w.rx.recv().ok()) {
        Some(l) => l,
        None => {
            workers.remove(&key);
            return Err("the session worker exited (APK unreadable?)".into());
        }
    };
    let v: Value = serde_json::from_str(&line).map_err(|e| e.to_string())?;
    // the full session is still loading: answer this one statelessly
    if v["busy"].as_bool() == Some(true) {
        return run_cli(fallback.as_deref().unwrap_or_default());
    }
    Ok((
        v["text"].as_str().unwrap_or_default().to_string(),
        v["ok"].as_bool().unwrap_or(false),
    ))
}

fn s(a: &Value, k: &str) -> Option<String> {
    a.get(k)
        .and_then(Value::as_str)
        .filter(|x| !x.is_empty())
        .map(str::to_string)
}

fn b(a: &Value, k: &str) -> bool {
    a.get(k).and_then(Value::as_bool).unwrap_or(false)
}

fn n(a: &Value, k: &str) -> Option<u64> {
    a.get(k).and_then(Value::as_u64)
}

/// `cache` defaults to on
fn cached(a: &Value) -> bool {
    a.get("cache").and_then(Value::as_bool).unwrap_or(true)
}

fn call(
    workers: &mut HashMap<String, Worker>,
    name: &str,
    a: &Value,
) -> Result<(String, bool), String> {
    let apk = s(a, "apk_path").ok_or("apk_path is required")?;
    let mut args: Vec<String> = Vec::new();
    let push_opt = |args: &mut Vec<String>, flag: &str, v: Option<String>| {
        if let Some(v) = v {
            args.push(flag.into());
            args.push(v);
        }
    };
    let paging = |args: &mut Vec<String>| {
        for k in ["limit", "offset"] {
            if let Some(v) = n(a, k) {
                args.push(format!("--{k}"));
                args.push(v.to_string());
            }
        }
    };
    let deobf = a
        .get("deobfuscate")
        .and_then(Value::as_bool)
        .unwrap_or(true);
    match name {
        "list_classes" => {
            args.extend(["classes".into(), apk]);
            push_opt(&mut args, "--prefix", s(a, "prefix"));
            if b(a, "app_only") {
                args.push("--app-only".into())
            }
            if b(a, "descriptors") {
                args.push("--desc".into())
            }
            paging(&mut args);
            run_cli(&args)
        }
        "list_methods" => {
            args.extend(["methods".into(), apk]);
            push_opt(&mut args, "--class", s(a, "class_name"));
            push_opt(&mut args, "--filter", s(a, "filter"));
            paging(&mut args);
            run_cli(&args)
        }
        "list_strings" => {
            args.extend(["strings".into(), apk]);
            push_opt(&mut args, "--filter", s(a, "filter"));
            paging(&mut args);
            run_cli(&args)
        }
        "find_refs" => {
            let mut req = vec![
                "refs".to_string(),
                s(a, "kind").ok_or("kind is required")?,
                s(a, "query").ok_or("query is required")?,
            ];
            push_opt(&mut req, "--class", s(a, "class_name"));
            for (k, f) in [
                ("fuzzy_class", "--fuzzy-class"),
                ("regex", "--regex"),
                ("ignore_case", "--ignore-case"),
                ("with_java", "--java"),
                ("json", "--json"),
            ] {
                if b(a, k) {
                    req.push(f.into())
                }
            }
            paging(&mut req);
            args.extend(["refs".into(), apk.clone()]);
            args.extend(req.iter().skip(1).cloned());
            if cached(a) {
                return ask_worker(workers, &apk, deobf, &req, Some(args));
            }
            run_cli(&args)
        }
        "decompile" => {
            let classes: Vec<String> = match a.get("classes") {
                Some(Value::Array(v)) => v
                    .iter()
                    .filter_map(|x| x.as_str().map(str::to_string))
                    .collect(),
                Some(Value::String(c)) => vec![c.clone()],
                _ => vec![],
            };
            if classes.is_empty() {
                return Err("classes is required (one or more class names)".into());
            }
            let mut opts = Vec::new();
            push_opt(&mut opts, "--method", s(a, "method"));
            if b(a, "smali") {
                opts.push("--smali".into())
            }
            if b(a, "full") {
                opts.push("--full".into())
            }
            let mut req = vec!["decompile".to_string()];
            req.extend(classes.iter().cloned());
            req.extend(opts.iter().cloned());
            args.extend(["decompile".into(), apk.clone()]);
            args.extend(classes);
            args.extend(opts);
            if !deobf {
                args.push("--no-deobf".into())
            }
            if let Some(dir) = s(a, "out_dir") {
                args.extend(["--out-dir".into(), dir]);
                return run_cli(&args);
            }
            if cached(a) {
                return ask_worker(workers, &apk, deobf, &req, Some(args));
            }
            run_cli(&args)
        }
        "search" => {
            let mut req = vec![
                "search".to_string(),
                s(a, "scope").ok_or("scope is required")?,
            ];
            req.extend(s(a, "query"));
            for (k, f) in [
                ("regex", "--regex"),
                ("case_sensitive", "--case"),
                ("app_only", "--app-only"),
                ("all", "--all"),
                ("whole_method", "--method"),
            ] {
                if b(a, k) {
                    req.push(f.into())
                }
            }
            if let Some(Value::Array(v)) = a.get("in") {
                for x in v.iter().filter_map(Value::as_str) {
                    req.extend(["--in".to_string(), x.to_string()]);
                }
            } else if let Some(x) = s(a, "in") {
                req.extend(["--in".to_string(), x]);
            }
            push_opt(&mut req, "--impl", s(a, "impl"));
            push_opt(
                &mut req,
                "--context",
                n(a, "context").map(|c| c.to_string()),
            );
            push_opt(&mut req, "--format", s(a, "format"));
            if cached(a) {
                return ask_worker(workers, &apk, deobf, &req, None);
            }
            args.extend(["search".into(), apk]);
            args.extend(req.into_iter().skip(1));
            args.push("--no-cache".into());
            if !deobf {
                args.push("--no-deobf".into())
            }
            run_cli(&args)
        }
        "apk_info" if cached(a) => ask_worker(
            workers,
            &apk,
            deobf,
            &["info".into()],
            Some(vec!["info".into(), apk.clone()]),
        ),
        "apk_info" => run_cli(&["info".into(), apk]),
        "get_manifest" => run_cli(&["manifest".into(), apk]),
        "get_resource" => {
            let path = s(a, "path").ok_or("path is required")?;
            if cached(a) {
                return ask_worker(
                    workers,
                    &apk,
                    deobf,
                    &["resource".into(), path.clone()],
                    Some(vec!["resource".into(), apk.clone(), path]),
                );
            }
            run_cli(&["resource".into(), apk, path])
        }
        "export_project" => run_cli(&[
            "export".into(),
            apk,
            s(a, "out_dir").ok_or("out_dir is required")?,
        ]),
        "verify_signature" => run_cli(&["verify".into(), apk]),
        "diff_apks" => {
            args.extend([
                "diff".into(),
                apk,
                s(a, "new_apk_path").ok_or("new_apk_path is required")?,
            ]);
            if b(a, "strings") {
                args.push("--strings".into());
            }
            if b(a, "app_only") {
                args.push("--app-only".into());
            }
            paging(&mut args);
            run_cli(&args)
        }
        "callers" => {
            args.extend([
                "callers".into(),
                apk,
                s(a, "class").ok_or("class is required")?,
            ]);
            if let Some(m) = s(a, "method") {
                args.push(m)
            }
            run_cli(&args)
        }
        "call_graph" => {
            args.extend([
                "callgraph".into(),
                apk,
                s(a, "class").ok_or("class is required")?,
            ]);
            if let Some(m) = s(a, "method") {
                args.push(m)
            }
            push_opt(&mut args, "--depth", n(a, "depth").map(|d| d.to_string()));
            run_cli(&args)
        }
        "field_access" => {
            args.extend([
                "access".into(),
                apk,
                s(a, "class").ok_or("class is required")?,
                s(a, "field").ok_or("field is required")?,
            ]);
            run_cli(&args)
        }
        "frida_hook_script" => {
            args.extend([
                "frida".into(),
                apk,
                s(a, "class").ok_or("class is required")?,
            ]);
            args.extend(s(a, "method"));
            if b(a, "live") {
                args.push("--live".into())
            }
            run_cli(&args)
        }
        "dump_app" => {
            args.extend([
                "dump".into(),
                apk,
                s(a, "out_dir").ok_or("out_dir is required")?,
            ]);
            if b(a, "attach") {
                args.push("--attach".into())
            }
            push_opt(&mut args, "--device", s(a, "device"));
            push_opt(&mut args, "--wait", n(a, "wait").map(|v| v.to_string()));
            push_opt(
                &mut args,
                "--scripts-for",
                n(a, "scripts_for").map(|v| v.to_string()),
            );
            run_cli(&args)
        }
        "il2cpp" => {
            args.extend(["il2cpp".into(), apk]);
            if let Some(Value::Array(v)) = a.get("extra_paths") {
                args.extend(v.iter().filter_map(|x| x.as_str().map(str::to_string)));
            }
            push_opt(&mut args, "--uses", s(a, "uses"));
            push_opt(&mut args, "--method", s(a, "method"));
            paging(&mut args);
            run_cli(&args)
        }
        "flutter" => {
            args.extend(["flutter".into(), apk]);
            push_opt(&mut args, "--abi", s(a, "abi"));
            for k in ["api", "strings"] {
                if b(a, k) {
                    args.push(format!("--{k}"))
                }
            }
            paging(&mut args);
            run_cli(&args)
        }
        "rename" | "comment" | "mapping" => {
            if name == "mapping" {
                args.extend([
                    "map".into(),
                    apk.clone(),
                    s(a, "direction").ok_or("direction is required")?,
                    s(a, "file").ok_or("file is required")?,
                ]);
            } else {
                let key = if name == "rename" { "new_name" } else { "text" };
                args.extend([
                    name.into(),
                    apk.clone(),
                    s(a, "target").ok_or("target is required")?,
                    // `--`: a name or comment that starts with '-' stays text
                    "--".into(),
                    s(a, key).ok_or(format!("{key} is required"))?,
                ]);
            }
            // a warm session holds the old names: drop it so the next call reloads them
            let prefix = format!("{apk}\0");
            workers.retain(|k, _| !k.starts_with(&prefix));
            run_cli(&args)
        }
        "get_smali" => {
            args.extend(["smali".into(), apk]);
            args.extend(s(a, "class"));
            if let Some(dir) = s(a, "out_dir") {
                if let Some(Value::Array(v)) = a.get("classes") {
                    args.extend(v.iter().filter_map(|x| x.as_str().map(str::to_string)));
                }
                args.extend(["--out-dir".into(), dir]);
            } else if s(a, "class").is_none() {
                return Err("class is required (or out_dir to write files)".into());
            }
            run_cli(&args)
        }
        "disassemble" => {
            args.extend(["disasm".into(), apk]);
            args.extend(s(a, "class"));
            paging(&mut args);
            run_cli(&args)
        }
        "decode_resources" => run_cli(&[
            "res".into(),
            apk,
            s(a, "out_dir").ok_or("out_dir is required")?,
        ]),
        "build_apk" => {
            args.extend([
                "build".into(),
                apk,
                s(a, "out_path").ok_or("out_path is required")?,
            ]);
            for (k, f) in [
                ("put", "--put"),
                ("delete", "--delete"),
                ("smali", "--smali"),
                ("strings", "--string"),
            ] {
                if let Some(Value::Array(v)) = a.get(k) {
                    for x in v.iter().filter_map(Value::as_str) {
                        args.extend([f.to_string(), x.to_string()]);
                    }
                }
            }
            push_opt(&mut args, "--manifest", s(a, "manifest"));
            push_opt(&mut args, "--res", s(a, "res_dir"));
            push_opt(&mut args, "--key", s(a, "key"));
            push_opt(&mut args, "--cert", s(a, "cert"));
            push_opt(&mut args, "--ks", s(a, "keystore"));
            push_opt(&mut args, "--ks-pass", s(a, "keystore_pass"));
            push_opt(&mut args, "--ks-key-pass", s(a, "key_pass"));
            push_opt(&mut args, "--ks-alias", s(a, "key_alias"));
            if b(a, "no_sign") {
                args.push("--no-sign".into())
            }
            run_cli(&args)
        }
        "consts" => {
            args.extend(["consts".into(), apk]);
            if let Some(Value::Array(v)) = a.get("classes") {
                args.extend(v.iter().filter_map(|x| x.as_str().map(str::to_string)));
            }
            push_opt(&mut args, "--value", s(a, "value"));
            push_opt(&mut args, "--name", s(a, "name"));
            paging(&mut args);
            run_cli(&args)
        }
        "returns" => {
            args.extend(["returns".into(), apk]);
            args.extend(s(a, "method"));
            push_opt(&mut args, "--impl", s(a, "impl"));
            if let Some(Value::Array(v)) = a.get("in") {
                for x in v.iter().filter_map(Value::as_str) {
                    args.extend(["--in".to_string(), x.to_string()]);
                }
            }
            push_opt(&mut args, "--value", s(a, "value"));
            paging(&mut args);
            run_cli(&args)
        }
        "size" => {
            args.extend(["size".into(), apk]);
            push_opt(&mut args, "--top", n(a, "top").map(|v| v.to_string()));
            run_cli(&args)
        }
        "decrypt_strings" => run_cli(&["decrypt".into(), apk]),
        "install_apk" => {
            args.extend(["install".into(), apk]);
            for (k, f) in [("device", "--device"), ("abi", "--abi")] {
                if let Some(v) = s(a, k) {
                    args.extend([f.into(), v]);
                }
            }
            run_cli(&args)
        }
        "scan" => {
            args.extend(["scan".into(), apk]);
            if let Some(f) = s(a, "filter") {
                args.extend(["--filter".into(), f]);
            }
            paging(&mut args);
            run_cli(&args)
        }
        "fingerprint" => {
            let mut args = vec!["fingerprint".into(), apk.clone()];
            if b(a, "strings") {
                args.push("--strings".into());
            }
            if b(a, "exodus") {
                args.push("--exodus".into());
            }
            if b(a, "all") {
                args.push("--all".into());
            }
            if b(a, "snapshot") {
                args.push("--snapshot".into());
            }
            if let Some(c) = s(a, "category") {
                args.push("--category".into());
                args.push(c);
            }
            run_cli(&args)
        }
        _ => Err(format!("unknown tool {name}")),
    }
}

/// The frida_* tools, on the one live session.
fn live_call(live: &mut Option<Live>, name: &str, a: &Value) -> Result<(String, bool), String> {
    if name == "frida_setup" {
        let out = crate::frida_setup::setup(s(a, "device").as_deref(), s(a, "push").as_deref())?;
        return Ok((out, true));
    }
    if name == "frida_start" {
        *live = None;
        let target = match (s(a, "package"), s(a, "apk_path")) {
            (Some(p), _) => p,
            (None, Some(apk)) => Some(crate::quick::package(&apk))
                .filter(|p| !p.is_empty())
                .ok_or("no package name in the APK's manifest; pass package")?,
            _ => return Err("pass apk_path or package".into()),
        };
        let l = Live::start(&target, b(a, "attach"), s(a, "device").as_deref())?;
        let text = format!("live on {target}\n{}", l.text(0, "", 50).0);
        *live = Some(l);
        return Ok((text, true));
    }
    let l = live
        .as_mut()
        .ok_or("no live session: call frida_start first")?;
    if !l.alive() && name != "frida_events" {
        return Err(format!("frida has exited:\n{}", l.text(0, "", 30).0));
    }
    match name {
        "frida_hook" if s(a, "preset").is_some() => {
            let p = s(a, "preset").unwrap_or_default();
            let js =
                crate::live::preset(&p).ok_or_else(|| format!("no preset {p}; presets: http"))?;
            l.hook(&p, js, true)?;
            Ok((
                format!(
                    "loaded preset {p}; its events have kind http (frida_events filter: http); active: {}",
                    l.hook_keys().join(", ")
                ),
                true,
            ))
        }
        "frida_hook" => {
            let class = s(a, "class").ok_or("class (or preset) is required")?;
            let method = s(a, "method");
            let mut args = vec![
                "frida".into(),
                s(a, "apk_path").ok_or("apk_path is required")?,
                class.clone(),
            ];
            args.extend(method.clone());
            args.push("--live".into());
            let (js, ok) = run_cli(&args)?;
            if !ok {
                return Ok((js, false));
            }
            let key = method.map_or(class.clone(), |m| format!("{class}#{m}"));
            l.hook(&key, &js, false)?;
            Ok((
                format!(
                    "hooked {key} ({} overloads); active: {}",
                    js.matches(".implementation").count(),
                    l.hook_keys().join(", ")
                ),
                true,
            ))
        }
        "frida_script" => {
            let key = s(a, "name").ok_or("name is required")?;
            l.hook(&key, &s(a, "js").ok_or("js is required")?, true)?;
            Ok((
                format!("loaded {key}; active: {}", l.hook_keys().join(", ")),
                true,
            ))
        }
        "frida_unhook" => {
            let n = l.unhook(&s(a, "key").ok_or("key is required")?)?;
            Ok((
                format!("removed {n}; active: {}", l.hook_keys().join(", ")),
                n > 0,
            ))
        }
        "frida_events" => {
            let since = n(a, "since").unwrap_or(0);
            let (body, next) = if b(a, "summary") {
                (l.summary(since), l.events.lock().unwrap().next)
            } else {
                l.text(
                    since,
                    &s(a, "filter").unwrap_or_default(),
                    n(a, "limit").unwrap_or(200) as usize,
                )
            };
            Ok((
                format!(
                    "next_since: {next}{}\n{body}",
                    if l.alive() {
                        ""
                    } else {
                        "  (frida has exited)"
                    }
                ),
                true,
            ))
        }
        "frida_stop" => {
            *live = None;
            Ok(("stopped".into(), true))
        }
        _ => Err(format!("unknown tool {name}")),
    }
}

/// Cut `text` at `max` characters on a line boundary, saying how to get the rest.
fn cap(text: String, max: usize) -> String {
    if text.chars().count() <= max {
        return text;
    }
    let cut: String = text.chars().take(max).collect();
    let cut = cut
        .rfind('\n')
        .map_or(cut.as_str(), |k| &cut[..k])
        .to_string();
    format!(
        "{cut}\n\n[truncated at {max} of {} characters: narrow the query, use limit/offset, or raise max_chars]",
        text.chars().count()
    )
}

pub fn serve() -> Result<(), String> {
    let mut workers: HashMap<String, Worker> = HashMap::new();
    let mut live: Option<Live> = None;
    let stdin = std::io::stdin();
    let mut out = std::io::stdout().lock();
    for line in stdin.lock().lines() {
        let line = line.map_err(|e| e.to_string())?;
        if line.trim().is_empty() {
            continue;
        }
        let msg: Value = match serde_json::from_str(&line) {
            Ok(v) => v,
            Err(e) => {
                let _ = writeln!(
                    out,
                    "{}",
                    json!({"jsonrpc": "2.0", "id": null, "error": {"code": -32700, "message": e.to_string()}})
                );
                continue;
            }
        };
        // notifications get no reply
        let Some(id) = msg.get("id").cloned() else {
            continue;
        };
        let method = msg["method"].as_str().unwrap_or_default();
        let params = &msg["params"];
        let reply = match method {
            "initialize" => Ok(json!({
                "protocolVersion": params["protocolVersion"].as_str().unwrap_or(PROTOCOL),
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "apkscope", "version": crate::upgrade::identity().version},
                "instructions": "apkscope reads, patches, rebuilds, signs and installs Android APKs by itself: no apktool, smali.jar, baksmali, jadx, zipalign or apksigner needed. Read: start with apk_info, then find_refs / list_classes / search to locate code, then decompile only the classes (or one method) you need. Patch: get_smali (one class as text, or out_dir for the whole app as .smali files) and/or decode_resources, edit, then build_apk (smali files or the folder) (assembles the smali into the right DEX, zipaligns, signs; with no edits it re-signs), verify_signature, install_apk. Check it live: frida_setup, frida_start, frida_hook. Also built in: security scan (scan), the app's HTTP API / URLs / secrets / server config (search scopes api, urls, secrets, config), constants and message ids (consts, returns), callers / call graphs / field access, string decryption (decrypt_strings), version diffs (diff_apks), size, Unity IL2CPP and Flutter apps, React Native / Hermes bundle strings, packed apps (dump_app), renames and comments with JADX / Enigma / ProGuard mappings (rename, comment, mapping), a full Gradle export (export_project). Before reaching for another tool, check this list and the tool descriptions. Calls on the same APK get faster after the first ones: a warm session loads in the background (pass cache: false to opt out)."
            })),
            "ping" => Ok(json!({})),
            "tools/list" => Ok(json!({"tools": tools()})),
            "tools/call" => {
                let name = params["name"].as_str().unwrap_or_default();
                let args = params.get("arguments").cloned().unwrap_or(json!({}));
                let max = n(&args, "max_chars").map_or(MAX_CHARS, |m| m as usize);
                let res = if name.starts_with("frida_") && name != "frida_hook_script" {
                    live_call(&mut live, name, &args)
                } else {
                    call(&mut workers, name, &args)
                };
                let (text, ok) = res.unwrap_or_else(|e| (e, false));
                Ok(json!({"content": [{"type": "text", "text": cap(text, max)}], "isError": !ok}))
            }
            _ => Err(json!({"code": -32601, "message": format!("method not found: {method}")})),
        };
        let msg = match reply {
            Ok(r) => json!({"jsonrpc": "2.0", "id": id, "result": r}),
            Err(e) => json!({"jsonrpc": "2.0", "id": id, "error": e}),
        };
        let _ = writeln!(out, "{msg}");
        let _ = out.flush();
    }
    Ok(())
}

/// `apkscope worker <apk>`: keeps one APK warm and answers one JSON request per line
/// (`["refs", kind, query, flags...]`, `["search", scope, query, flags...]`,
/// `["decompile", class..., flags]`, `["info"]`, `["resource", path]`) with
/// `{"ok": bool, "text": "..."}`. The raw DEX files load first (enough for refs, well under a
/// second); the full session builds in the background, and until it is there requests that
/// need it get `{"busy": true}` (search waits for it instead).
pub fn worker(apk: &str, deobf: bool) -> Result<(), String> {
    let files = crate::quick::scan(apk, |l| {
        l.all()?;
        Ok((std::mem::take(&mut l.name), std::mem::take(&mut l.buf)))
    })?;
    let dexes: Vec<(String, crate::dex::Dex)> = files
        .iter()
        .filter_map(|(n, b)| Some((n.clone(), crate::dex::Dex::parse(b).ok()?)))
        .collect();
    let state: std::sync::Arc<std::sync::OnceLock<Result<crate::session::State, String>>> =
        Default::default();
    let (bg, path) = (state.clone(), apk.to_string());
    std::thread::Builder::new()
        .stack_size(256 << 20)
        .spawn(move || {
            let _ = bg.set(crate::load(&path, deobf));
        })
        .map_err(|e| e.to_string())?;
    // an idle session holds the whole APK in memory: give it back after IDLE_SECS unused
    static LAST: AtomicU64 = AtomicU64::new(0);
    let start = Instant::now();
    std::thread::spawn(move || {
        loop {
            std::thread::sleep(std::time::Duration::from_secs(30));
            if start.elapsed().as_secs().saturating_sub(LAST.load(Relaxed)) > IDLE_SECS {
                std::process::exit(0);
            }
        }
    });
    let mut out = std::io::stdout().lock();
    let _ = writeln!(out, "{}", json!({"ready": true}));
    let _ = out.flush();
    for line in std::io::stdin().lock().lines() {
        let line = line.map_err(|e| e.to_string())?;
        // never idle while a request runs, however long it takes
        LAST.store(u64::MAX, Relaxed);
        let req: Vec<String> = serde_json::from_str(&line).unwrap_or_default();
        let kind = req.first().map(String::as_str).unwrap_or_default();
        let st = match kind {
            "refs" => None,
            "search" => Some(state.wait()),
            _ => match state.get() {
                Some(s) => Some(s),
                None => {
                    LAST.store(start.elapsed().as_secs(), Relaxed);
                    let _ = writeln!(out, "{}", json!({"ok": false, "busy": true}));
                    let _ = out.flush();
                    continue;
                }
            },
        };
        let res: Result<String, String> = (|| {
            if kind == "refs" {
                let mut r = req[1..].to_vec();
                let json = crate::flag(&mut r, "--json");
                let limit =
                    crate::num(crate::opt(&mut r, &["--limit"])?, "--limit")?.unwrap_or(usize::MAX);
                let offset =
                    crate::num(crate::opt(&mut r, &["--offset"])?, "--offset")?.unwrap_or(0);
                let (q, java) = crate::refs_query(r)?;
                let hits = crate::quick::refs_loaded(&dexes, &q, offset.saturating_add(limit))?;
                let hits = &hits[offset.min(hits.len())..];
                // Java context needs the session's decompiler (whole-APK names, disk cache)
                let st = if java {
                    Some(state.wait().as_ref()?)
                } else {
                    None
                };
                let java_of = |owners: &[String]| -> Vec<(String, Option<String>)> {
                    owners
                        .iter()
                        .map(|o| {
                            (
                                o.clone(),
                                st.and_then(|st| {
                                    st.class_text(
                                        &format!(
                                            "{};",
                                            o.trim_end_matches(';').split('$').next().unwrap_or(o)
                                        ),
                                        false,
                                    )
                                }),
                            )
                        })
                        .collect()
                };
                let text =
                    crate::refs_text(&q, hits, json, if java { Some(&java_of) } else { None })?;
                return Ok(format!("{text}[{} refs]", hits.len()));
            }
            let st = st.expect("needs the session").as_ref()?;
            match kind {
                "search" => {
                    let a = crate::search_args(&req[1..])?;
                    let (text, hits, note) = crate::search_on(st, &a, &a.pos)?;
                    Ok(format!("{text}\n[{hits} hits. {note}]"))
                }
                "decompile" => {
                    let mut r = req[1..].to_vec();
                    let method = crate::opt(&mut r, &["--method"])?;
                    let smali = crate::flag(&mut r, "--smali");
                    let mut text = String::new();
                    for c in &r {
                        let t = st
                            .class_text(c, smali)
                            .ok_or_else(|| format!("class {c} not found"))?;
                        match &method {
                            Some(m) => {
                                text += &crate::quick::method_of(&t, m)
                                    .ok_or_else(|| format!("method {m} not found in {c}"))?
                            }
                            None => text += &t,
                        }
                        text.push('\n');
                    }
                    Ok(text)
                }
                "info" => Ok(crate::session::overview(st)),
                "resource" => st
                    .target_text(req.get(1).map_or("", |s| s))
                    .ok_or_else(|| "resource not found".to_string()),
                _ => Err(format!("unknown request {line}")),
            }
        })();
        let (ok, text) = match res {
            Ok(t) => (true, t),
            Err(e) => (false, e),
        };
        LAST.store(start.elapsed().as_secs(), Relaxed);
        let _ = writeln!(out, "{}", json!({"ok": ok, "text": text}));
        let _ = out.flush();
    }
    Ok(())
}

#[cfg(test)]
#[path = "../tests/apkscope/mcp.rs"]
mod tests;
