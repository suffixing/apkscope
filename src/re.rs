//! Reverse-engineering helpers on top of the DEX reader: callers/callees and call graphs,
//! field reads/writes, Frida hook scripts, a security quick-scan, string-decryptor evaluation,
//! and the per-APK project file (the user's renames and comments, JADX/Enigma mappings).

use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::fmt::Write as _;
use std::rc::Rc;

use crate::bytecode::{self, Ref};
use crate::deobf::Notes;
use crate::dex::{self, Dex};

// ---------- members and cross-references ----------

/// `a.b.C` / `La/b/C;` -> `La/b/C;`
pub fn desc(class: &str) -> String {
    if class.starts_with('L') && class.ends_with(';') { class.to_string() } else { format!("L{};", class.replace('.', "/")) }
}

/// Whether `owner` is `top` or one of its nested classes.
fn in_class(owner: &str, top: &str) -> bool {
    owner == top || owner.strip_prefix(top.trim_end_matches(';')).is_some_and(|r| r.starts_with('$'))
}

/// Methods referenced by `(class, name)`: `name` None = every method of the class (and its nested classes).
/// Returns per DEX the wanted method ids.
fn wanted_methods(dx: &Dex, top: &str, name: Option<&str>) -> HashSet<u32> {
    let mut out = HashSet::new();
    for id in 0..dx.counts()[3] as u32 {
        if let Ok((c, n, _)) = dx.method_parts(id) {
            if in_class(&c, top) && name.is_none_or(|w| w == n) {
                out.insert(id);
            }
        }
    }
    out
}

/// Every method in the APK that calls a method `name` of `class` (or any of its methods).
/// Rows: (caller, callee).
pub fn callers(dexes: &[Dex], class: &str, name: Option<&str>) -> Vec<(String, String)> {
    let top = desc(class);
    let mut out = Vec::new();
    for dx in dexes {
        let want = wanted_methods(dx, &top, name);
        if want.is_empty() {
            continue;
        }
        for c in 0..dx.class_count {
            let _ = dx.each_method(c, |m, insns| {
                let Some(insns) = insns else { return };
                let mut seen = HashSet::new();
                bytecode::for_each_ref(insns, |r, idx| {
                    if r == Ref::Method && want.contains(&idx) && seen.insert(idx) {
                        out.push((dx.method_ref(m).unwrap_or_default(), dx.method_ref(idx).unwrap_or_default()));
                    }
                });
            });
        }
    }
    out.sort();
    out.dedup();
    out
}

/// Methods called by the methods `name` of `class` (all of them for None), in call order.
/// Rows: (caller, callee).
pub fn callees(dexes: &[Dex], class: &str, name: Option<&str>) -> Vec<(String, String)> {
    let top = desc(class);
    let mut out = Vec::new();
    for dx in dexes {
        for c in 0..dx.class_count {
            let Ok(owner) = dx.class_descriptor(c) else { continue };
            if !in_class(&owner, &top) {
                continue;
            }
            let _ = dx.each_method(c, |m, insns| {
                let (Some(insns), Ok((_, n, _))) = (insns, dx.method_parts(m)) else { return };
                if name.is_some_and(|w| w != n) {
                    return;
                }
                let mut seen = HashSet::new();
                bytecode::for_each_ref(insns, |r, idx| {
                    if r == Ref::Method && seen.insert(idx) {
                        out.push((dx.method_ref(m).unwrap_or_default(), dx.method_ref(idx).unwrap_or_default()));
                    }
                });
            });
        }
    }
    out
}

/// Code of the method `La/b;->name(...)` named by a method ref, if the APK defines it.
fn find_code<'a>(dexes: &'a [Dex<'a>], mref: &str) -> Option<(&'a Dex<'a>, u32, &'a [u8])> {
    let (cls, _) = mref.split_once("->")?;
    for dx in dexes {
        let Some(c) = dx.find_class(cls) else { continue };
        let data = dx.class_data(c).ok()?;
        for m in data.methods {
            if dx.method_ref(m.method_idx).ok().as_deref() == Some(mref) {
                return Some((dx, m.method_idx, m.code?.insns));
            }
        }
    }
    None
}

/// Callee tree of the method(s) `name` of `class`, following calls into code the APK defines,
/// `depth` levels deep, plus who calls it. Library calls are leaves; repeats are marked.
pub fn call_graph(dexes: &[Dex], class: &str, name: Option<&str>, depth: usize) -> String {
    let mut o = String::new();
    let roots: Vec<String> = {
        let mut r: Vec<String> = callees(dexes, class, name).into_iter().map(|x| x.0).collect();
        r.dedup();
        r
    };
    let _ = writeln!(o, "// Callers");
    let calls = callers(dexes, class, name);
    if calls.is_empty() {
        let _ = writeln!(o, "//   (none found: entry point, reflection, JNI or framework callback)");
    }
    for (from, to) in &calls {
        let _ = writeln!(o, "{from}\n    -> {to}");
    }
    let _ = writeln!(o, "\n// Calls (depth {depth}; [lib] = not in this APK, [seen] = expanded above)");
    let mut seen = HashSet::new();
    fn walk(dexes: &[Dex], m: &str, d: usize, max: usize, seen: &mut HashSet<String>, o: &mut String) {
        let pad = "    ".repeat(d);
        let Some((dx, _, insns)) = find_code(dexes, m) else {
            let _ = writeln!(o, "{pad}{m}  [lib]");
            return;
        };
        if !seen.insert(m.to_string()) {
            let _ = writeln!(o, "{pad}{m}  [seen]");
            return;
        }
        let _ = writeln!(o, "{pad}{m}");
        if d >= max {
            return;
        }
        let mut kids = Vec::new();
        bytecode::for_each_ref(insns, |r, idx| {
            if r == Ref::Method {
                if let Ok(s) = dx.method_ref(idx) {
                    if !kids.contains(&s) {
                        kids.push(s);
                    }
                }
            }
        });
        for k in kids {
            walk(dexes, &k, d + 1, max, seen, o);
        }
    }
    for r in &roots {
        walk(dexes, r, 0, depth, &mut seen, &mut o);
    }
    if roots.is_empty() {
        let _ = writeln!(o, "// no method with code found for {class}{}", name.map(|n| format!("->{n}")).unwrap_or_default());
    }
    o
}

/// Who reads and who writes field `name` of `class`. Rows: (method, field, is_write).
pub fn field_access(dexes: &[Dex], class: &str, name: &str) -> Vec<(String, String, bool)> {
    let top = desc(class);
    let mut out = Vec::new();
    for dx in dexes {
        let want: HashSet<u32> = (0..dx.counts()[2] as u32).filter(|&f| dx.field_parts(f).is_ok_and(|(c, _, n)| c == top && n == name)).collect();
        if want.is_empty() {
            continue;
        }
        for c in 0..dx.class_count {
            let _ = dx.each_method(c, |m, insns| {
                let Some(insns) = insns else { return };
                let mut hit = false;
                bytecode::for_each_ref(insns, |r, idx| hit |= r == Ref::Field && want.contains(&idx));
                if !hit {
                    return;
                }
                let Ok(code) = bytecode::decode(insns) else { return };
                let mut seen = HashSet::new();
                for i in code.iter().filter(|i| matches!(i.op, 0x52..=0x6d) && want.contains(&i.idx)) {
                    // iput 59-5f, sput 67-6d
                    let write = matches!(i.op, 0x59..=0x5f | 0x67..=0x6d);
                    if seen.insert((i.idx, write)) {
                        out.push((dx.method_ref(m).unwrap_or_default(), dx.field_ref(i.idx).unwrap_or_default(), write));
                    }
                }
            });
        }
    }
    out.sort();
    out
}

// ---------- Frida ----------

/// Descriptor -> the type name Frida's `overload()` wants.
fn frida_type(t: &str) -> String {
    match t {
        "I" => "int", "Z" => "boolean", "B" => "byte", "S" => "short", "C" => "char", "J" => "long", "F" => "float", "D" => "double", "V" => "void",
        _ if t.starts_with('[') => return t.replace('/', "."),
        _ => return t.trim_start_matches('L').trim_end_matches(';').replace('/', "."),
    }
    .to_string()
}

/// A ready-to-run Frida script hooking every overload of `name` in `class` (all methods for None):
/// logs arguments, return value and exceptions, then calls the original.
pub fn frida(dexes: &[Dex], class: &str, name: Option<&str>) -> Result<String, String> {
    let d = desc(class);
    let (dx, c) = dexes.iter().find_map(|dx| dx.find_class(&d).map(|c| (dx, c))).ok_or_else(|| format!("class {class} not found"))?;
    let java = d.trim_start_matches('L').trim_end_matches(';').replace('/', ".");
    let mut o = format!("// frida -U -f <package> -l hook.js\nJava.perform(() => {{\n    const C = Java.use(\"{java}\");\n");
    let mut n = 0;
    for m in dx.class_data(c)?.methods {
        let (_, mname, proto) = dx.method_parts(m.method_idx)?;
        if mname == "<clinit>" || name.is_some_and(|w| w != mname && !(w == "<init>" && mname == "<init>")) || m.access & 0x1000 != 0 && name.is_none() {
            continue;
        }
        let (ret, params) = dx.proto_parts(proto)?;
        let js = if mname == "<init>" { "$init".to_string() } else { mname.clone() };
        let args: Vec<String> = (0..params.len()).map(|k| format!("a{k}")).collect();
        let types: Vec<String> = params.iter().map(|p| format!("\"{}\"", frida_type(p))).collect();
        let a = args.join(", ");
        let shown = args.iter().map(|x| format!("${{{x}}}")).collect::<Vec<_>>().join(", ");
        let _ = write!(
            o,
            "    C[\"{js}\"].overload({}).implementation = function ({a}) {{\n        console.log(`[call] {java}.{mname}({shown})`);\n        try {{\n            const r = this[\"{js}\"].overload({}).call(this{}{a});\n{}            return r;\n        }} catch (e) {{\n            console.log(`[throw] {java}.{mname}: ${{e}}`);\n            throw e;\n        }}\n    }};\n",
            types.join(", "),
            types.join(", "),
            if args.is_empty() { "" } else { ", " },
            if ret == "V" { String::new() } else { format!("            console.log(`[ret]  {java}.{mname} -> ${{r}}`);\n") },
        );
        n += 1;
    }
    if n == 0 {
        return Err(format!("no method {} in {class}", name.unwrap_or("")));
    }
    o += "});\n";
    Ok(o)
}

// ---------- security quick-scan ----------

/// (API method ref prefix, what it means). Matched against every call in the APK.
const RISKY_CALLS: &[(&str, &str)] = &[
    ("Landroid/webkit/WebView;->addJavascriptInterface", "WebView JS bridge: page JavaScript can call into Java"),
    ("Landroid/webkit/WebSettings;->setJavaScriptEnabled", "WebView JavaScript enabled"),
    ("Landroid/webkit/WebSettings;->setAllowFileAccess", "WebView file:// access setting"),
    ("Landroid/webkit/WebSettings;->setAllowUniversalAccessFromFileURLs", "WebView: file URLs may read any origin"),
    ("Landroid/webkit/WebSettings;->setAllowFileAccessFromFileURLs", "WebView: file URLs may read other files"),
    ("Landroid/webkit/SslErrorHandler;->proceed", "TLS errors ignored in a WebView"),
    ("Ljavax/net/ssl/HttpsURLConnection;->setDefaultHostnameVerifier", "global hostname verifier replaced"),
    ("Ljavax/net/ssl/HttpsURLConnection;->setHostnameVerifier", "custom hostname verifier"),
    ("Ljava/lang/Runtime;->exec", "runs shell commands"),
    ("Ldalvik/system/DexClassLoader;-><init>", "loads code at runtime"),
    ("Ldalvik/system/InMemoryDexClassLoader;-><init>", "loads code from memory"),
    ("Ljava/lang/System;->loadLibrary", "loads a native library"),
    ("Landroid/content/Context;->openFileOutput", "writes app files (check the mode)"),
    ("Landroid/database/sqlite/SQLiteDatabase;->rawQuery", "raw SQL (check for injection)"),
    ("Landroid/database/sqlite/SQLiteDatabase;->execSQL", "raw SQL (check for injection)"),
    ("Ljava/util/Random;-><init>", "java.util.Random (not for keys or tokens)"),
    ("Ljava/security/SecureRandom;->setSeed", "SecureRandom seeded by the app"),
    ("Landroid/os/Environment;->getExternalStorageDirectory", "external storage (readable by other apps on old Android)"),
    ("Landroid/content/ClipboardManager;->setPrimaryClip", "writes the clipboard"),
    ("Landroid/telephony/TelephonyManager;->getDeviceId", "reads the device IMEI"),
    ("Landroid/util/Log;->", "logging (may leak data to logcat)"),
];

/// Strings that name weak crypto when passed to Cipher/MessageDigest.
const WEAK_CRYPTO: &[(&str, &str)] = &[
    ("^(?i)(DES|DESede|RC4|ARCFOUR|Blowfish)(/.*)?$", "weak cipher"),
    ("^(?i)AES$|^(?i)[A-Z0-9]+/ECB/", "ECB mode (AES alone defaults to ECB)"),
    ("^(?i)(MD5|MD4|SHA-?1)$", "weak hash"),
    ("^(?i)SSL(v3)?$|^(?i)TLSv1(\\.1)?$", "old TLS/SSL protocol"),
];

/// Classes that implement the TLS trust interfaces (often to accept every certificate).
const TRUST_IFACES: &[(&str, &str)] = &[
    ("Ljavax/net/ssl/X509TrustManager;", "custom X509TrustManager (check checkServerTrusted is not empty)"),
    ("Ljavax/net/ssl/HostnameVerifier;", "custom HostnameVerifier (check verify() does not return true)"),
];

/// Security quick-scan: manifest flags and exported components (from the overview), risky APIs,
/// weak crypto, trust-all TLS, and the key/secret and URL search hits.
pub fn scan(st: &crate::session::State) -> String {
    let dexes = &st.dexes;
    let mut o = String::from("// apkscope security quick-scan. Findings are leads, not verdicts: check each one in the code.\n\n");
    o += &crate::session::overview(st);
    // risky calls
    let mut calls: Vec<(&str, &str, String)> = Vec::new();
    let weak: Vec<(regex::Regex, &str)> = WEAK_CRYPTO.iter().map(|(p, w)| (regex::Regex::new(p).unwrap(), *w)).collect();
    let mut crypto: Vec<(String, &str, String)> = Vec::new();
    let mut trust: Vec<(String, &str)> = Vec::new();
    for dx in dexes {
        let risky: HashMap<u32, usize> = (0..dx.counts()[3] as u32)
            .filter_map(|id| {
                let r = dx.method_ref(id).ok()?;
                RISKY_CALLS.iter().position(|(p, _)| r.starts_with(p)).map(|k| (id, k))
            })
            .collect();
        let weak_strs: HashMap<u32, usize> = (0..dx.counts()[0] as u32)
            .filter_map(|id| {
                let s = dx.string(id).ok()?;
                weak.iter().position(|(re, _)| re.is_match(&s)).map(|k| (id, k))
            })
            .collect();
        for c in 0..dx.class_count {
            if let Ok(def) = dx.class_def(c) {
                for (iface, what) in TRUST_IFACES {
                    if def.interfaces.iter().any(|i| i == iface) {
                        trust.push((dex::java_name(&def.class), what));
                    }
                }
            }
            let _ = dx.each_method(c, |m, insns| {
                let Some(insns) = insns else { return };
                let (mut strs, mut uses_crypto) = (Vec::new(), false);
                bytecode::for_each_ref(insns, |r, idx| match r {
                    Ref::Method => {
                        if let Some(&k) = risky.get(&idx) {
                            calls.push((RISKY_CALLS[k].1, RISKY_CALLS[k].0, dx.method_ref(m).unwrap_or_default()));
                        }
                        uses_crypto |= dx.method_ref(idx).is_ok_and(|r| r.starts_with("Ljavax/crypto/Cipher;->getInstance") || r.starts_with("Ljava/security/MessageDigest;->getInstance") || r.starts_with("Ljavax/net/ssl/SSLContext;->getInstance"));
                    }
                    Ref::String => {
                        if let Some(&k) = weak_strs.get(&idx) {
                            strs.push((k, idx));
                        }
                    }
                    _ => {}
                });
                if uses_crypto {
                    for (k, s) in strs {
                        crypto.push((dx.string(s).unwrap_or_default(), weak[k].1, dx.method_ref(m).unwrap_or_default()));
                    }
                }
            });
        }
    }
    let _ = writeln!(o, "\n// weak crypto ({})", crypto.len());
    for (s, what, at) in &crypto {
        let _ = writeln!(o, "{what:<38}\"{s}\"    in {at}");
    }
    let _ = writeln!(o, "\n// TLS trust overrides ({})", trust.len());
    for (c, what) in &trust {
        let _ = writeln!(o, "{c}    {what}");
    }
    calls.sort();
    calls.dedup();
    let _ = writeln!(o, "\n// risky APIs ({} call sites)", calls.len());
    let mut last = "";
    let mut shown = 0;
    for (what, api, at) in &calls {
        if *what != last {
            let total = calls.iter().filter(|c| c.0 == *what).count();
            let _ = writeln!(o, "{what}  [{api}]  {total} site{}", if total == 1 { "" } else { "s" });
            last = what;
            shown = 0;
        }
        // logging and Random are everywhere: a few examples are enough
        if shown < 8 {
            let _ = writeln!(o, "    {at}");
        } else if shown == 8 {
            let _ = writeln!(o, "    ...");
        }
        shown += 1;
    }
    if st.index.get().is_none() {
        st.build_index();
    }
    for (scope, title) in [(crate::session::Scope::Secrets, "keys & secrets"), (crate::session::Scope::Urls, "URLs")] {
        let Ok(mut m) = crate::session::Matcher::new("", scope, false, false) else { continue };
        m.app_only = true;
        let hits = crate::session::search(st, &m, &Default::default());
        let _ = writeln!(o, "\n// {title} in app code ({})", hits.len());
        for (c, line, text) in hits.iter().take(200) {
            let _ = writeln!(o, "{c}:{line}    {}", text.trim());
        }
        if hits.len() > 200 {
            let _ = writeln!(o, "... {} more (apkscope search <apk> {})", hits.len() - 200, title.split(' ').next().unwrap_or("").to_lowercase());
        }
    }
    o
}

// ---------- string decryption ----------

#[derive(Clone, Debug)]
enum V {
    Int(i64),
    Null,
    Str(Rc<Vec<u16>>),
    /// array of primitives (chars, bytes, ints, longs) or strings
    Arr(Rc<RefCell<Vec<V>>>),
    Sb(Rc<RefCell<Vec<u16>>>),
    /// `new String` / `new StringBuilder` waiting for its constructor
    Fresh,
}

impl V {
    fn int(&self) -> Option<i64> {
        if let V::Int(v) = self { Some(*v) } else { None }
    }
}

const MAX_STEPS: usize = 300_000;

struct Vm<'a> {
    dexes: &'a [Dex<'a>],
    steps: usize,
    /// (dex pointer, field idx) -> value, filled by running `<clinit>` on first use
    statics: HashMap<(usize, u32), V>,
    inited: HashSet<String>,
}

fn utf16(s: &str) -> Rc<Vec<u16>> {
    Rc::new(s.encode_utf16().collect())
}

fn base64(s: &[u16], flags: i64) -> Option<Vec<V>> {
    let url = flags & 8 != 0;
    let mut bits = 0u32;
    let mut n = 0;
    let mut out = Vec::new();
    for &c in s {
        let v = match c as u8 {
            b'A'..=b'Z' => c as u32 - 65,
            b'a'..=b'z' => c as u32 - 71,
            b'0'..=b'9' => c as u32 + 4,
            b'+' if !url => 62,
            b'/' if !url => 63,
            b'-' if url => 62,
            b'_' if url => 63,
            b'=' | b'\n' | b'\r' | b' ' => continue,
            _ => return None,
        };
        bits = bits << 6 | v;
        n += 6;
        if n >= 8 {
            n -= 8;
            out.push(V::Int((bits >> n) as u8 as i8 as i64));
        }
    }
    Some(out)
}

impl<'a> Vm<'a> {
    fn dex_key(dx: &Dex) -> usize {
        dx.bytes().as_ptr() as usize
    }

    /// Run `<clinit>` of `cls` once, after seeding its static initial values.
    fn init_class(&mut self, cls: &str, depth: usize) -> Option<()> {
        if !self.inited.insert(cls.to_string()) {
            return Some(());
        }
        let dexes = self.dexes;
        let (dx, c) = dexes.iter().find_map(|dx| dx.find_class(cls).map(|c| (dx, c)))?;
        let data = dx.class_data(c).ok()?;
        let vals = dx.static_values(c).unwrap_or_default();
        let key = Self::dex_key(dx);
        for (k, (f, acc)) in data.fields.iter().enumerate() {
            if acc & 0x8 == 0 {
                break;
            }
            let v = match vals.get(k) {
                Some(dex::Value::Int(i, _)) => V::Int(*i),
                Some(dex::Value::Bool(b)) => V::Int(*b as i64),
                Some(dex::Value::Str(s)) => V::Str(utf16(&dx.string(*s).ok()?)),
                Some(dex::Value::Null) | None => match dx.field_parts(*f).ok()?.1.as_bytes()[0] {
                    b'L' | b'[' => V::Null,
                    _ => V::Int(0),
                },
                _ => V::Null,
            };
            self.statics.insert((key, *f), v);
        }
        if let Some(m) = data.methods.iter().find(|m| dx.method_parts(m.method_idx).is_ok_and(|p| p.1 == "<clinit>")) {
            self.run(dx, m.code.as_ref()?, vec![], depth + 1, true)?;
        }
        Some(())
    }

    fn static_field(&mut self, dx: &Dex, f: u32, depth: usize) -> Option<V> {
        let (cls, _, name) = dx.field_parts(f).ok()?;
        self.init_class(&cls, depth)?;
        // the field id may come from another DEX than the class: match by name
        let key = Self::dex_key(dx);
        if let Some(v) = self.statics.get(&(key, f)) {
            return Some(v.clone());
        }
        let dexes = self.dexes;
        dexes.iter().find_map(|d2| {
            let k2 = Self::dex_key(d2);
            self.statics.iter().find(|((k, f2), _)| *k == k2 && d2.field_parts(*f2).is_ok_and(|(c, _, n)| c == cls && n == name)).map(|x| x.1.clone())
        })
    }

    /// Library calls the evaluator understands; None = unknown (give up).
    fn builtin(&mut self, r: &str, a: &[V]) -> Option<Option<V>> {
        let s = |k: usize| if let Some(V::Str(s)) = a.get(k) { Some(s.clone()) } else { None };
        let arr = |k: usize| if let Some(V::Arr(x)) = a.get(k) { Some(x.borrow().iter().map(|v| v.int()).collect::<Option<Vec<i64>>>()) } else { None }.flatten();
        let i = |k: usize| a.get(k).and_then(V::int);
        let bytes_to = |b: Vec<i64>| -> Rc<Vec<u16>> { utf16(&String::from_utf8_lossy(&b.iter().map(|&x| x as u8).collect::<Vec<u8>>())) };
        let chars = |v: &[u16]| V::Arr(Rc::new(RefCell::new(v.iter().map(|&c| V::Int(c as i64)).collect())));
        let sb = |k: usize| if let Some(V::Sb(x)) = a.get(k) { Some(x.clone()) } else { None };
        Some(match r {
            "Ljava/lang/String;->toCharArray()[C" => Some(chars(&s(0)?)),
            "Ljava/lang/String;->length()I" => Some(V::Int(s(0)?.len() as i64)),
            "Ljava/lang/String;->charAt(I)C" => Some(V::Int(*s(0)?.get(i(1)? as usize)? as i64)),
            "Ljava/lang/String;->intern()Ljava/lang/String;" | "Ljava/lang/String;->toString()Ljava/lang/String;" => Some(V::Str(s(0)?)),
            "Ljava/lang/String;->getBytes()[B" | "Ljava/lang/String;->getBytes(Ljava/lang/String;)[B" | "Ljava/lang/String;->getBytes(Ljava/nio/charset/Charset;)[B" => {
                Some(V::Arr(Rc::new(RefCell::new(String::from_utf16_lossy(&s(0)?).bytes().map(|b| V::Int(b as i8 as i64)).collect()))))
            }
            "Ljava/lang/String;->substring(I)Ljava/lang/String;" => Some(V::Str(Rc::new(s(0)?.get(i(1)? as usize..)?.to_vec()))),
            "Ljava/lang/String;->substring(II)Ljava/lang/String;" => Some(V::Str(Rc::new(s(0)?.get(i(1)? as usize..i(2)? as usize)?.to_vec()))),
            "Ljava/lang/String;->valueOf([C)Ljava/lang/String;" | "Ljava/lang/String;->copyValueOf([C)Ljava/lang/String;" => Some(V::Str(Rc::new(arr(0)?.iter().map(|&c| c as u16).collect()))),
            "Ljava/lang/String;->valueOf(C)Ljava/lang/String;" => Some(V::Str(Rc::new(vec![i(0)? as u16]))),
            "Ljava/lang/String;->valueOf(I)Ljava/lang/String;" => Some(V::Str(utf16(&(i(0)? as i32).to_string()))),
            "Landroid/util/Base64;->decode(Ljava/lang/String;I)[B" => Some(V::Arr(Rc::new(RefCell::new(base64(&s(0)?, i(1)?)?)))),
            "Landroid/util/Base64;->decode([BI)[B" => Some(V::Arr(Rc::new(RefCell::new(base64(&arr(0)?.iter().map(|&c| c as u16).collect::<Vec<_>>(), i(1)?)?)))),
            "Ljava/lang/Math;->abs(I)I" => Some(V::Int((i(0)? as i32).wrapping_abs() as i64)),
            "Ljava/lang/Integer;->parseInt(Ljava/lang/String;)I" => Some(V::Int(String::from_utf16_lossy(&s(0)?).parse::<i32>().ok()? as i64)),
            "Ljava/lang/Object;-><init>()V" => None,
            _ => {
                let (cls, rest) = r.split_once("->")?;
                let is_sb = cls == "Ljava/lang/StringBuilder;" || cls == "Ljava/lang/StringBuffer;";
                if cls == "Ljava/lang/String;" && rest.starts_with("<init>") {
                    // constructors replace the receiver: handled by the caller through Fresh
                    let v = match rest {
                        "<init>([C)V" => Rc::new(arr(1)?.iter().map(|&c| c as u16).collect()),
                        "<init>([CII)V" => Rc::new(arr(1)?.get(i(2)? as usize..(i(2)? + i(3)?) as usize)?.iter().map(|&c| c as u16).collect()),
                        "<init>([B)V" | "<init>([BLjava/lang/String;)V" | "<init>([BLjava/nio/charset/Charset;)V" => bytes_to(arr(1)?),
                        "<init>(Ljava/lang/String;)V" => s(1)?,
                        _ => return None,
                    };
                    return Some(Some(V::Str(v)));
                }
                if !is_sb {
                    return None;
                }
                match rest {
                    "<init>()V" | "<init>(I)V" => Some(V::Sb(Rc::new(RefCell::new(vec![])))),
                    "<init>(Ljava/lang/String;)V" => Some(V::Sb(Rc::new(RefCell::new(s(1)?.to_vec())))),
                    _ if rest.starts_with("append(") => {
                        let b = sb(0)?;
                        match &rest[7..rest.find(')')?] {
                            "C" => b.borrow_mut().push(i(1)? as u16),
                            "Ljava/lang/String;" | "Ljava/lang/CharSequence;" => b.borrow_mut().extend(s(1)?.iter()),
                            "I" => b.borrow_mut().extend(((i(1)? as i32).to_string()).encode_utf16()),
                            "[C" => b.borrow_mut().extend(arr(1)?.iter().map(|&c| c as u16)),
                            _ => return None,
                        }
                        Some(V::Sb(b))
                    }
                    "toString()Ljava/lang/String;" => Some(V::Str(Rc::new(sb(0)?.borrow().clone()))),
                    "length()I" => Some(V::Int(sb(0)?.borrow().len() as i64)),
                    "charAt(I)C" => Some(V::Int(*sb(0)?.borrow().get(i(1)? as usize)? as i64)),
                    "reverse()Ljava/lang/StringBuilder;" | "reverse()Ljava/lang/StringBuffer;" => {
                        let b = sb(0)?;
                        b.borrow_mut().reverse();
                        Some(V::Sb(b))
                    }
                    _ => return None,
                }
            }
        })
    }

    /// Interpret one method. `clinit` allows static writes (only while initialising a class).
    fn run(&mut self, dx: &Dex, code: &dex::Code, args: Vec<V>, depth: usize, clinit: bool) -> Option<Option<V>> {
        if depth > 8 {
            return None;
        }
        let insns = bytecode::decode(code.insns).ok()?;
        let units: Vec<u16> = code.insns.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
        let at: HashMap<u32, usize> = insns.iter().enumerate().map(|(k, i)| (i.off, k)).collect();
        let mut r = vec![V::Null; code.registers as usize];
        let first = (code.registers - code.ins) as usize;
        // wide arguments take two registers; values sit in the first
        let mut slot = first;
        for v in args {
            *r.get_mut(slot)? = v;
            slot += 1;
        }
        let mut res = V::Null;
        let mut pc = 0usize;
        let u32_at = |o: usize| -> Option<u32> { Some(*units.get(o)? as u32 | (*units.get(o + 1)? as u32) << 16) };
        loop {
            self.steps += 1;
            if self.steps > MAX_STEPS {
                return None;
            }
            let i = insns.get(pc)?;
            let g = |k: usize| i.regs[k] as usize;
            let jump = |off: i64| at.get(&((i.off as i64 + off) as u32)).copied();
            let mut next = pc + 1;
            match i.op {
                0x00 | 0x1d | 0x1e | 0x1f => {}
                0x01..=0x09 => *r.get_mut(g(0))? = r.get(g(1))?.clone(),
                0x0a..=0x0c => *r.get_mut(g(0))? = std::mem::replace(&mut res, V::Null),
                0x0e => return Some(None),
                0x0f..=0x11 => return Some(Some(r.get(g(0))?.clone())),
                0x12..=0x19 => *r.get_mut(g(0))? = V::Int(if i.op <= 0x15 { i.lit as i32 as i64 } else { i.lit }),
                0x1a | 0x1b => *r.get_mut(g(0))? = V::Str(utf16(&dx.string(i.idx).ok()?)),
                0x21 => {
                    let V::Arr(a) = r.get(g(1))? else { return None };
                    let n = a.borrow().len();
                    r[g(0)] = V::Int(n as i64);
                }
                0x22 => {
                    let t = dx.type_name(i.idx).ok()?;
                    r[g(0)] = match t.as_str() {
                        "Ljava/lang/String;" => V::Fresh,
                        "Ljava/lang/StringBuilder;" | "Ljava/lang/StringBuffer;" => V::Fresh,
                        _ => return None,
                    };
                }
                0x23 => {
                    let n = r.get(g(1))?.int()?;
                    if !(0..=1 << 20).contains(&n) {
                        return None;
                    }
                    let t = dx.type_name(i.idx).ok()?;
                    let z = if t.len() == 2 { V::Int(0) } else { V::Null };
                    r[g(0)] = V::Arr(Rc::new(RefCell::new(vec![z; n as usize])));
                }
                0x26 => {
                    let p = (i.off as i64 + i.lit) as usize;
                    let (w, n) = (*units.get(p + 1)? as usize, u32_at(p + 2)? as usize);
                    let bytes: Vec<u8> = units.get(p + 4..p + 4 + (w * n).div_ceil(2))?.iter().flat_map(|u| u.to_le_bytes()).collect();
                    let vals: Vec<V> = bytes.chunks_exact(w).take(n).map(|c| V::Int(match w {
                        1 => c[0] as i8 as i64,
                        2 => i16::from_le_bytes([c[0], c[1]]) as i64,
                        4 => i32::from_le_bytes([c[0], c[1], c[2], c[3]]) as i64,
                        _ => i64::from_le_bytes(c.try_into().unwrap_or([0; 8])),
                    })).collect();
                    let V::Arr(a) = r.get(g(0))? else { return None };
                    let mut a = a.borrow_mut();
                    for (k, v) in vals.into_iter().enumerate() {
                        *a.get_mut(k)? = v;
                    }
                }
                0x28..=0x2a => next = jump(i.lit)?,
                0x2b | 0x2c => {
                    let key = r.get(g(0))?.int()? as i32;
                    let p = (i.off as i64 + i.lit) as usize;
                    let n = *units.get(p + 1)? as usize;
                    let target = if i.op == 0x2b {
                        let first = u32_at(p + 2)? as i32;
                        let k = key.wrapping_sub(first);
                        if k >= 0 && (k as usize) < n { Some(u32_at(p + 4 + 2 * k as usize)? as i32) } else { None }
                    } else {
                        (0..n).find(|&k| u32_at(p + 2 + 2 * k).is_some_and(|x| x as i32 == key)).and_then(|k| u32_at(p + 2 + 2 * n + 2 * k)).map(|x| x as i32)
                    };
                    if let Some(t) = target {
                        next = jump(t as i64)?;
                    }
                }
                0x31 => {
                    let (a, b) = (r.get(g(1))?.int()?, r.get(g(2))?.int()?);
                    r[g(0)] = V::Int(a.cmp(&b) as i64);
                }
                0x32..=0x3d => {
                    let a = r.get(g(0))?;
                    let b = if i.op <= 0x37 { r.get(g(1))?.clone() } else { V::Int(0) };
                    let ord = match (a, &b) {
                        (V::Int(x), V::Int(y)) => (*x as i32).cmp(&(*y as i32)) as i8,
                        (V::Null, V::Int(0)) => 0,
                        (_, V::Int(0)) => 1,
                        _ => return None,
                    };
                    let take = match (i.op - 0x32) % 6 {
                        0 => ord == 0,
                        1 => ord != 0,
                        2 => ord < 0,
                        3 => ord >= 0,
                        4 => ord > 0,
                        _ => ord <= 0,
                    };
                    if take {
                        next = jump(i.lit)?;
                    }
                }
                0x44..=0x4a => {
                    let V::Arr(a) = r.get(g(1))? else { return None };
                    let k = r.get(g(2))?.int()?;
                    let v = a.borrow().get(usize::try_from(k).ok()?)?.clone();
                    r[g(0)] = v;
                }
                0x4b..=0x51 => {
                    let V::Arr(a) = r.get(g(1))?.clone() else { return None };
                    let k = r.get(g(2))?.int()?;
                    let v = match (i.op, r.get(g(0))?.clone()) {
                        (0x4f, V::Int(x)) => V::Int(x as i8 as i64),
                        (0x50, V::Int(x)) => V::Int(x as u16 as i64),
                        (0x51, V::Int(x)) => V::Int(x as i16 as i64),
                        (_, v) => v,
                    };
                    *a.borrow_mut().get_mut(usize::try_from(k).ok()?)? = v;
                }
                0x60..=0x66 => r[g(0)] = self.static_field(dx, i.idx, depth)?,
                0x67..=0x6d if clinit => {
                    let v = r.get(g(0))?.clone();
                    self.statics.insert((Self::dex_key(dx), i.idx), v);
                }
                0x6e..=0x72 | 0x74..=0x78 => {
                    let regs: Vec<usize> = if i.range { (0..i.nregs as usize).map(|k| i.regs[0] as usize + k).collect() } else { i.regs[..i.nregs as usize].iter().map(|&x| x as usize).collect() };
                    let (_, _, proto) = dx.method_parts(i.idx).ok()?;
                    let (_, params) = dx.proto_parts(proto).ok()?;
                    let is_static = matches!(i.op, 0x71 | 0x77);
                    // drop the second register of each wide argument
                    let mut a = Vec::new();
                    let mut k = 0;
                    if !is_static {
                        a.push(r.get(*regs.first()?)?.clone());
                        k = 1;
                    }
                    for p in &params {
                        a.push(r.get(*regs.get(k)?)?.clone());
                        k += if p == "J" || p == "D" { 2 } else { 1 };
                    }
                    let mref = dx.method_ref(i.idx).ok()?;
                    let out = match self.builtin(&mref, &a) {
                        Some(v) => v,
                        None if matches!(i.op, 0x70 | 0x71 | 0x76 | 0x77) => {
                            let (d2, _, _) = find_code(self.dexes, &mref)?;
                            let (cls, _) = mref.split_once("->")?;
                            let c = d2.find_class(cls)?;
                            let m = d2.class_data(c).ok()?.methods.into_iter().find(|m| d2.method_ref(m.method_idx).ok().as_deref() == Some(&mref))?;
                            let code = m.code?;
                            if is_static {
                                self.init_class(cls, depth)?;
                            }
                            // wide arguments: give the callee its register pairs back
                            let mut full = Vec::new();
                            let mut it = a.into_iter();
                            if !is_static {
                                full.push(it.next()?);
                            }
                            for (p, v) in params.iter().zip(it) {
                                full.push(v);
                                if p == "J" || p == "D" {
                                    full.push(V::Null);
                                }
                            }
                            self.run(d2, &code, full, depth + 1, false)?
                        }
                        None => return None,
                    };
                    // a constructor fills in its receiver register
                    if mref.contains("-><init>(") && !is_static {
                        if let (Some(V::Fresh), Some(v)) = (r.get(regs[0]), &out) {
                            let v = v.clone();
                            r[regs[0]] = v.clone();
                            // javac copies `new` into a second register before the call
                            for x in r.iter_mut() {
                                if matches!(x, V::Fresh) {
                                    *x = v.clone();
                                }
                            }
                        }
                    } else {
                        res = out.unwrap_or(V::Null);
                    }
                }
                0x7b..=0x8f => {
                    let x = r.get(g(1))?.int()?;
                    r[g(0)] = V::Int(match i.op {
                        0x7b => (x as i32).wrapping_neg() as i64,
                        0x7c => !(x as i32) as i64,
                        0x7d => x.wrapping_neg(),
                        0x7e => !x,
                        0x81 => x as i32 as i64,
                        0x84 => x as i32 as i64,
                        0x8d => x as i8 as i64,
                        0x8e => x as u16 as i64,
                        0x8f => x as i16 as i64,
                        _ => return None,
                    });
                }
                0x90..=0xa5 | 0xb0..=0xc5 | 0xd0..=0xe2 => {
                    let (op, wide, a, b) = match i.op {
                        0x90..=0xa5 => ((i.op - 0x90) % 11, i.op >= 0x9b, r.get(g(1))?.int()?, r.get(g(2))?.int()?),
                        0xb0..=0xc5 => ((i.op - 0xb0) % 11, i.op >= 0xbb, r.get(g(0))?.int()?, r.get(g(1))?.int()?),
                        // lit16 ops have no shifts; rsub is op 1 with swapped operands
                        0xd0..=0xd7 => ((i.op - 0xd0), false, r.get(g(1))?.int()?, i.lit),
                        _ => ((i.op - 0xd8), false, r.get(g(1))?.int()?, i.lit),
                    };
                    let rsub = matches!(i.op, 0xd1 | 0xd9);
                    let v = if wide {
                        match op {
                            0 => a.wrapping_add(b),
                            1 => a.wrapping_sub(b),
                            2 => a.wrapping_mul(b),
                            3 => a.checked_div(b)?,
                            4 => a.checked_rem(b)?,
                            5 => a & b,
                            6 => a | b,
                            7 => a ^ b,
                            8 => a.wrapping_shl(b as u32 & 63),
                            9 => a.wrapping_shr(b as u32 & 63),
                            _ => ((a as u64) >> (b as u32 & 63)) as i64,
                        }
                    } else {
                        let (a, b) = (a as i32, b as i32);
                        (match op {
                            0 => a.wrapping_add(b),
                            1 if rsub => b.wrapping_sub(a),
                            1 => a.wrapping_sub(b),
                            2 => a.wrapping_mul(b),
                            3 => a.checked_div(b)?,
                            4 => a.checked_rem(b)?,
                            5 => a & b,
                            6 => a | b,
                            7 => a ^ b,
                            8 => a.wrapping_shl(b as u32 & 31),
                            9 => a.wrapping_shr(b as u32 & 31),
                            _ => ((a as u32) >> (b as u32 & 31)) as i32,
                        }) as i64
                    };
                    r[g(0)] = V::Int(v);
                }
                _ => return None,
            }
            pc = next;
        }
    }
}

/// Run a static method on constant arguments and return the string it builds, when it only
/// computes (no I/O, no instance state). Only for methods the APK defines.
fn eval_string(dexes: &[Dex], mref: &str, args: Vec<V>) -> Option<String> {
    let (dx, idx, _) = find_code(dexes, mref)?;
    let (cls, _) = mref.split_once("->")?;
    let c = dx.find_class(cls)?;
    let m = dx.class_data(c).ok()?.methods.into_iter().find(|m| m.method_idx == idx)?;
    let code = m.code?;
    let (_, _, proto) = dx.method_parts(idx).ok()?;
    let (_, params) = dx.proto_parts(proto).ok()?;
    let mut full = Vec::new();
    for (p, v) in params.iter().zip(args) {
        full.push(v);
        if p == "J" || p == "D" {
            full.push(V::Null);
        }
    }
    let mut vm = Vm { dexes, steps: 0, statics: HashMap::new(), inited: HashSet::new() };
    vm.init_class(cls, 0)?;
    let V::Str(s) = vm.run(dx, &code, full, 0, false)?? else { return None };
    let s = String::from_utf16(&s).ok()?;
    // readable text only: decryptors return words, keys and URLs, not binary noise
    (s.chars().count() <= 2000 && s.chars().all(|c| !c.is_control() || c == '\n' || c == '\t')).then_some(s)
}

/// Static methods that look like string decryptors: return String, take only strings, ints,
/// longs or byte/char arrays.
fn decryptor_shape(dx: &Dex, m: u32) -> bool {
    let Ok((_, name, proto)) = dx.method_parts(m) else { return false };
    let Ok((ret, params)) = dx.proto_parts(proto) else { return false };
    ret == "Ljava/lang/String;" && !params.is_empty() && name != "valueOf" && params.iter().all(|p| matches!(p.as_str(), "Ljava/lang/String;" | "I" | "J" | "S" | "C" | "B" | "[B" | "[C" | "[I"))
}

thread_local! {
    static DECRYPTED: RefCell<HashMap<(usize, u32, String), Option<String>>> = RefCell::new(HashMap::new());
}

static DEXES: std::sync::OnceLock<&'static [Dex<'static>]> = std::sync::OnceLock::new();

/// Make the APK's DEX files available to inline decryption (once, after loading).
pub fn set_dexes(d: &'static [Dex<'static>]) {
    let _ = DEXES.set(d);
}

/// Plaintext of `m(args)` when `m` is a string decryptor and every argument is a constant;
/// rendered by the Java printer as a comment next to the call.
pub fn decrypt_call(dx: &Dex, m: u32, args: &[crate::ir::Expr]) -> Option<String> {
    use crate::ir::Expr;
    let dexes = *DEXES.get()?;
    if !decryptor_shape(dx, m) {
        return None;
    }
    let mut key = String::new();
    let mut vals = Vec::new();
    for a in args {
        let v = match a {
            Expr::Lit(v, _) => V::Int(*v),
            Expr::Str(s) => V::Str(utf16(s)),
            Expr::ArrayLit(_, xs) => V::Arr(Rc::new(RefCell::new(xs.iter().map(|&x| V::Int(x)).collect()))),
            _ => return None,
        };
        let _ = write!(key, "{v:?}|");
        vals.push(v);
    }
    let mref = dx.method_ref(m).ok()?;
    let k = (dx.bytes().as_ptr() as usize, m, key);
    if let Some(r) = DECRYPTED.with(|c| c.borrow().get(&k).cloned()) {
        return r;
    }
    let r = eval_string(dexes, &mref, vals).filter(|p| !args.iter().any(|a| matches!(a, Expr::Str(s) if s == p)));
    DECRYPTED.with(|c| c.borrow_mut().insert(k, r.clone()));
    r
}

/// Every decryptor call with constant arguments in the APK: (caller, decryptor, plaintext).
/// Constants are tracked per straight-line run of code (reset at branch targets).
pub fn decrypt_all(dexes: &[Dex]) -> Vec<(String, String, String)> {
    let mut out = Vec::new();
    for dx in dexes {
        let cands: HashSet<u32> = (0..dx.counts()[3] as u32).filter(|&m| decryptor_shape(dx, m) && dx.method_parts(m).is_ok_and(|(c, _, _)| dx.find_class(&c).is_some())).collect();
        if cands.is_empty() {
            continue;
        }
        let mut memo: HashMap<String, Option<String>> = HashMap::new();
        for c in 0..dx.class_count {
            let _ = dx.each_method(c, |m, insns| {
                let Some(insns) = insns else { return };
                let mut any = false;
                bytecode::for_each_ref(insns, |r, idx| any |= r == Ref::Method && cands.contains(&idx));
                if !any {
                    return;
                }
                let Ok(code) = bytecode::decode(insns) else { return };
                let units: Vec<u16> = insns.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
                let targets: HashSet<u32> = code.iter().filter(|i| matches!(i.op, 0x28..=0x2a | 0x32..=0x3d)).map(|i| (i.off as i64 + i.lit) as u32).collect();
                let mut known: HashMap<u16, V> = HashMap::new();
                for i in &code {
                    if targets.contains(&i.off) {
                        known.clear();
                    }
                    match i.op {
                        0x12..=0x19 => {
                            known.insert(i.regs[0], V::Int(if i.op <= 0x15 { i.lit as i32 as i64 } else { i.lit }));
                            continue;
                        }
                        0x1a | 0x1b => {
                            if let Ok(s) = dx.string(i.idx) {
                                known.insert(i.regs[0], V::Str(utf16(&s)));
                            }
                            continue;
                        }
                        0x23 => {
                            if let (Some(V::Int(n)), true) = (known.get(&i.regs[1]).cloned(), dx.type_name(i.idx).is_ok_and(|t| t.len() == 2)) {
                                if (0..4096).contains(&n) {
                                    known.insert(i.regs[0], V::Arr(Rc::new(RefCell::new(vec![V::Int(0); n as usize]))));
                                    continue;
                                }
                            }
                        }
                        0x26 => {
                            // fill-array-data into a tracked array
                            let p = (i.off as i64 + i.lit) as usize;
                            if let (Some(V::Arr(a)), Some(&w), Some(&lo), Some(&hi)) = (known.get(&i.regs[0]), units.get(p + 1), units.get(p + 2), units.get(p + 3)) {
                                let (w, n) = (w as usize, (lo as u32 | (hi as u32) << 16) as usize);
                                let bytes: Vec<u8> = units.get(p + 4..p + 4 + (w * n).div_ceil(2)).unwrap_or(&[]).iter().flat_map(|u| u.to_le_bytes()).collect();
                                let mut a = a.borrow_mut();
                                for (k, ch) in bytes.chunks_exact(w.max(1)).take(n.min(a.len())).enumerate() {
                                    a[k] = V::Int(match w {
                                        1 => ch[0] as i8 as i64,
                                        2 => i16::from_le_bytes([ch[0], ch[1]]) as i64,
                                        4 => i32::from_le_bytes([ch[0], ch[1], ch[2], ch[3]]) as i64,
                                        _ => 0,
                                    });
                                }
                            }
                            continue;
                        }
                        0x71 | 0x77 if cands.contains(&i.idx) => {
                            let regs: Vec<u16> = if i.range { (0..i.nregs as u16).map(|k| i.regs[0] + k).collect() } else { i.regs[..i.nregs as usize].to_vec() };
                            let params = dx.method_parts(i.idx).and_then(|p| dx.proto_parts(p.2)).map(|p| p.1).unwrap_or_default();
                            let mut args = Vec::new();
                            let mut k = 0;
                            for p in &params {
                                match regs.get(k).and_then(|r| known.get(r)) {
                                    Some(v) => args.push(v.clone()),
                                    None => break,
                                }
                                k += if p == "J" { 2 } else { 1 };
                            }
                            if args.len() == params.len() {
                                let mref = dx.method_ref(i.idx).unwrap_or_default();
                                let key = format!("{mref}{args:?}");
                                let plain = memo.entry(key).or_insert_with(|| eval_string(dexes, &mref, args)).clone();
                                if let Some(p) = plain {
                                    out.push((dx.method_ref(m).unwrap_or_default(), mref, p));
                                }
                            }
                        }
                        _ => {}
                    }
                    // any other write forgets the register
                    if i.nregs > 0 && !i.range && !matches!(i.op, 0x26..=0x3d | 0x4b..=0x51 | 0x59..=0x5f | 0x67..=0x78 | 0x0e..=0x11 | 0x1d | 0x1e) {
                        known.remove(&i.regs[0]);
                    }
                }
            });
        }
    }
    out
}

// ---------- project file: renames, comments, mappings ----------

/// `<apk>.apkscope.json`, next to the APK.
pub fn project_file(apk: &str) -> std::path::PathBuf {
    std::path::PathBuf::from(format!("{apk}.apkscope.json"))
}

fn map_json(m: &HashMap<String, String>) -> serde_json::Value {
    let mut v: Vec<(&String, &String)> = m.iter().collect();
    v.sort();
    serde_json::Value::Object(v.into_iter().map(|(k, x)| (k.clone(), serde_json::Value::String(x.clone()))).collect())
}

pub fn load_notes(apk: &str) -> Result<Notes, String> {
    let p = project_file(apk);
    let Ok(text) = std::fs::read_to_string(&p) else { return Ok(Notes::default()) };
    let v: serde_json::Value = serde_json::from_str(&text).map_err(|e| format!("{}: {e}", p.display()))?;
    let get = |k: &str| -> HashMap<String, String> { v.get(k).and_then(|o| o.as_object()).map(|o| o.iter().filter_map(|(a, b)| Some((a.clone(), b.as_str()?.to_string()))).collect()).unwrap_or_default() };
    Ok(Notes { classes: get("classes"), members: get("members"), comments: get("comments") })
}

pub fn save_notes(apk: &str, n: &Notes) -> Result<(), String> {
    let v = serde_json::json!({ "classes": map_json(&n.classes), "members": map_json(&n.members), "comments": map_json(&n.comments) });
    std::fs::write(project_file(apk), serde_json::to_string_pretty(&v).unwrap_or_default()).map_err(|e| e.to_string())
}

/// Short hash of the notes, so decompiled code cached with other names isn't reused.
pub fn notes_tag(n: &Notes) -> u64 {
    let mut all: Vec<String> = [&n.classes, &n.members, &n.comments].iter().enumerate().flat_map(|(k, m)| m.iter().map(move |(a, b)| format!("{k}{a}={b}"))).collect();
    all.sort();
    if all.is_empty() { 0 } else { dex::name_hash(&all.join("\n")) }
}

/// Set (or with empty `text`, remove) a rename or comment. `key`: `La/b;`, `La/b;->field`,
/// `La/b;->method()`. A class renamed to a bare short name keeps its package.
pub fn apply_note(n: &mut Notes, key: &str, comment: bool, text: &str) {
    let map = match (comment, key.contains("->")) {
        (true, _) => &mut n.comments,
        (_, true) => &mut n.members,
        _ => &mut n.classes,
    };
    let value = if !comment && !key.contains("->") && !text.is_empty() {
        if text.contains('.') || text.contains('/') { desc(text) } else { format!("{}{text};", key.trim_end_matches(';').rsplit_once('/').map_or("L".to_string(), |x| format!("{}/", x.0))) }
    } else {
        text.to_string()
    };
    if value.is_empty() {
        map.remove(key);
    } else {
        map.insert(key.to_string(), value);
    }
}

/// Real descriptor of a class shown as `shown` (its simple name as printed) inside top-level
/// class `top`; `top` itself when `shown` is its own name or nothing matches.
pub fn nested_class(dexes: &[Dex], top: &str, shown: &str) -> String {
    let prefix = format!("{}$", top.trim_end_matches(';'));
    for dx in dexes {
        for c in 0..dx.class_count {
            let Ok(d) = dx.class_descriptor(c) else { continue };
            if d.starts_with(&prefix) && dex::java_name(&d).rsplit(['.', '$']).next() == Some(shown) {
                return d;
            }
        }
    }
    top.to_string()
}

/// Real name of a member of `class` shown as `shown` (after deobfuscation and user renames).
/// Constructors are shown with the class name and come back as `<init>`.
pub fn real_member(dexes: &[Dex], class: &str, shown: &str, method: bool) -> Option<String> {
    for dx in dexes {
        let Some(c) = dx.find_class(class) else { continue };
        let data = dx.class_data(c).ok()?;
        if method {
            let simple = dex::java_name(class).rsplit(['.', '$']).next().unwrap_or("").to_string();
            if shown == simple {
                return Some("<init>".into());
            }
            for m in &data.methods {
                let Ok((_, n, _)) = dx.method_parts(m.method_idx) else { continue };
                if crate::deobf::method(class, &n).unwrap_or_else(|| n.clone()) == shown {
                    return Some(n);
                }
            }
        } else {
            for (f, _) in &data.fields {
                let Ok((_, ty, n)) = dx.field_parts(*f) else { continue };
                if crate::deobf::field(class, &n, &ty).unwrap_or_else(|| n.clone()) == shown {
                    return Some(n);
                }
            }
        }
    }
    None
}

/// Export the user's renames (and comments, for Enigma) as a JADX `.jobf` or Enigma `.mapping` file.
pub fn export_mapping(dexes: &[Dex], n: &Notes, enigma: bool) -> String {
    let mut o = String::new();
    // per class: (new class name, [(kind, old, new, descriptor)])
    let mut classes: std::collections::BTreeMap<String, Vec<(char, String, String, String)>> = Default::default();
    for c in n.classes.keys() {
        classes.entry(c.clone()).or_default();
    }
    for (key, new) in &n.members {
        let Some((cls, name)) = key.split_once("->") else { continue };
        let (name, is_method) = name.strip_suffix("()").map_or((name, false), |n| (n, true));
        let mut found = false;
        for dx in dexes {
            let Some(ci) = dx.find_class(cls) else { continue };
            let Ok(data) = dx.class_data(ci) else { continue };
            for m in &data.methods {
                if let Ok((_, mn, p)) = dx.method_parts(m.method_idx) {
                    if is_method && mn == name {
                        let sig = dx.proto(p).unwrap_or_default();
                        classes.entry(cls.to_string()).or_default().push(('m', mn, new.clone(), sig));
                        found = true;
                    }
                }
            }
            for (f, _) in &data.fields {
                if let Ok((_, ty, fname)) = dx.field_parts(*f) {
                    if !is_method && fname == name {
                        classes.entry(cls.to_string()).or_default().push(('f', fname, new.clone(), ty));
                        found = true;
                    }
                }
            }
        }
        if !found {
            classes.entry(cls.to_string()).or_default();
        }
    }
    let path = |d: &str| d.trim_start_matches('L').trim_end_matches(';').to_string();
    for (cls, members) in &classes {
        let new = n.classes.get(cls);
        if enigma {
            let _ = writeln!(o, "CLASS {}{}", path(cls), new.map(|x| format!(" {}", path(x))).unwrap_or_default());
            if let Some(c) = n.comments.get(cls) {
                for l in c.lines() {
                    let _ = writeln!(o, "\tCOMMENT {l}");
                }
            }
            for (k, old, nn, sig) in members {
                let _ = writeln!(o, "\t{} {old} {nn} {sig}", if *k == 'm' { "METHOD" } else { "FIELD" });
                if let Some(c) = n.comments.get(&format!("{cls}->{old}{}", if *k == 'm' { "()" } else { "" })) {
                    for l in c.lines() {
                        let _ = writeln!(o, "\t\tCOMMENT {l}");
                    }
                }
            }
        } else {
            let dotted = path(cls).replace('/', ".");
            if let Some(x) = new {
                let short = path(x).rsplit(['/', '$']).next().unwrap_or("").to_string();
                let _ = writeln!(o, "c {dotted} = {short}");
            }
            for (k, old, nn, sig) in members {
                match k {
                    'm' => {
                        let _ = writeln!(o, "m {dotted}.{old}{sig} = {nn}");
                    }
                    _ => {
                        let _ = writeln!(o, "f {dotted}.{old}:{sig} = {nn}");
                    }
                }
            }
        }
    }
    o
}

/// Merge a JADX `.jobf` or Enigma `.mapping` file into the notes; returns how many names were read.
pub fn import_mapping(text: &str, n: &mut Notes) -> usize {
    let mut count = 0;
    let enigma = text.lines().any(|l| l.starts_with("CLASS "));
    if enigma {
        let mut cls = String::new();
        let mut member: Option<String> = None;
        for line in text.lines() {
            let depth = line.chars().take_while(|c| *c == '\t').count();
            let parts: Vec<&str> = line.trim().split_whitespace().collect();
            match parts.as_slice() {
                // nested classes are written as CLASS Inner inside their outer class
                ["CLASS", old, rest @ ..] => {
                    cls = if depth > 0 && !cls.is_empty() { format!("{}${old};", cls.trim_end_matches(';')) } else { format!("L{old};") };
                    member = None;
                    if let Some(new) = rest.first() {
                        let new = if new.contains('/') || depth == 0 { format!("L{new};") } else { format!("{}${new};", cls.rsplit_once('$').map_or("", |x| x.0)) };
                        n.classes.insert(cls.clone(), new);
                        count += 1;
                    }
                }
                ["METHOD" | "FIELD", old, rest @ ..] => {
                    let paren = if parts[0] == "METHOD" { "()" } else { "" };
                    member = Some(format!("{cls}->{old}{paren}"));
                    // `METHOD old new (sig)` or `METHOD old (sig)`
                    if let Some(new) = rest.first().filter(|x| !x.starts_with('(') && rest.len() >= 2 || !x.starts_with('(') && parts[0] == "FIELD" && rest.len() >= 2) {
                        n.members.insert(format!("{cls}->{old}{paren}"), new.to_string());
                        count += 1;
                    }
                }
                ["COMMENT", ..] => {
                    let text = line.trim().trim_start_matches("COMMENT").trim().to_string();
                    let key = member.clone().filter(|_| depth >= 2).unwrap_or_else(|| cls.clone());
                    let e = n.comments.entry(key).or_default();
                    if !e.is_empty() {
                        e.push('\n');
                    }
                    e.push_str(&text);
                }
                _ => {}
            }
        }
    } else {
        for line in text.lines() {
            let Some((lhs, new)) = line.split_once(" = ") else { continue };
            let new = new.trim();
            match lhs.split_once(' ') {
                Some(("c", c)) => {
                    let d = desc(c.trim());
                    let pkg = d.trim_end_matches(';').rsplit_once(['/', '$']).map_or("L".to_string(), |(p, _)| format!("{p}{}", &d[p.len()..p.len() + 1]));
                    n.classes.insert(d.clone(), format!("{pkg}{new};"));
                    count += 1;
                }
                Some((k @ ("m" | "f"), rest)) => {
                    let rest = rest.trim();
                    let head = if k == "m" { rest.split('(').next().unwrap_or(rest) } else { rest.split(':').next().unwrap_or(rest) };
                    if let Some((c, old)) = head.rsplit_once('.') {
                        n.members.insert(format!("{}->{old}{}", desc(c), if k == "m" { "()" } else { "" }), new.to_string());
                        count += 1;
                    }
                }
                _ => {}
            }
        }
    }
    count
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frida_types() {
        assert_eq!(frida_type("I"), "int");
        assert_eq!(frida_type("Ljava/lang/String;"), "java.lang.String");
        assert_eq!(frida_type("[B"), "[B");
        assert_eq!(frida_type("[Ljava/lang/String;"), "[Ljava.lang.String;");
    }

    #[test]
    fn base64_decodes() {
        let s: Vec<u16> = "aGk=".encode_utf16().collect();
        let b: Vec<i64> = base64(&s, 0).unwrap().iter().map(|v| v.int().unwrap()).collect();
        assert_eq!(b, vec![104, 105]);
    }

    #[test]
    fn mappings_round_trip() {
        let mut n = Notes::default();
        let jobf = "c a.b.C = Login\nm a.b.C.a(I)V = check\nf a.b.C.x:I = count\n";
        assert_eq!(import_mapping(jobf, &mut n), 3);
        assert_eq!(n.classes["La/b/C;"], "La/b/Login;");
        assert_eq!(n.members["La/b/C;->a()"], "check");
        assert_eq!(n.members["La/b/C;->x"], "count");
        let mut e = Notes::default();
        let enigma = "CLASS a/b/C com/x/Login\n\tCOMMENT main screen\n\tMETHOD a check (I)V\n\t\tCOMMENT validates\n\tFIELD x count I\n";
        assert_eq!(import_mapping(enigma, &mut e), 3);
        assert_eq!(e.classes["La/b/C;"], "Lcom/x/Login;");
        assert_eq!(e.members["La/b/C;->a()"], "check");
        assert_eq!(e.comments["La/b/C;->a()"], "validates");
        assert_eq!(e.comments["La/b/C;"], "main screen");
    }

    #[test]
    fn evaluates_xor_decryptor() {
        // static String d(String s): char[] c = s.toCharArray(); for (i..) c[i] ^= 1; return new String(c);
        // run directly on the VM with a hand-built method body
        let d = crate::dex::tests::tiny_dex();
        let dx = Dex::parse(&d).unwrap();
        let dexes = [dx];
        let mut vm = Vm { dexes: &dexes, steps: 0, statics: HashMap::new(), inited: HashSet::new() };
        // registers v0..v3, arg in v3 (a char[]): v0 = len; v1 = 0; loop: if v1 >= v0 goto end;
        // v2 = v3[v1]; v2 ^= 1; v2 = (char) v2; v3[v1] = v2; v1++; goto loop; end: return-object v3
        let units: [u16; 13] = [0x3021, 0x0112, 0x0135, 0x000b, 0x0249, 0x0103, 0x02df, 0x0102, 0x0250, 0x0103, 0x01d8, 0x0101, 0xf628];
        let mut code_units = units.to_vec();
        code_units.push(0x0311); // return-object v3
        let bytes: Vec<u8> = code_units.iter().flat_map(|u| u.to_le_bytes()).collect();
        let code = dex::Code { registers: 4, ins: 1, insns: &bytes, tries: vec![] };
        let arr = V::Arr(Rc::new(RefCell::new("ih".encode_utf16().map(|c| V::Int(c as i64)).collect())));
        let Some(Some(V::Arr(out))) = vm.run(&dexes[0], &code, vec![arr], 0, false) else { panic!("no result") };
        let s: String = out.borrow().iter().map(|v| v.int().unwrap() as u8 as char).collect();
        assert_eq!(s, "hi");
    }
}
