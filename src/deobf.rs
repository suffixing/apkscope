//! Readable names for obfuscated identifiers. Classes get a per-APK map (hints from the
//! SourceFile attribute or the supertype); members are renamed by a fixed rule, so overrides
//! and every call site agree without a whole-program pass.

use std::collections::{HashMap, HashSet};
use std::sync::OnceLock;

use crate::dex::Dex;

/// class descriptor -> renamed descriptor; set once at startup when deobfuscation is on
static CLASSES: OnceLock<HashMap<String, String>> = OnceLock::new();

/// (enum descriptor, obfuscated field) -> the constant's real name, read from `new E("NAME", ...)`
static ENUM_NAMES: OnceLock<HashMap<(String, String), String>> = OnceLock::new();

/// Real short names that must survive (`id`, `x`, `ui` ...).
const KEEP: &[&str] = &["x", "y", "z", "w", "h", "id", "to", "of", "on", "is", "at", "go", "up", "ok", "io", "ui", "op", "os", "db", "fn", "it", "js", "vm", "tv", "gl", "ml", "ws", "rx", "v4", "v7"];

const KEYWORDS: &[&str] = &[
    "abstract", "assert", "boolean", "break", "byte", "case", "catch", "char", "class", "const", "continue", "default", "do",
    "double", "else", "enum", "extends", "final", "finally", "float", "for", "goto", "if", "implements", "import", "instanceof",
    "int", "interface", "long", "native", "new", "package", "private", "protected", "public", "return", "short", "static",
    "strictfp", "super", "switch", "synchronized", "this", "throw", "throws", "transient", "try", "void", "volatile", "while",
    "true", "false", "null",
];

/// Looks like ProGuard/R8 output: `a`, `b0`, `zza`, keywords, or not a Java identifier.
pub fn obfuscated(name: &str) -> bool {
    if name.is_empty() || name.starts_with('<') || KEEP.contains(&name) {
        return false;
    }
    let valid = name.chars().next().is_some_and(|c| c.is_alphabetic() || c == '_' || c == '$') && name.chars().all(|c| c.is_alphanumeric() || c == '_' || c == '$');
    !valid || KEYWORDS.contains(&name) || name.chars().count() <= 2 || (name.starts_with("zz") && name.len() <= 5)
}

/// Stricter rule for package and class names: single letters are never real names there.
fn obfuscated_type(name: &str) -> bool {
    obfuscated(name) || name.chars().count() == 1
}

fn cap(s: &str) -> String {
    let clean: String = s.chars().map(|c| if c.is_alphanumeric() || c == '_' { c } else { '_' }).collect();
    let mut cs = clean.chars();
    match cs.next() {
        Some(c) => c.to_uppercase().chain(cs).collect(),
        None => "_".into(),
    }
}

pub fn enabled() -> bool {
    CLASSES.get().is_some()
}

/// Renamed class descriptor, if deobfuscation is on and the class was renamed.
pub fn class(desc: &str) -> Option<&'static str> {
    CLASSES.get()?.get(desc).map(String::as_str)
}

/// Original characters kept as-is: `a` and `A` are different members and must stay different.
fn ident(s: &str) -> String {
    s.chars().map(|c| if c.is_alphanumeric() || c == '_' || c == '$' { c } else { '_' }).collect()
}

/// `a()` -> `ma()`, `A()` -> `mA()`
pub fn method(name: &str) -> Option<String> {
    (enabled() && obfuscated(name)).then(|| format!("m{}", ident(name)))
}

/// field `a` of type `String` -> `str_a`; the type keeps same-named fields of different types apart
pub fn field(owner: &str, name: &str, ty: &str) -> Option<String> {
    if !enabled() || !obfuscated(name) {
        return None;
    }
    // an enum constant (a field of an enum typed as that enum) keeps the name its constructor was given
    if owner == ty {
        if let Some(n) = ENUM_NAMES.get().and_then(|m| m.get(&(owner.to_string(), name.to_string()))) {
            return Some(n.clone());
        }
    }
    Some(format!("{}_{}", crate::ir::name_for(Some(ty)), ident(name)))
}

/// Scan each enum's static initializer: `new E("NAME", ...)` stored into a static field of type E
/// names that field. Only valid, unique identifiers are kept.
fn enum_names(dexes: &[Dex]) -> HashMap<(String, String), String> {
    use crate::bytecode::decode;
    let mut out = HashMap::new();
    for dex in dexes {
        for c in 0..dex.class_count {
            let Ok(def) = dex.class_def(c) else { continue };
            if def.superclass.as_deref() != Some("Ljava/lang/Enum;") {
                continue;
            }
            let Ok(data) = dex.class_data(c) else { continue };
            let Some(code) = data.methods.iter().find(|m| dex.method_parts(m.method_idx).is_ok_and(|p| p.1 == "<clinit>")).and_then(|m| m.code.as_ref()) else { continue };
            let Ok(insns) = decode(code.insns) else { continue };
            let (mut strs, mut named): (HashMap<u16, u32>, HashMap<u16, u32>) = (HashMap::new(), HashMap::new());
            let mut found: Vec<(String, String)> = Vec::new();
            for i in &insns {
                match i.op {
                    0x1a | 0x1b => {
                        strs.insert(i.regs[0], i.idx);
                    }
                    // invoke-direct E.<init>(this, name, ordinal, ...)
                    0x70 | 0x76 => {
                        let regs: Vec<u16> = if i.range { (0..i.nregs as u16).map(|k| i.regs[0] + k).collect() } else { i.regs[..i.nregs as usize].to_vec() };
                        let ctor = dex.method_parts(i.idx).is_ok_and(|(cls, n, _)| n == "<init>" && cls == def.class);
                        if let (true, Some(&this), Some(s)) = (ctor, regs.first(), regs.get(1).and_then(|r| strs.get(r))) {
                            named.insert(this, *s);
                        }
                    }
                    // sput-object vA, E.field
                    0x69 => {
                        if let (Some(s), Ok((cls, ty, fname))) = (named.get(&i.regs[0]), dex.field_parts(i.idx)) {
                            if cls == def.class && ty == def.class {
                                if let Ok(n) = dex.string(*s) {
                                    found.push((fname, n));
                                }
                            }
                        }
                    }
                    _ => {
                        // any other write to a register forgets what it held
                        if let Some(&r) = i.regs.first().filter(|_| i.nregs > 0 && !i.range) {
                            if !matches!(i.op, 0x69 | 0x6e..=0x78) {
                                strs.remove(&r);
                                named.remove(&r);
                            }
                        }
                    }
                }
            }
            let unique: std::collections::HashSet<&String> = found.iter().map(|f| &f.1).collect();
            if unique.len() != found.len() {
                continue;
            }
            for (fname, n) in found {
                if !obfuscated(&n) && fname != n {
                    out.insert((def.class.clone(), fname), n);
                }
            }
        }
    }
    out
}

fn package(pkg: &str) -> String {
    pkg.split('/').map(|s| if !s.is_empty() && obfuscated_type(s) { format!("pkg_{}", cap(s).to_lowercase()) } else { s.to_string() }).collect::<Vec<_>>().join("/")
}

/// Build the class map from every DEX in the APK and turn deobfuscation on.
pub fn init(dexes: &[Dex]) {
    // (descriptor, source-file hint, supertype hint)
    let mut all: Vec<(String, Option<String>, Option<String>)> = Vec::new();
    for dex in dexes {
        for c in 0..dex.class_count {
            let Ok(def) = dex.class_def(c) else { continue };
            let file = def.source_file.as_deref().and_then(|f| f.split('.').next()).filter(|f| f.len() >= 3 && *f != "SourceFile" && !obfuscated(f)).map(str::to_string);
            let sup = def
                .superclass
                .iter()
                .filter(|s| *s != "Ljava/lang/Object;")
                .chain(def.interfaces.iter())
                .map(|s| s.trim_end_matches(';').rsplit(['/', '$']).next().unwrap_or("").to_string())
                .find(|s| s.len() >= 3 && !obfuscated(s));
            all.push((def.class, file, sup));
        }
    }
    // outer classes before their inner ones
    all.sort_by_key(|(d, _, _)| (d.matches('$').count(), d.len()));
    let mut used: HashSet<String> = all.iter().map(|(d, _, _)| d.to_lowercase()).collect();
    let mut map: HashMap<String, String> = HashMap::new();
    for (desc, file, sup) in &all {
        let body = desc.trim_start_matches('L').trim_end_matches(';');
        let (pkg, cls) = body.rsplit_once('/').unwrap_or(("", body));
        let new_pkg = package(pkg);
        let (outer, last) = match cls.rsplit_once('$') {
            Some((o, l)) => {
                let parent = format!("L{pkg}{}{o};", if pkg.is_empty() { "" } else { "/" });
                // middle pieces of a compiler-made name (`a$b$default$1`) are not names of their own
                let prefix = map
                    .get(&parent)
                    .map(|p| p.trim_start_matches('L').trim_end_matches(';').to_string())
                    .unwrap_or_else(|| format!("{new_pkg}{}{o}", if new_pkg.is_empty() { "" } else { "/" }));
                (Some(prefix), l)
            }
            None => (None, cls),
        };
        // anonymous classes keep their number, `$$` lambdas keep their (empty) segment
        let rename = obfuscated_type(last) && !last.chars().all(|c| c.is_ascii_digit());
        let join = |name: &str| match &outer {
            Some(p) => format!("L{p}${name};"),
            None => format!("L{new_pkg}{}{name};", if new_pkg.is_empty() { "" } else { "/" }),
        };
        let new = if rename {
            let candidates = [file.clone().filter(|_| outer.is_none()), sup.as_ref().map(|s| format!("{s}{}", cap(last))), Some(format!("Class{}", cap(last)))];
            let mut pick = None;
            for c in candidates.into_iter().flatten() {
                let d = join(&c);
                if !used.contains(&d.to_lowercase()) {
                    pick = Some(d);
                    break;
                }
            }
            // every candidate taken: number the last one
            pick.unwrap_or_else(|| (2..).map(|n| join(&format!("Class{}{n}", cap(last)))).find(|d| !used.contains(&d.to_lowercase())).unwrap())
        } else {
            join(last)
        };
        if new != *desc {
            used.insert(new.to_lowercase());
            map.insert(desc.clone(), new);
        }
    }
    let enums = enum_names(dexes);
    eprintln!("deobf: {} classes renamed, {} enum constants named from their strings", map.len(), enums.len());
    let _ = ENUM_NAMES.set(enums);
    let _ = CLASSES.set(map);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_obfuscated_names() {
        for n in ["a", "b0", "zza", "zzbx", "if", "A", "1x"] {
            assert!(obfuscated(n), "{n}");
        }
        for n in ["id", "x", "onCreate", "LoginActivity", "<init>", "abc"] {
            assert!(!obfuscated(n), "{n}");
        }
        assert_eq!(package("a/b0/okhttp3/ui/h"), "pkg_a/pkg_b0/okhttp3/ui/pkg_h");
        assert_eq!(cap("a0"), "A0");
        assert_ne!(ident("a"), ident("A"));
    }
}
