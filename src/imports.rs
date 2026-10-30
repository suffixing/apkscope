//! Import declarations. Printers emit `type_ref` markers carrying the full name; `resolve`
//! decides per file which simple names are unambiguous, adds the imports, and fully
//! qualifies the losers of any name clash.

use std::collections::{BTreeMap, BTreeSet, HashMap};

const OPEN: char = '\u{1}';
const CLOSE: char = '\u{2}';

/// descriptor hash -> `pkg/Outer.Inner` source path, from the APK's real nesting; set once at startup.
/// Keyed by hash so huge apps don't hold every descriptor twice; a 64-bit collision among a few
/// hundred thousand classes is vanishingly unlikely.
static PATHS: std::sync::OnceLock<HashMap<u64, Box<str>>> = std::sync::OnceLock::new();
/// top-level source path -> simple names declared in its file (itself and every nested class)
static DECLARED: std::sync::OnceLock<HashMap<u64, Box<[Box<str>]>>> = std::sync::OnceLock::new();

/// Record how every class in the APK is written in source (after renaming).
pub fn init(dexes: &[crate::dex::Dex]) {
    fn path(dex: &crate::dex::Dex, c: usize, memo: &mut HashMap<String, String>) -> String {
        let desc = dex.class_descriptor(c).unwrap_or_default();
        if let Some(p) = memo.get(&desc) {
            return p.clone();
        }
        let renamed = |d: &str| crate::deobf::class(d).unwrap_or(d).to_string();
        let p = match dex.nesting().parent[c] {
            Some(o) => {
                let odesc = dex.class_descriptor(o).unwrap_or_default();
                format!("{}.{}", path(dex, o, memo), crate::java::inner_name(&renamed(&desc), &renamed(&odesc)))
            }
            None => top_level(&desc),
        };
        memo.insert(desc, p.clone());
        p
    }
    let mut memo = HashMap::new();
    for dex in dexes {
        for c in 0..dex.class_count {
            path(dex, c, &mut memo);
        }
    }
    let mut declared: HashMap<String, BTreeSet<String>> = HashMap::new();
    for p in memo.values() {
        let (pkg, cls) = p.split_once('/').unwrap_or(("", p));
        let top = cls.split('.').next().unwrap_or(cls);
        declared.entry(format!("{pkg}/{top}")).or_default().insert(parts(p).0);
    }
    let _ = DECLARED.set(declared.into_iter().map(|(k, v)| (crate::dex::name_hash(&k), v.into_iter().map(String::into_boxed_str).collect())).collect());
    let _ = PATHS.set(memo.iter().map(|(k, v)| (crate::dex::name_hash(k), v.clone().into_boxed_str())).collect());
}

/// `pkg/Name` keeping any `$` in the name (the class has no outer class in the APK)
fn top_level(desc: &str) -> String {
    let jn = crate::dex::java_name(desc);
    match jn.rsplit_once('.') {
        Some((pkg, cls)) => format!("{pkg}/{cls}"),
        None => format!("/{jn}"),
    }
}

/// Source path of a class: from the APK when known, else (framework classes) every `$` nests.
pub fn source_path(desc: &str) -> String {
    if let Some(p) = PATHS.get().and_then(|m| m.get(&crate::dex::name_hash(desc))) {
        return p.to_string();
    }
    let t = top_level(desc);
    let (pkg, cls) = t.split_once('/').unwrap_or(("", &t));
    format!("{pkg}/{}", cls.replace('$', "."))
}

/// Display form of a type descriptor, as a marker resolved later (`[I` -> `int[]`).
pub fn type_ref(desc: &str) -> String {
    if let Some(inner) = desc.strip_prefix('[') {
        return type_ref(inner) + "[]";
    }
    if desc.starts_with('L') {
        return format!("{OPEN}{}{CLOSE}", source_path(desc));
    }
    crate::ir::jtype(desc)
}

/// `a.b/Outer.Inner` -> (`Inner`, `a.b.Outer.Inner`, `a.b`)
fn parts(path: &str) -> (String, String, String) {
    let (pkg, cls) = path.split_once('/').unwrap_or(("", path));
    let simple = cls.rsplit('.').next().unwrap_or(cls).to_string();
    let dotted = if pkg.is_empty() { cls.to_string() } else { format!("{pkg}.{cls}") };
    (simple, dotted, pkg.to_string())
}

/// Replace markers in a file's text and insert imports after the `package` line.
/// `own` is the file's top-level class as a source path (`a.b/Foo`), `pkg` its package.
pub fn resolve(text: &str, pkg: &str, own: &str) -> String {
    // every referenced class, by simple name
    let mut by_simple: HashMap<String, BTreeMap<String, usize>> = HashMap::new();
    let mut rest = text;
    while let Some(i) = rest.find(OPEN) {
        let Some(j) = rest[i..].find(CLOSE) else { break };
        let full = &rest[i + 1..i + j];
        *by_simple.entry(parts(full).0).or_default().entry(full.to_string()).or_default() += 1;
        rest = &rest[i + j + 1..];
    }
    let own_prefix = format!("{own}.");
    // which full name owns each simple name, following Java's lookup order
    let rank = |full: &str| -> u8 {
        let p = parts(full).2;
        if full == own || full.starts_with(&own_prefix) {
            0
        } else if p == pkg {
            1
        } else if p == "java.lang" {
            2
        } else {
            3
        }
    };
    // a name declared in this file shadows any other type of that name, even when never referenced
    let declared = DECLARED.get().and_then(|d| d.get(&crate::dex::name_hash(own)));
    let mut winner: HashMap<String, String> = HashMap::new();
    let mut imports = BTreeSet::new();
    for (simple, fulls) in &by_simple {
        let best = fulls.iter().min_by_key(|(f, n)| (rank(f), std::cmp::Reverse(**n), (*f).clone())).map(|(f, _)| f.clone()).unwrap();
        if rank(&best) != 0 && declared.is_some_and(|d| d.iter().any(|n| **n == **simple)) {
            continue;
        }
        if rank(&best) == 3 {
            imports.insert(parts(&best).1);
        }
        winner.insert(simple.clone(), best);
    }
    let mut out = String::with_capacity(text.len() + imports.len() * 40);
    let mut rest = text;
    while let Some(i) = rest.find(OPEN) {
        out += &rest[..i];
        let Some(j) = rest[i..].find(CLOSE) else { break };
        let full = &rest[i + 1..i + j];
        let (simple, dotted, _) = parts(full);
        out += if winner.get(&simple).is_some_and(|w| w == full) { &simple } else { &dotted };
        rest = &rest[i + j + 1..];
    }
    out += rest;
    if imports.is_empty() {
        return out;
    }
    let block: String = imports.iter().map(|i| format!("import {i};\n")).collect();
    match out.find(";\n\n").filter(|_| out.starts_with("package ")) {
        Some(k) => format!("{}{block}\n{}", &out[..k + 3], &out[k + 3..]),
        None => format!("{block}\n{out}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn m(full: &str) -> String {
        format!("{OPEN}{full}{CLOSE}")
    }

    #[test]
    fn framework_paths_nest_on_dollar() {
        assert_eq!(source_path("Landroid/os/Parcelable$Creator;"), "android.os/Parcelable.Creator");
    }

    #[test]
    fn imports_and_clashes() {
        let text = format!("package a.b;\n\nclass Foo {{\n    {} x; {} y; {} z; {} w; {} q;\n}}\n", m("java.util/List"), m("a.b/Foo.Inner"), m("c.d/Item"), m("e.f/Item"), m("java.lang/String"));
        let out = resolve(&text, "a.b", "a.b/Foo");
        assert!(out.starts_with("package a.b;\n\nimport c.d.Item;\nimport java.util.List;\n\nclass Foo"), "{out}");
        // one Item is imported, the other stays fully qualified; nested and java.lang need no import
        assert!(out.contains("List x; Inner y; Item z; e.f.Item w; String q;"), "{out}");
    }

    #[test]
    fn declared_nested_name_shadows_supertype() {
        DECLARED.get_or_init(|| HashMap::from([(crate::dex::name_hash("a.b/Foo"), vec!["Foo".into(), "Factory".into()].into_boxed_slice())]));
        // `class Factory implements Factory` would be cyclic: the supertype must stay qualified
        let text = format!("package a.b;

class Foo {{
    static class Factory implements {} {{}}
}}
", m("c.d/Bar.Factory"));
        let out = resolve(&text, "a.b", "a.b/Foo");
        assert!(out.contains("implements c.d.Bar.Factory {}") && !out.contains("import"), "{out}");
    }
}
