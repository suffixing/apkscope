//! Fast, stateless query commands: classes, methods, strings, refs, decompile, manifest, diff.

use std::fmt::Write as _;
use std::io::Write as _;

use crate::cli;
use crate::quick;
use crate::session;

use crate::cli::{
    ClassesArgs, DecompileArgs, DiffArgs, ManifestArgs, MethodsArgs, RefsArgs, StringsArgs,
};

pub fn classes(a: &ClassesArgs) -> Result<(), String> {
    let apk = a.apk.as_str();
    let prefix = a.prefix.clone().unwrap_or_default();
    let (app, raw) = (a.app_only, a.desc);
    let o = cli::out_opts();
    if o.json || o.offset > 0 || o.limit != usize::MAX {
        return cli::emit_list(&quick::classes(apk, &prefix, app, raw)?);
    }
    cli::emit_stream(
        |sink| quick::classes_each(apk, &prefix, app, raw, sink),
        |w, names: Vec<String>| {
            names
                .iter()
                .try_for_each(|n| w.write_all(n.as_bytes()).and_then(|_| w.write_all(b"\n")))
        },
    )
}

pub fn methods(a: &MethodsArgs) -> Result<(), String> {
    let apk = a.apk.as_str();
    let class = a.class.clone();
    let filter = a.filter.clone().unwrap_or_default();
    let o = cli::out_opts();
    if o.json || o.offset > 0 || o.limit != usize::MAX {
        let texts = quick::methods(apk, class.as_deref(), &filter)?;
        cli::emit_list(
            &texts
                .iter()
                .flat_map(|t| t.lines().map(str::to_string))
                .collect::<Vec<_>>(),
        )
    } else {
        cli::emit_stream(
            |sink| quick::methods_each(apk, class.as_deref(), &filter, sink),
            |w, t: String| w.write_all(t.as_bytes()),
        )
    }
}

pub fn strings(a: &StringsArgs) -> Result<(), String> {
    let apk = a.apk.as_str();
    let filter = a.filter.clone().unwrap_or_default();
    cli::emit_list(&quick::strings(apk, &filter)?)
}

pub fn refs(a: &RefsArgs) -> Result<(), String> {
    let apk = a.apk.as_str();
    let kind_str = a.kind.as_str();
    let kind = quick::Kind::parse(kind_str).ok_or_else(|| {
        format!("unknown kind {kind_str}: string, type, method, field, extends, impl")
    })?;
    let text = a.query.join(" ");
    if text.is_empty() {
        return Err("refs needs a query".into());
    }
    let q = quick::Query {
        kind,
        text,
        class: a.class.clone(),
        fuzzy_class: a.fuzzy_class,
        regex: a.regex,
        ignore_case: a.ignore_case,
    };
    let java = a.java;
    let t = std::time::Instant::now();
    let o = cli::out_opts();
    let hits = quick::refs(apk, &q, o.offset.saturating_add(o.limit))?;
    let hits = &hits[o.offset.min(hits.len())..];
    // raw names, so the query text matches the decompiled lines
    let java_of = |owners: &[String]| {
        quick::decompile(apk, owners, false, false)
            .map(|v| v.into_iter().map(|(n, r)| (n, r.ok())).collect())
            .unwrap_or_default()
    };
    let text = refs_text(&q, hits, o.json, if java { Some(&java_of) } else { None })?;
    cli::emit(&text)?;
    crate::note!(
        "{} refs in {:.0} ms",
        hits.len(),
        t.elapsed().as_secs_f64() * 1000.0
    );
    Ok(())
}

/// `refs` words after the APK: kind, query and flags. Returns the query and `--java`.
/// (Kept for the MCP server's tool-call parser; the CLI handler above builds the same
/// `quick::Query` directly from clap fields.)
pub fn refs_query(mut args: Vec<String>) -> Result<(quick::Query, bool), String> {
    let class = cli::opt(&mut args, &["--class"])?;
    let (fuzzy, regex, ic, java) = (
        cli::flag(&mut args, "--fuzzy-class"),
        cli::flag(&mut args, "--regex"),
        cli::flag(&mut args, "--ignore-case"),
        cli::flag(&mut args, "--java"),
    );
    let [kind, query @ ..] = args.as_slice() else {
        return Err("usage: apkscope refs <apk> <kind> <query>".into());
    };
    let kind = quick::Kind::parse(kind).ok_or_else(|| {
        format!("unknown kind {kind}: string, type, method, field, extends, impl")
    })?;
    let q = quick::Query {
        kind,
        text: query.join(" "),
        class,
        fuzzy_class: fuzzy,
        regex,
        ignore_case: ic,
    };
    if q.text.is_empty() {
        return Err("refs needs a query".into());
    }
    Ok((q, java))
}

/// Java context for `refs_text`: decompiles the given classes,
/// (class, the lines of its text that mention the query).
pub type JavaOf<'a> = &'a dyn Fn(&[String]) -> Vec<(String, Option<String>)>;

/// Hits as text or JSON; with `java_of`, each referencing class's decompiled lines that mention
/// the query (one decompile per class).
pub fn refs_text(
    q: &quick::Query,
    hits: &[quick::Ref_],
    json: bool,
    java_of: Option<JavaOf<'_>>,
) -> Result<String, String> {
    let mut code: std::collections::HashMap<String, Vec<String>> = Default::default();
    if let Some(java_of) = java_of {
        let mut owners: Vec<String> = hits
            .iter()
            .map(|h| h.1.split("->").next().unwrap_or(&h.1).to_string())
            .collect();
        owners.sort();
        owners.dedup();
        let needle = match q.kind {
            quick::Kind::Type => q
                .text
                .trim_end_matches(';')
                .rsplit(['.', '/', '$'])
                .next()
                .unwrap_or(&q.text)
                .to_string(),
            _ => q.text.clone(),
        };
        let pat = if q.regex {
            needle
        } else {
            ::regex::escape(&needle)
        };
        let re = ::regex::RegexBuilder::new(&pat)
            .case_insensitive(q.ignore_case)
            .build()
            .map_err(|e| e.to_string())?;
        for (name, text) in java_of(&owners) {
            let lines = text
                .map(|j| {
                    j.lines()
                        .enumerate()
                        .filter(|(_, l)| re.is_match(l) && !l.starts_with("import "))
                        .map(|(n, l)| format!("{:>5}: {}", n + 1, l.trim()))
                        .collect()
                })
                .unwrap_or_default();
            code.insert(name, lines);
        }
    }
    let mut text = String::new();
    if json {
        let rows: Vec<String> = hits
            .iter()
            .map(|(d, m, w)| {
                let owner = m.split("->").next().unwrap_or(m);
                let java = code
                    .get(owner)
                    .map(|l| {
                        format!(
                            ",\"java\":[{}]",
                            l.iter()
                                .map(|x| session::json_str(x))
                                .collect::<Vec<_>>()
                                .join(",")
                        )
                    })
                    .unwrap_or_default();
                format!(
                    "{{\"dex\":{},\"from\":{},\"match\":{}{java}}}",
                    session::json_str(d),
                    session::json_str(m),
                    session::json_str(w)
                )
            })
            .collect();
        text = format!("[\n{}\n]\n", rows.join(",\n"));
    } else {
        let mut shown = std::collections::HashSet::new();
        for (d, m, w) in hits {
            let _ = writeln!(text, "{d} | {m} | matched={}", w.replace('\n', "\\n"));
            let owner = m.split("->").next().unwrap_or(m);
            if let Some(lines) = code.get(owner).filter(|_| shown.insert(owner.to_string())) {
                for l in lines {
                    let _ = writeln!(text, "    {l}");
                }
            }
        }
    }
    Ok(text)
}

pub fn decompile(a: &DecompileArgs, deobf: bool) -> Result<(), String> {
    let apk = a.apk.as_str();
    let method = &a.method;
    let (smali, full) = (a.smali, a.full);
    let mut names = a.names.clone();
    if let Some(f) = &a.classes_file {
        let list = std::fs::read_to_string(f).map_err(|e| format!("{f}: {e}"))?;
        names.extend(
            list.lines()
                .map(str::trim)
                .filter(|l| !l.is_empty() && !l.starts_with('#'))
                .map(str::to_string),
        );
    }
    let names = &names;
    if names.is_empty() {
        if a.out_dir.is_some() {
            return Err(
                "--out-dir needs class names (or --classes-file); for every class use `apkscope export`"
                    .into(),
            );
        }
        return decompile_all(apk, None, deobf);
    }
    let results: Vec<(String, Result<String, String>)> = if full {
        // whole-APK names: same output as the viewer and export
        let st = cli::load(apk, deobf)?;
        names
            .iter()
            .map(|n| {
                (
                    n.clone(),
                    st.class_text(n, smali)
                        .ok_or_else(|| format!("class {n} not found")),
                )
            })
            .collect()
    } else {
        quick::decompile(apk, names, smali, deobf)?
    };
    let mut text = String::new();
    let mut missing = Vec::new();
    let mut written = 0;
    if let Some(dir) = &a.out_dir {
        std::fs::create_dir_all(dir).map_err(|e| format!("{dir}: {e}"))?;
    }
    for (name, r) in results {
        let body = match r {
            Ok(t) => match method {
                Some(m) => match quick::method_of(&t, m) {
                    Some(x) => x,
                    None => {
                        missing.push(format!("method {m} not found in {name}"));
                        continue;
                    }
                },
                None => t + "\n",
            },
            Err(e) => {
                missing.push(e);
                continue;
            }
        };
        match &a.out_dir {
            Some(dir) => {
                let ext = if smali { "smali" } else { "java" };
                let safe = name.replace(['/', '\\', ':'], "_");
                let file = std::path::Path::new(dir).join(format!("{safe}.{ext}"));
                std::fs::write(&file, body).map_err(|e| format!("{}: {e}", file.display()))?;
                written += 1;
            }
            None => text += &body,
        }
    }
    match &a.out_dir {
        Some(dir) => crate::note!("wrote {written} file(s) to {dir}"),
        None => cli::emit(&text)?,
    }
    if missing.is_empty() {
        Ok(())
    } else {
        Err(missing.join("; "))
    }
}

fn decompile_all(path: &str, class: Option<&str>, deobf: bool) -> Result<(), String> {
    let mut apk = crate::export::open(&session::prepare(path)?)?;
    // 'static so inline string decryption can reach every DEX
    let raw: &'static [Vec<u8>] = Box::leak(
        apk.dex()?
            .into_iter()
            .map(|(_, b)| b)
            .collect::<Vec<_>>()
            .into_boxed_slice(),
    );
    let dexes: Vec<crate::dex::Dex<'static>> = raw
        .iter()
        .filter_map(|b| crate::dex::Dex::parse(b).ok())
        .collect();
    if deobf {
        crate::deobf::init(&dexes);
    }
    crate::deobf::set_notes(crate::re::load_notes(path)?);
    crate::re::set_dexes(Box::leak(
        raw.iter()
            .filter_map(|b| crate::dex::Dex::parse(b).ok())
            .collect::<Vec<_>>()
            .into_boxed_slice(),
    ));
    crate::imports::init(&dexes);
    let mut out = std::io::BufWriter::new(std::io::stdout().lock());
    let mut found = false;
    'all: for dex in &dexes {
        let nest = dex.nesting();
        for (c, parent) in nest.parent.iter().enumerate() {
            let desc = dex.class_descriptor(c).unwrap_or_default();
            // accept the readable name or the original one
            let raw = desc
                .trim_start_matches('L')
                .trim_end_matches(';')
                .replace('/', ".");
            match class {
                Some(want) if want != crate::dex::java_name(&desc) && want != raw => continue,
                None if parent.is_some() => continue, // printed inside its outer class
                _ => {}
            }
            found = true;
            match crate::java::class(dex, c) {
                Ok(s) => {
                    let _ = writeln!(out, "{s}");
                }
                Err(e) => {
                    let _ = writeln!(out, "/* class {c} failed: {e} */");
                }
            }
            if class.is_some() {
                break 'all;
            }
        }
    }
    let _ = out.flush();
    match class {
        Some(c) if !found => Err(format!("class {c} not found")),
        _ => Ok(()),
    }
}

pub fn manifest(a: &ManifestArgs) -> Result<(), String> {
    let apk = a.apk.as_str();
    let m = quick::read_entry(apk, "AndroidManifest.xml")?.ok_or("no AndroidManifest.xml")?;
    let table =
        quick::read_entry(apk, "resources.arsc")?.and_then(|d| apkscope_core::table::read(&d).ok());
    let names = table.as_ref().map(apkscope_core::res::Names::new);
    cli::emit(&apkscope_core::res::decode_xml(&m, names.as_ref())?)
}

pub fn diff(a: &DiffArgs) -> Result<(), String> {
    let old = a.old.as_str();
    let new = a.new.as_str();
    cli::emit_list(&quick::diff(old, new, a.strings, a.app_only)?)
}
