//! One opened APK and everything that searches it: the reference index, the decompiled-code
//! cache, scoped searches, usages, result export and the manifest overview. Shared by the
//! viewer and the `search` command.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock, RwLock};

use crate::dex::{self, Dex};
use crate::export::{self, Apk};
use crate::index::{self, Index};
use crate::{bytecode, cache, elf, java, res};

/// Worker threads for indexing and searching (0 = all cores).
pub static THREADS: AtomicUsize = AtomicUsize::new(0);

/// Whether a full scan may write the decompiled-code cache.
pub static CACHE_WRITE: AtomicBool = AtomicBool::new(true);

pub fn threads() -> usize {
    match THREADS.load(Ordering::Relaxed) {
        0 => std::thread::available_parallelism().map_or(4, |n| n.get()),
        n => n,
    }
}

/// Resident memory of this process, in bytes.
#[cfg(feature = "gui")]
pub fn memory_used() -> Option<u64> {
    #[cfg(windows)]
    {
        #[repr(C)]
        #[derive(Default)]
        struct Counters {
            cb: u32,
            faults: u32,
            peak_ws: usize,
            ws: usize,
            a: usize,
            b: usize,
            c: usize,
            d: usize,
            pagefile: usize,
            peak_pagefile: usize,
        }
        unsafe extern "system" {
            fn GetCurrentProcess() -> isize;
            fn K32GetProcessMemoryInfo(p: isize, c: *mut Counters, cb: u32) -> i32;
        }
        let mut c = Counters {
            cb: std::mem::size_of::<Counters>() as u32,
            ..Default::default()
        };
        // safety: c is a correctly sized PROCESS_MEMORY_COUNTERS that outlives the call
        let ok = unsafe { K32GetProcessMemoryInfo(GetCurrentProcess(), &mut c, c.cb) };
        (ok != 0).then_some(c.ws as u64)
    }
    #[cfg(not(windows))]
    {
        let s = std::fs::read_to_string("/proc/self/statm").ok()?;
        s.split_whitespace()
            .nth(1)?
            .parse::<u64>()
            .ok()
            .map(|p| p * 4096)
    }
}

/// Where a top-level class comes from.
#[derive(Clone, Copy, PartialEq, Debug)]
pub enum Origin {
    /// the app's own package
    App,
    /// unknown or obfuscated packages: may well be app code
    Other,
    /// a known SDK or library
    Library,
}

/// Package prefixes of common Android SDKs and libraries (Java names, dot-terminated).
const LIBRARIES: &[&str] = &[
    "android.",
    "androidx.",
    "com.android.",
    "dalvik.",
    "java.",
    "javax.",
    "kotlin.",
    "kotlinx.",
    "org.jetbrains.",
    "org.intellij.",
    "com.google.",
    "com.squareup.",
    "okhttp3.",
    "okio.",
    "retrofit2.",
    "io.reactivex.",
    "rx.",
    "io.grpc.",
    "com.facebook.",
    "com.bumptech.",
    "dagger.",
    "hilt_aggregated_deps.",
    "com.fasterxml.",
    "org.json.",
    "org.apache.",
    "org.slf4j.",
    "ch.qos.",
    "com.airbnb.",
    "io.sentry.",
    "com.crashlytics.",
    "io.fabric.",
    "com.adjust.",
    "com.appsflyer.",
    "com.unity3d.",
    "com.applovin.",
    "com.ironsource.",
    "com.mopub.",
    "com.chartboost.",
    "com.vungle.",
    "com.inmobi.",
    "com.amazon.",
    "com.microsoft.",
    "org.chromium.",
    "io.flutter.",
    "com.facebook.react.",
    "org.greenrobot.",
    "net.sqlcipher.",
    "org.bouncycastle.",
    "org.conscrypt.",
    "com.tencent.",
    "com.huawei.",
    "io.branch.",
    "com.onesignal.",
    "com.revenuecat.",
    "io.realm.",
    "org.koin.",
    "coil.",
    "com.github.",
    "io.ktor.",
    "org.reactivestreams.",
    "com.jakewharton.",
    "timber.",
    "io.opentelemetry.",
    "com.braze.",
    "com.mixpanel.",
    "com.segment.",
    "com.stripe.",
    "com.paypal.",
    "com.yandex.",
    "com.bytedance.sdk.",
];

/// Origin of a class by its (displayed) Java name. App code is the manifest package's
/// organization (`com.unciv.app` -> `com.unciv`), since apps often keep code beside the
/// launcher package; known libraries are checked first.
pub fn origin(name: &str, package: &str) -> Origin {
    if LIBRARIES.iter().any(|p| name.starts_with(p)) {
        return Origin::Library;
    }
    let parts: Vec<&str> = package.split('.').collect();
    let root = if parts.len() >= 3 {
        parts[..2].join(".")
    } else {
        package.to_string()
    };
    if !root.is_empty() && name.starts_with(&root) && name[root.len()..].starts_with('.') {
        Origin::App
    } else {
        Origin::Other
    }
}

/// One-line meanings of well-known native libraries, shared by `info` and `flutter`. Small
/// and factual on purpose: one line per library, nothing for unknowns.
pub fn native_lib_meaning(path: &str) -> Option<&'static str> {
    let name = path.rsplit('/').next()?.to_ascii_lowercase();
    Some(match name.as_str() {
        "libpdfium.so" | "libmupdf.so" | "libmupdf_java.so" => "in-app PDF rendering",
        "libapp.so" => "Flutter Dart AOT snapshot",
        "libflutter.so" => "Flutter engine",
        "libunity.so" => "Unity engine",
        "libil2cpp.so" => "Unity IL2CPP (C# compiled to native code)",
        "libhermes.so" => "React Native Hermes JS engine",
        "libjsc.so" => "React Native JavaScriptCore engine",
        "libc++_shared.so" => "NDK C++ runtime",
        "libjiagu.so" => "packer: 360 Jiagu",
        "libnesec.so" => "packer: NetEase",
        "libsecshell.so" | "libsecexe.so" => "packer: Bangcle",
        "libmobisec.so" => "packer: Tencent Legu",
        "libtprt.so" => "Tencent X5 WebView",
        _ if name.starts_with("libjiagu_") => "packer: 360 Jiagu",
        _ if name.starts_with("libdexhelper") => "packer: SecNeo",
        _ if name.starts_with("libshella") => "packer: SecNeo",
        _ => return None,
    })
}

pub struct State {
    pub path: String,
    /// the APK actually read (differs from `path` for bundles and .dex)
    pub file: String,
    pub dexes: Vec<Dex<'static>>,
    /// top-level classes: (java name, dex, class index); the position is the class id
    pub classes: Vec<(String, usize, usize)>,
    /// res path -> text (manifest, values XML) decoded at startup
    pub texts: BTreeMap<String, String>,
    /// res path -> path inside the APK, decoded on demand
    pub files: BTreeMap<String, String>,
    names: Option<res::Names>,
    apk: Mutex<Apk>,
    /// every zip entry name, for the overview
    pub entries: Vec<String>,
    pub package: String,
    pub methods: usize,
    /// origin of each top-level class (same order as `classes`)
    pub origin: Vec<Origin>,
    natives: OnceLock<Vec<(String, String)>>,
    pub index: OnceLock<Index>,
    pub indexed: AtomicUsize,
    cache: RwLock<Option<Arc<cache::Reader>>>,
    cache_dir: std::path::PathBuf,
}

/// What apkscope opens, for file dialogs and the start screen.
pub const INPUTS: [&str; 6] = ["apk", "jar", "apks", "xapk", "apkm", "dex"];

/// Turn any supported input into an APK path: a `.jar` of DEX files (Android's framework JARs)
/// reads as one, split bundles (`.apks`, `.xapk`, `.apkm`) give their `base.apk`, a bare `.dex`
/// is wrapped in a minimal APK. Both land in the cache folder.
pub fn prepare(path: &str) -> Result<String, String> {
    use std::io::{Read, Write};
    let ext = std::path::Path::new(path)
        .extension()
        .map(|e| e.to_string_lossy().to_lowercase())
        .unwrap_or_default();
    let stem = std::path::Path::new(path)
        .file_stem()
        .map_or("input".into(), |s| s.to_string_lossy().into_owned());
    let dir = cache::root().join("inputs");
    match ext.as_str() {
        "apk" | "jar" => Ok(path.to_string()),
        "apks" | "xapk" | "apkm" => {
            // all three are plain ZIPs of split APKs; `.apkm` was encrypted before 2021,
            // but APKMirror now serves it as a regular ZIP, same as `.apks`/`.xapk`.
            let f = std::fs::File::open(path).map_err(|e| format!("{path}: {e}"))?;
            let mut zip = zip::ZipArchive::new(f).map_err(|e| format!("{path}: {e}"))?;
            let names: Vec<String> = zip
                .file_names()
                .filter_map(|n| n.ok().map(|n| n.into_owned()))
                .filter(|n| n.ends_with(".apk"))
                .collect();
            // the base split holds the code; fall back to the largest APK inside
            let base = names
                .iter()
                .find(|n| n.rsplit('/').next() == Some("base.apk"))
                .cloned()
                .or_else(|| {
                    names
                        .iter()
                        .max_by_key(|n| zip.by_name(n).map(|e| e.size()).unwrap_or(0))
                        .cloned()
                });
            let base = base.ok_or("no APK inside this bundle")?;
            let size = zip.by_name(&base).map_err(|e| e.to_string())?.size();
            let out = dir.join(format!("{stem}-{size:x}-base.apk"));
            if !out.exists() {
                std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
                let mut data = Vec::new();
                zip.by_name(&base)
                    .map_err(|e| e.to_string())?
                    .read_to_end(&mut data)
                    .map_err(|e| e.to_string())?;
                std::fs::write(&out, data).map_err(|e| e.to_string())?;
            }
            Ok(out.display().to_string())
        }
        "dex" => {
            let data = std::fs::read(path).map_err(|e| format!("{path}: {e}"))?;
            Dex::parse(&data).map_err(|e| format!("{path}: {e}"))?;
            let out = dir.join(format!("{stem}-{:x}.apk", data.len()));
            std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
            let mut w =
                zip::ZipWriter::new(std::fs::File::create(&out).map_err(|e| e.to_string())?);
            let opts = zip::write::SimpleFileOptions::default()
                .compression_method(zip::CompressionMethod::Stored);
            w.start_file("classes.dex", opts)
                .map_err(|e| e.to_string())?;
            w.write_all(&data).map_err(|e| e.to_string())?;
            w.finish().map_err(|e| e.to_string())?;
            Ok(out.display().to_string())
        }
        _ => Err(format!(
            "apkscope opens {}; not .{ext}",
            INPUTS.map(|e| format!(".{e}")).join(", ")
        )),
    }
}

pub fn load(path: &str, deobf: bool) -> Result<State, String> {
    let real = prepare(path)?;
    let mut apk = export::open(&real)?;
    // a session lives until the process exits, so the DEX bytes can be 'static
    let raw: Vec<&'static [u8]> = std::mem::take(&mut apk.dex)
        .into_iter()
        .map(|(_, b)| &*Box::leak(b.into_boxed_slice()))
        .collect();
    let dexes: Vec<Dex<'static>> = raw.iter().filter_map(|b| Dex::parse(b).ok()).collect();
    if deobf {
        crate::deobf::init(&dexes);
    }
    let notes = crate::re::load_notes(path)?;
    let tag = crate::re::notes_tag(&notes);
    crate::deobf::set_notes(notes);
    // inline string decryption needs every DEX, from any thread
    crate::re::set_dexes(Box::leak(
        raw.iter()
            .filter_map(|b| Dex::parse(b).ok())
            .collect::<Vec<_>>()
            .into_boxed_slice(),
    ));
    crate::imports::init(&dexes);
    let mut classes = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for (d, dx) in dexes.iter().enumerate() {
        let nest = dx.nesting();
        for (c, parent) in nest.parent.iter().enumerate() {
            if parent.is_none()
                && let Ok(desc) = dx.class_descriptor(c)
                && seen.insert(desc.clone())
            {
                classes.push((dex::java_name(&desc), d, c));
            }
        }
    }
    classes.sort();
    let entries: Vec<String> = apk
        .zip
        .file_names()
        .filter_map(|n| n.ok().map(|n| n.into_owned()))
        .collect();
    let table = apk
        .read("resources.arsc")
        .and_then(|d| apkscope_core::table::read(&d).ok());
    let names = table.as_ref().map(res::Names::new);
    let mut texts = BTreeMap::new();
    let mut files = BTreeMap::new();
    let mut package = String::new();
    if let Some(m) = apk.read("AndroidManifest.xml")
        && let Ok(t) = res::decode_xml(&m, names.as_ref())
    {
        package = attr(&t, "package").unwrap_or_default();
        texts.insert("AndroidManifest.xml".to_string(), t);
    }
    if let (Some(t), Some(n)) = (&table, &names) {
        let dec = res::decode_table(t, n);
        for (p, text) in dec.values {
            texts.insert(format!("res/{p}"), text);
        }
        for (p, src) in dec.files {
            files.insert(format!("res/{p}"), src);
        }
    }
    let methods = dexes
        .iter()
        .map(|d| {
            (0..d.class_count)
                .map(|c| d.class_data(c).map_or(0, |x| x.methods.len()))
                .sum::<usize>()
        })
        .sum();
    let origin = classes
        .iter()
        .map(|c| self::origin(&c.0, &package))
        .collect();
    let cache_dir = cache::dir_for(&real, deobf, tag);
    let reader = cache::Reader::open(&cache_dir, classes.len()).map(Arc::new);
    Ok(State {
        path: path.to_string(),
        file: real.clone(),
        dexes,
        classes,
        texts,
        files,
        names,
        apk: Mutex::new(apk),
        entries,
        package,
        methods,
        origin,
        natives: OnceLock::new(),
        index: OnceLock::new(),
        indexed: AtomicUsize::new(0),
        cache: RwLock::new(reader),
        cache_dir,
    })
}

impl State {
    /// Build the reference index (call once, off the UI thread).
    pub fn build_index(&self) {
        let list: Vec<(usize, usize)> = self.classes.iter().map(|c| (c.1, c.2)).collect();
        let idx = index::build(&self.dexes, &list, threads(), &self.indexed);
        let _ = self.index.set(idx);
    }

    pub fn cached(&self) -> bool {
        self.cache.read().unwrap().is_some()
    }

    /// Top-level class by its shown name, or by its original (obfuscated) name or descriptor.
    pub fn find(&self, name: &str) -> Option<usize> {
        let by = |n: &str| self.classes.binary_search_by(|c| c.0.as_str().cmp(n)).ok();
        by(name).or_else(|| {
            let desc = if name.starts_with('L') && name.ends_with(';') {
                name.to_string()
            } else {
                format!("L{};", name.replace('.', "/"))
            };
            by(&dex::java_name(&desc))
        })
    }

    /// Origin of a class by its Java name: its id when it is a top-level class, otherwise
    /// computed from the name and the manifest package.
    pub fn origin_of(&self, name: &str) -> Origin {
        match self.find(name) {
            Some(k) => self.origin[k],
            None => origin(name, &self.package),
        }
    }

    /// Java of top-level class `k`, from the cache when there is one.
    fn java_of(
        &self,
        k: usize,
        reader: Option<(&cache::Reader, &mut std::fs::File)>,
    ) -> Option<String> {
        if let Some((r, f)) = reader
            && let Some(t) = r.get(f, k)
        {
            return Some(t);
        }
        let (_, d, c) = &self.classes[k];
        java::class(&self.dexes[*d], *c).ok()
    }

    pub fn class_text(&self, name: &str, smali: bool) -> Option<String> {
        let k = self.find(name)?;
        let (_, d, c) = &self.classes[k];
        let dx = &self.dexes[*d];
        if !smali {
            let reader = self.cache.read().unwrap().clone();
            let mut f = reader.as_ref().and_then(|r| r.file());
            let text = match (&reader, f.as_mut()) {
                (Some(r), Some(f)) => self.java_of(k, Some((r, f))),
                _ => None,
            };
            return Some(text.unwrap_or_else(|| {
                java::class(dx, *c).unwrap_or_else(|e| format!("/* failed: {e} */"))
            }));
        }
        Some(self::smali(dx, *c))
    }

    /// Text of a resource; binary files are described, not shown.
    pub fn resource(&self, path: &str) -> Option<String> {
        if let Some(t) = self.texts.get(path) {
            return Some(t.clone());
        }
        // only paths from the table can be read, so nothing can reach other zip entries
        let src = self.files.get(path)?;
        let data = self.apk.lock().ok()?.read(src)?;
        match res::decode_xml(&data, self.names.as_ref()) {
            Ok(t) => Some(t),
            Err(_) => Some(format!("// binary file, {} bytes ({src})", data.len())),
        }
    }

    pub fn is_res(&self, t: &str) -> bool {
        self.texts.contains_key(t) || self.files.contains_key(t)
    }

    pub fn is_native(&self, t: &str) -> bool {
        t.ends_with(".so") && self.entries.iter().any(|e| e == t)
    }

    /// Text of a hit's target: decompiled class, resource or native-library report.
    pub fn target_text(&self, t: &str) -> Option<String> {
        if self.is_native(t) {
            Some(self.native_report(t))
        } else if self.is_res(t) {
            self.resource(t)
        } else {
            self.class_text(t, false)
        }
    }

    /// Raw bytes of any file inside the APK (only names from its own listing).
    /// Edited manifest text -> binary XML, typed like the APK's own manifest.
    #[cfg(feature = "gui")]
    pub fn encode_manifest(&self, text: &str) -> Result<Vec<u8>, String> {
        let names = self
            .names
            .as_ref()
            .ok_or("this APK has no resources.arsc to resolve @references")?;
        Ok(crate::axml::encode(
            text,
            self.read_entry("AndroidManifest.xml").as_deref(),
            names,
        )?)
    }

    pub fn read_entry(&self, name: &str) -> Option<Vec<u8>> {
        if !self.entries.iter().any(|e| e == name) {
            return None;
        }
        self.apk.lock().ok()?.read(name)
    }

    /// `minSdkVersion` from the manifest.
    #[cfg(feature = "gui")]
    pub fn min_sdk(&self) -> Option<u32> {
        let m = self.texts.get("AndroidManifest.xml")?;
        let at = m.find("<uses-sdk")?;
        attr(&m[at..], "android:minSdkVersion")?.parse().ok()
    }

    /// Every file in the APK as (name, size, compressed size).
    #[cfg(feature = "gui")]
    pub fn files_list(&self) -> Vec<(String, u64, u64)> {
        let mut apk = self.apk.lock().unwrap();
        let mut v: Vec<(String, u64, u64)> = self
            .entries
            .iter()
            .filter(|e| !e.ends_with('/'))
            .map(|e| {
                let (s, c) = apk
                    .zip
                    .by_name(e)
                    .map_or((0, 0), |f| (f.size(), f.compressed_size()));
                (e.clone(), s, c)
            })
            .collect();
        v.sort();
        v
    }

    /// A file inside the APK shown as text: its content when it is text, else a hex dump.
    #[cfg(feature = "gui")]
    pub fn file_view(&self, name: &str) -> String {
        let Some(d) = self.read_entry(name) else {
            return format!("// {name}: not found");
        };
        let mut o = format!(
            "// {name}
// {} bytes

",
            d.len()
        );
        if let Ok(t) = res::decode_xml(&d, self.names.as_ref()) {
            return o + &t;
        }
        match std::str::from_utf8(&d) {
            Ok(t) if d.len() < 4 << 20 && !t.contains('\0') => o + t,
            _ => {
                for (k, row) in d.chunks(16).take(256).enumerate() {
                    let hexs: String = row.iter().map(|b| format!("{b:02x} ")).collect();
                    let text: String = row
                        .iter()
                        .map(|&b| {
                            if (0x20..0x7f).contains(&b) {
                                b as char
                            } else {
                                '.'
                            }
                        })
                        .collect();
                    let _ = writeln!(o, "{:08x}  {hexs:<48} {text}", k * 16);
                }
                if d.len() > 4096 {
                    let _ = writeln!(
                        o,
                        "
// first 4096 bytes shown; extract the file for the rest"
                    );
                }
                o
            }
        }
    }

    /// Write every file of the APK under `dir`, skipping names that would escape it.
    #[cfg(feature = "gui")]
    pub fn extract_all(&self, dir: &std::path::Path) -> Result<usize, String> {
        let mut n = 0;
        for (name, _, _) in self.files_list() {
            let rel = std::path::Path::new(&name);
            if name.contains("..") || rel.is_absolute() || name.contains(':') {
                continue;
            }
            let out = dir.join(rel);
            if let Some(p) = out.parent() {
                std::fs::create_dir_all(p).map_err(|e| e.to_string())?;
            }
            if let Some(d) = self.read_entry(&name) {
                std::fs::write(&out, d).map_err(|e| format!("{}: {e}", out.display()))?;
                n += 1;
            }
        }
        Ok(n)
    }

    /// Native libraries as (path, uncompressed size), grouped by ABI folder.
    pub fn native_libs(&self) -> Vec<(String, u64)> {
        let mut apk = self.apk.lock().unwrap();
        let mut v: Vec<(String, u64)> = self
            .entries
            .iter()
            .filter(|e| e.starts_with("lib/") && e.ends_with(".so"))
            .map(|e| (e.clone(), apk.zip.by_name(e).map_or(0, |f| f.size())))
            .collect();
        v.sort();
        v
    }

    /// Java methods declared `native`, as (class, method) with their original (JNI) names.
    pub fn native_methods(&self) -> &[(String, String)] {
        self.natives.get_or_init(|| {
            let mut v = Vec::new();
            for dx in &self.dexes {
                for c in 0..dx.class_count {
                    let Ok(data) = dx.class_data(c) else { continue };
                    for m in data.methods.iter().filter(|m| m.access & 0x100 != 0) {
                        if let (Ok(desc), Ok((_, name, _))) =
                            (dx.class_descriptor(c), dx.method_parts(m.method_idx))
                        {
                            v.push((
                                desc.trim_start_matches('L')
                                    .trim_end_matches(';')
                                    .replace(['/', '$'], "."),
                                name,
                            ));
                        }
                    }
                }
            }
            v.sort();
            v.dedup();
            v
        })
    }

    /// Readable report of one native library.
    pub fn native_report(&self, path: &str) -> String {
        let Some(data) = self.read_entry(path) else {
            return format!("// {path}: not found");
        };
        let mut o = String::new();
        let _ = writeln!(
            o,
            "// {path}
"
        );
        let e = match elf::parse(&data) {
            Ok(e) => e,
            Err(err) => return format!("{o}// {err}, {} bytes", data.len()),
        };
        let _ = writeln!(o, "size              {} bytes", data.len());
        let _ = writeln!(o, "architecture      {} ({}-bit)", e.machine, e.bits);
        let _ = writeln!(
            o,
            "JNI_OnLoad        {}",
            if e.exports.iter().any(|x| x == "JNI_OnLoad") {
                "yes: natives may also be registered at runtime (RegisterNatives), which can't be mapped statically"
            } else {
                "no"
            }
        );
        let _ = writeln!(
            o,
            "
// needs ({})",
            e.needed.len()
        );
        for n in &e.needed {
            let _ = writeln!(o, "{n}");
        }
        let natives = self.native_methods();
        let jni: Vec<(&String, (String, String))> = e
            .exports
            .iter()
            .filter_map(|x| elf::jni_target(x).map(|t| (x, t)))
            .collect();
        let _ = writeln!(
            o,
            "
// JNI exports -> Java native methods ({})",
            jni.len()
        );
        for (sym, (cls, m)) in &jni {
            let found = natives.binary_search(&(cls.clone(), m.clone())).is_ok();
            let _ = writeln!(
                o,
                "{cls}.{m}(){}    <- {sym}",
                if found {
                    ""
                } else {
                    "    (no such native method in the DEX)"
                }
            );
        }
        let _ = writeln!(
            o,
            "
// other exports ({})",
            e.exports.len() - jni.len()
        );
        for x in e
            .exports
            .iter()
            .filter(|x| !x.starts_with("Java_"))
            .take(2000)
        {
            let _ = writeln!(o, "{x}");
        }
        let all = elf::strings(&data, 6);
        let url = regex::Regex::new(URL_RE).unwrap();
        let secret = regex::Regex::new(SECRET_RE).unwrap();
        let interesting: Vec<&String> = all
            .iter()
            .filter(|s| {
                url.is_match(&format!("\"{s}\""))
                    || secret.is_match(&format!("\"{s}\""))
                    || secret.is_match(s)
            })
            .collect();
        let _ = writeln!(
            o,
            "
// URL- or key-like strings ({}). Heuristic: encrypted or computed values won't show",
            interesting.len()
        );
        for s in &interesting {
            let _ = writeln!(o, "{s}");
        }
        let _ = writeln!(
            o,
            "
// all strings, 6+ characters ({}{})",
            all.len().min(5000),
            if all.len() > 5000 { ", first 5000" } else { "" }
        );
        for s in all.iter().take(5000) {
            let _ = writeln!(o, "{s}");
        }
        o
    }

    /// Forget this APK's cache (after the user cleared the cache folder).
    pub fn drop_cache(&self) {
        *self.cache.write().unwrap() = None;
    }

    /// Strings of the app containing `needle` (case-insensitive), with how many classes use each.
    #[cfg(feature = "gui")]
    pub fn strings(&self, needle: &str, limit: usize) -> Vec<(String, usize)> {
        let low = needle.to_lowercase();
        let idx = self.index.get();
        let mut out = Vec::new();
        for (d, dx) in self.dexes.iter().enumerate() {
            for id in 0..dx.counts()[0] {
                let Ok(s) = dx.string(id as u32) else {
                    continue;
                };
                if !s.trim().is_empty() && s.to_lowercase().contains(&low) {
                    let users = idx.map_or(0, |i| i.users(d, index::STRING, id).len());
                    out.push((s, users));
                    if out.len() >= limit {
                        return out;
                    }
                }
            }
        }
        out
    }
}

pub const LIMIT: usize = 5000;

#[derive(Clone, Copy, PartialEq, Debug)]
pub enum Scope {
    Class,
    Code,
    String,
    Usages,
    Res,
    Urls,
    Http,
    Secrets,
    Api,
}

impl Scope {
    #[cfg(feature = "gui")]
    pub const ALL: [Scope; 9] = [
        Scope::Code,
        Scope::String,
        Scope::Usages,
        Scope::Class,
        Scope::Res,
        Scope::Urls,
        Scope::Http,
        Scope::Secrets,
        Scope::Api,
    ];

    #[cfg(feature = "gui")]
    pub fn label(self) -> &'static str {
        match self {
            Scope::Class => "Class names",
            Scope::Code => "Code",
            Scope::String => "String literals",
            Scope::Usages => "Usages (xref)",
            Scope::Res => "Resources",
            Scope::Urls => "URLs & endpoints",
            Scope::Http => "HTTP / API calls",
            Scope::Secrets => "Keys & secrets",
            Scope::Api => "HTTP API (Retrofit)",
        }
    }

    pub fn parse(s: &str) -> Option<Scope> {
        Some(match s {
            "class" => Scope::Class,
            "code" => Scope::Code,
            "string" => Scope::String,
            "usages" | "xref" => Scope::Usages,
            "res" => Scope::Res,
            "urls" => Scope::Urls,
            "http" => Scope::Http,
            "secrets" => Scope::Secrets,
            "api" => Scope::Api,
            _ => return None,
        })
    }

    /// API scopes list everything they find; the query only narrows them
    pub fn query_optional(self) -> bool {
        matches!(
            self,
            Scope::Urls | Scope::Http | Scope::Secrets | Scope::Api
        )
    }

    /// scopes that read decompiled classes
    pub fn decompiles(self) -> bool {
        !matches!(self, Scope::Class | Scope::Res)
    }

    /// What the scope can miss: shown next to the results.
    pub fn note(self) -> &'static str {
        match self {
            Scope::Code => {
                "Searches decompiled Java. Names are shown after deobfuscation, so search for what you see in the viewer."
            }
            Scope::String => {
                "Matches string literals as stored in the app. Strings built at runtime, encrypted or loaded from native code won't appear."
            }
            Scope::Usages => {
                "Finds classes that reference a method, field, class or string with this name, then the lines that mention it. Calls made via reflection, JNI or dynamic loading are not visible."
            }
            Scope::Class => "Matches class names (deobfuscated).",
            Scope::Res => {
                "Searches decoded XML resources and the manifest, plus resource file names."
            }
            Scope::Urls => {
                "Heuristic: finds URL-like string literals. Endpoints built at runtime, encrypted, downloaded from a config, or kept in native libraries won't be found, and some hits are documentation or ad URLs. App code only by default; --all includes library code."
            }
            Scope::Http => {
                "Heuristic: finds common networking APIs (Retrofit, OkHttp, HttpURLConnection). Apps using other libraries, their own wrappers, native code or obfuscated networking may not show up, and library code shows up too. App code only by default; --all includes library code."
            }
            Scope::Secrets => {
                "Heuristic: finds well-known key formats and key-like names, plus a labelled lower-confidence entropy tier of the app's own string constants. A hit is not proof of a leaked secret (many keys are meant to be public), and keys that are encrypted, split or fetched at runtime won't be found. App code only by default; --all includes library code."
            }
            Scope::Api => {
                "Retrofit-annotated interfaces only: verb, path, parameters and base URL read from the annotations. Generic return types are erased in the DEX, so response models and call-site arguments are inferred from the interface's callers and labelled as such. Dynamic paths and non-Retrofit HTTP calls don't show up (see urls / http)."
            }
        }
    }
}

const URL_RE: &str = r#""((?:https?|wss?)://[^"\s]+|/(?:api|v\d+|rest|graphql|auth|oauth|user|users|login)\b[^"\s]*)""#;
const HTTP_RE: &str = r"@(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS|HTTP|Headers?|Query|QueryMap|Path|Body|Field|FieldMap|FormUrlEncoded|Multipart|Part|Url)\b|\bRequest\.Builder|\.url\(|\.newCall\(|HttpURLConnection|openConnection\(|\.addHeader\(|\.header\(|Retrofit\.Builder|\.baseUrl\(|setRequestMethod\(|HttpUrl\.(parse|get)\(|WebSocket";
pub(crate) const SECRET_RE: &str = r#"AIza[0-9A-Za-z_\-]{35}|AKIA[0-9A-Z]{16}|(sk|pk|rk)_(live|test)_[0-9A-Za-z]{16,}|gh[pousr]_[0-9A-Za-z]{36}|xox[baprs]-[0-9A-Za-z\-]{10,}|eyJ[0-9A-Za-z_\-]{10,}\.[0-9A-Za-z_\-]{10,}|(?i)"(authorization|bearer ?|x-api-key|api[_-]?key|x-auth-token|client[_-]?secret|access[_-]?token)"|(?i)\b\w*(api_?key|secret|token|password|passwd|client_?id|private_?key|access_?key|auth_?header|sign_?key|signing_?salt|hmac_?key|hash_?key|encryption_?key|license_?key|merchant_?id|partner_?code)\w*\s*=\s*"[^"]{6,}"|(?i)name="[^"]*(api_?key|secret|token|client_?id|app_?id|private_?key|access_?key|auth_?header|sign_?key|signing_?salt|hmac_?key|hash_?key|encryption_?key|license_?key|merchant_?id|partner_?code)[^"]*">[^<\s]{6,}<"#;
/// prefilter for HTTP: types and member names a matching line would mention
const HTTP_TYPES_RE: &str = r"retrofit2/|okhttp3/(Request|HttpUrl|WebSocket|Call|OkHttpClient)|Https?URLConnection|WebSocket";
const HTTP_MEMBERS: [&str; 7] = [
    "openConnection",
    "addHeader",
    "header",
    "newCall",
    "baseUrl",
    "setRequestMethod",
    "url",
];
const SECRET_NAME_RE: &str = r"(?i)api_?key|secret|token|password|passwd|client_?id|private_?key|access_?key|auth_?header|sign_?key|signing_?salt|hmac_?key|hash_?key|encryption_?key|license_?key|merchant_?id|partner_?code";

/// What one search looks for: an optional user query plus the scope's own pattern.
pub struct Matcher {
    pub scope: Scope,
    /// skip classes from known libraries
    pub app_only: bool,
    query: Option<regex::Regex>,
    builtin: Option<regex::Regex>,
}

impl Matcher {
    pub fn new(q: &str, scope: Scope, use_regex: bool, case: bool) -> Result<Matcher, String> {
        let query = if q.is_empty() {
            None
        } else {
            let pat = if use_regex {
                q.to_string()
            } else {
                regex::escape(q)
            };
            Some(
                regex::RegexBuilder::new(&pat)
                    .case_insensitive(!case)
                    .build()
                    .map_err(|e| e.to_string())?,
            )
        };
        let builtin = match scope {
            Scope::Urls => Some(URL_RE),
            Scope::Http => Some(HTTP_RE),
            Scope::Secrets => Some(SECRET_RE),
            _ => None,
        }
        .map(|p| regex::Regex::new(p).unwrap());
        Ok(Matcher {
            scope,
            app_only: false,
            query,
            builtin,
        })
    }

    fn query_hits(&self, s: &str) -> bool {
        self.query.as_ref().is_none_or(|q| q.is_match(s))
    }

    pub fn line(&self, l: &str) -> bool {
        if self.builtin.is_some() && l.trim_start().starts_with("import ") {
            return false;
        }
        match (&self.builtin, self.scope) {
            // XML namespaces and spec URLs are identifiers, not endpoints
            (Some(b), Scope::Urls) => {
                const NOISE: [&str; 6] = [
                    "schemas.android.com",
                    "www.w3.org",
                    "ns.adobe.com",
                    "www.apache.org/licenses",
                    "xmlpull.org",
                    "schemas.xmlsoap.org",
                ];
                if !b
                    .captures_iter(l)
                    .any(|c| !NOISE.iter().any(|n| c[1].contains(n)))
                {
                    return false;
                }
            }
            (Some(b), _) if !b.is_match(l) => return false,
            _ => {}
        }
        match (&self.query, self.scope) {
            (None, _) => true,
            // only inside a string literal
            (Some(q), Scope::String) => l.split('"').skip(1).step_by(2).any(|lit| q.is_match(lit)),
            (Some(q), _) => q.is_match(l),
        }
    }
}

/// (target: class or resource path, line, text)
pub type Hit = (String, usize, String);

/// Shared with the caller: how far a search got, and a flag to stop it.
#[derive(Default)]
pub struct Progress {
    pub done: AtomicUsize,
    pub total: AtomicUsize,
    pub cancel: AtomicBool,
}

/// Classes that can contain a match, from the index; None = every class must be read.
fn candidates(st: &State, m: &Matcher) -> Option<Vec<usize>> {
    let idx = st.index.get()?;
    let wants = |kind: usize| match m.scope {
        Scope::String | Scope::Urls => kind == index::STRING,
        Scope::Usages | Scope::Secrets => true,
        Scope::Http => kind != index::STRING,
        _ => false,
    };
    if !(0..4).any(wants) {
        return None;
    }
    let http_types = regex::Regex::new(HTTP_TYPES_RE).unwrap();
    let secret_names = regex::Regex::new(SECRET_NAME_RE).unwrap();
    let mut hit = vec![false; st.classes.len()];
    let tables: Vec<(usize, usize)> = st
        .dexes
        .iter()
        .enumerate()
        .flat_map(|(d, _)| (0..4).filter(|&k| wants(k)).map(move |k| (d, k)))
        .collect();
    // one table per task: strings of a big DEX are the slow part
    let found = Mutex::new(Vec::new());
    let next = AtomicUsize::new(0);
    std::thread::scope(|s| {
        for _ in 0..threads().min(tables.len()).max(1) {
            s.spawn(|| {
                let mut mine = Vec::new();
                loop {
                    let t = next.fetch_add(1, Ordering::Relaxed);
                    let Some(&(d, kind)) = tables.get(t) else {
                        break;
                    };
                    let dx = &st.dexes[d];
                    for id in 0..dx.counts()[kind] {
                        let ok = match kind {
                            index::STRING => dx.string(id as u32).is_ok_and(|s| match m.scope {
                                Scope::String | Scope::Usages => m.query_hits(&s),
                                _ => m.line(&format!("\"{s}\"")),
                            }),
                            index::TYPE => dx.type_name(id as u32).is_ok_and(|t| match m.scope {
                                Scope::Http => http_types.is_match(&t),
                                Scope::Usages => {
                                    m.query_hits(&dex::java_name(&t))
                                        || crate::deobf::class(&t).is_some_and(|n| m.query_hits(n))
                                }
                                _ => false,
                            }),
                            _ => {
                                let (owner, name, ty) = if kind == index::FIELD {
                                    dx.field_parts(id as u32)
                                        .map(|(c, t, n)| (c, n, t))
                                        .unwrap_or_default()
                                } else {
                                    dx.method_parts(id as u32)
                                        .map(|(c, n, _)| (c, n, String::new()))
                                        .unwrap_or_default()
                                };
                                let shown = if kind == index::FIELD {
                                    crate::deobf::field(&owner, &name, &ty)
                                } else {
                                    crate::deobf::method(&owner, &name)
                                };
                                match m.scope {
                                    Scope::Http => {
                                        kind == index::METHOD
                                            && HTTP_MEMBERS.contains(&name.as_str())
                                    }
                                    Scope::Secrets => secret_names.is_match(&name),
                                    Scope::Usages => {
                                        m.query_hits(&name)
                                            || shown.is_some_and(|n| m.query_hits(&n))
                                    }
                                    _ => false,
                                }
                            }
                        };
                        if ok {
                            mine.extend_from_slice(idx.users(d, kind, id));
                        }
                    }
                }
                found.lock().unwrap().extend(mine);
            });
        }
    });
    for k in found.into_inner().unwrap() {
        if let Some(h) = hit.get_mut(k as usize) {
            *h = true;
        }
    }
    Some(
        hit.iter()
            .enumerate()
            .filter(|x| *x.1)
            .map(|x| x.0)
            .collect(),
    )
}

pub fn search(st: &State, m: &Matcher, prog: &Progress) -> Vec<Hit> {
    search_stats(st, m, prog).0
}

/// `search` plus what the app-only filter hid: for `class`, the hidden name matches
/// themselves; for the decompiling scopes, the library classes the index said could match
/// but that were never decompiled. Callers print it so nothing disappears silently now
/// that the API scopes default to app-only.
pub fn search_stats(st: &State, m: &Matcher, prog: &Progress) -> (Vec<Hit>, usize) {
    let mut hits = Vec::new();
    let mut hidden = 0usize;
    if m.scope == Scope::Class {
        for (k, c) in st.classes.iter().enumerate() {
            if !m.line(&c.0) {
                continue;
            }
            if m.app_only && st.origin[k] == Origin::Library {
                hidden += 1;
                continue;
            }
            if hits.len() < LIMIT {
                hits.push((c.0.clone(), 0, String::new()));
            }
        }
        return (hits, hidden);
    }
    if m.scope == Scope::Api {
        let mut api = api_sheet(st, m);
        if m.app_only {
            api.retain(|h| {
                st.find(&h.0)
                    .is_none_or(|k| st.origin[k] != Origin::Library)
            });
        }
        return (api, 0);
    }
    if matches!(
        m.scope,
        Scope::Res | Scope::Urls | Scope::Secrets | Scope::Usages
    ) {
        for (p, t) in &st.texts {
            // translations repeat the default strings; API scopes only need res/values
            if m.scope != Scope::Res && p.starts_with("res/values-") {
                continue;
            }
            for (ln, l) in t.lines().enumerate() {
                if m.line(l) {
                    hits.push((p.clone(), ln + 1, l.trim().to_string()));
                }
            }
        }
        if m.scope == Scope::Res {
            hits.extend(
                st.files
                    .keys()
                    .filter(|p| m.line(p))
                    .map(|p| (p.clone(), 0, String::new())),
            );
        }
    }
    // endpoints and keys are often kept in native code; one ABI is enough, the others repeat it
    if matches!(m.scope, Scope::Urls | Scope::Secrets) {
        let libs = st.native_libs();
        let abi = [
            "lib/arm64-v8a/",
            "lib/armeabi-v7a/",
            "lib/x86_64/",
            "lib/x86/",
        ]
        .into_iter()
        .find(|a| libs.iter().any(|l| l.0.starts_with(a)));
        for (lib, _) in libs
            .iter()
            .filter(|l| abi.is_some_and(|a| l.0.starts_with(a)))
        {
            if prog.cancel.load(Ordering::Relaxed) {
                break;
            }
            let Some(data) = st.read_entry(lib) else {
                continue;
            };
            for s in elf::strings(&data, 6) {
                if m.line(&format!("\"{s}\"")) {
                    // line 0: the report lists strings in its own order, so there is no line to jump to
                    hits.push((lib.clone(), 0, s));
                }
            }
        }
    }
    if m.scope.decompiles() {
        let mut list = candidates(st, m).unwrap_or_else(|| (0..st.classes.len()).collect());
        if m.app_only {
            let before = list.len();
            list.retain(|&k| st.origin[k] != Origin::Library);
            hidden += before - list.len();
        }
        hits.extend(scan(st, m, &list, prog));
    }
    // first-party first for the API scopes: app code, then resources / native / other code,
    // then known libraries. Stable, so the (target, line) order holds within each rank.
    if matches!(m.scope, Scope::Urls | Scope::Http | Scope::Secrets) {
        hits.sort_by_key(|h| target_rank(st, &h.0));
    }
    hits.truncate(LIMIT);
    (hits, hidden)
}

/// 0 app code, 1 other code or a resource / native target, 2 known library: the order the
/// API scopes rank their hits by.
fn target_rank(st: &State, t: &str) -> u8 {
    st.find(t).map_or(1, |k| match st.origin[k] {
        Origin::App => 0,
        Origin::Other => 1,
        Origin::Library => 2,
    })
}

/// The source label and rank of a hit's target: code by origin, or "resources" / "native".
fn hit_kind(st: &State, t: &str) -> (&'static str, u8) {
    if let Some(k) = st.find(t) {
        match st.origin[k] {
            Origin::App => ("app code", 0),
            Origin::Other => ("other code", 1),
            Origin::Library => ("library code", 2),
        }
    } else if t.starts_with("lib/") {
        ("native", 1)
    } else {
        ("resources", 1)
    }
}

/// Distinct URL hosts among these hits.
#[cfg(any(test, feature = "gui"))]
pub fn host_count(hits: &[Hit]) -> usize {
    let re = regex::Regex::new(r#"(?:https?|wss?)://([^/?#\s"'<>\\]+)"#).unwrap();
    let mut set = std::collections::BTreeSet::new();
    for (_, _, t) in hits {
        if let Some(c) = re.captures(t) {
            set.insert(c[1].to_string());
        }
    }
    set.len()
}

/// One host's row of the `urls` summary.
#[derive(Default)]
struct HostRow {
    hits: usize,
    by_source: BTreeMap<&'static str, usize>,
    /// referenced from app-owned code
    app: bool,
}

/// One-line summaries for the API scopes, shown above the results in text output: `urls`
/// gets a host table (per-host counts by source, app-referenced hosts first), `http` and
/// `secrets` a source count. CSV/JSON stay machine-shaped.
pub fn search_summary(st: &State, scope: Scope, hits: &[Hit]) -> Vec<String> {
    let mut out = Vec::new();
    if hits.is_empty() {
        return out;
    }
    if scope == Scope::Urls {
        let mut hosts: BTreeMap<String, HostRow> = BTreeMap::new();
        let mut bare = 0usize;
        let re = regex::Regex::new(r#"(?:https?|wss?)://([^/?#\s"'<>\\]+)"#).unwrap();
        for (t, _, text) in hits {
            let (kind, rank) = hit_kind(st, t);
            let Some(c) = re.captures(text) else {
                bare += 1;
                continue;
            };
            let e = hosts.entry(c[1].to_string()).or_default();
            e.hits += 1;
            *e.by_source.entry(kind).or_insert(0) += 1;
            e.app |= rank == 0;
        }
        let mut list: Vec<(String, HostRow)> = hosts.into_iter().collect();
        list.sort_by(|a, b| {
            b.1.app
                .cmp(&a.1.app)
                .then_with(|| b.1.hits.cmp(&a.1.hits))
                .then_with(|| a.0.cmp(&b.0))
        });
        out.push(format!(
            "// hosts ({}), app-referenced first{}",
            list.len(),
            if bare > 0 {
                format!(
                    ", {bare} hit{} without a host",
                    if bare == 1 { "" } else { "s" }
                )
            } else {
                String::new()
            }
        ));
        for (h, row) in &list {
            let parts: Vec<String> = row
                .by_source
                .iter()
                .map(|(k, c)| format!("{k} {c}"))
                .collect();
            out.push(format!("  {h}    {}    {}", row.hits, parts.join(", ")));
        }
    } else if matches!(scope, Scope::Http | Scope::Secrets) {
        let mut counts: BTreeMap<&'static str, usize> = BTreeMap::new();
        for (t, _, _) in hits {
            *counts.entry(hit_kind(st, t).0).or_insert(0) += 1;
        }
        let parts: Vec<String> = counts.iter().map(|(k, c)| format!("{k} {c}")).collect();
        out.push(format!("// hits by source: {}", parts.join(", ")));
    }
    out
}

// ---------- the app's declared HTTP API (Retrofit) ----------

/// One endpoint of a Retrofit interface, read straight from the annotations.
struct Endpoint {
    class: String,
    method: String,
    verb: String,
    path: String,
    /// (annotation kind, name when the annotation carries one, parameter type)
    params: Vec<(&'static str, Option<String>, String)>,
    /// raw return type, e.g. `Call` — generic parameters are erased in the DEX
    ret: String,
    dex: usize,
    method_idx: u32,
}

/// One endpoint's call sites: what its callers pass, and the classes they reference.
#[derive(Default)]
struct Callers {
    class: String,
    /// parameter name -> literal or resolved constant, from positional call arguments
    args: BTreeMap<String, String>,
    /// response-model candidates: classes the callers reference as `X.class`
    models: Vec<String>,
}

/// `I` -> `int`, `Ljava/lang/String;` -> `String`, `[B` -> `byte[]`
fn short_ty(t: &str) -> String {
    let base = t.trim_start_matches('[');
    let array = if base.len() != t.len() { "[]" } else { "" };
    let named = match base {
        "I" => "int".to_string(),
        "Z" => "boolean".to_string(),
        "B" => "byte".to_string(),
        "S" => "short".to_string(),
        "C" => "char".to_string(),
        "J" => "long".to_string(),
        "F" => "float".to_string(),
        "D" => "double".to_string(),
        "V" => "void".to_string(),
        _ => base
            .trim_start_matches('L')
            .trim_end_matches(';')
            .rsplit('/')
            .next()
            .unwrap_or(base)
            .to_string(),
    };
    format!("{named}{array}")
}

/// The Retrofit parameter annotations this reads; the second field says whether the
/// annotation names the parameter (`value = "key"`).
fn param_kind(t: &str) -> Option<(&'static str, bool)> {
    Some(match t {
        "Lretrofit2/http/Query;" => ("query", true),
        "Lretrofit2/http/QueryName;" => ("query name", false),
        "Lretrofit2/http/QueryMap;" => ("query map", false),
        "Lretrofit2/http/Path;" => ("path", true),
        "Lretrofit2/http/Field;" => ("field", true),
        "Lretrofit2/http/FieldMap;" => ("field map", false),
        "Lretrofit2/http/Body;" => ("body", false),
        "Lretrofit2/http/Header;" => ("header", true),
        "Lretrofit2/http/HeaderMap;" => ("header map", false),
        "Lretrofit2/http/Part;" => ("part", true),
        "Lretrofit2/http/PartMap;" => ("part map", false),
        "Lretrofit2/http/Url;" => ("url", false),
        _ => return None,
    })
}

/// Every Retrofit-annotated interface method: verb, path, parameters, return type.
/// Discovery runs on the reference index (the `users` of the annotation types), so no
/// class is decompiled to build this list.
fn retrofit_endpoints(st: &State) -> Vec<Endpoint> {
    const VERBS: [&str; 7] = ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"];
    let Some(idx) = st.index.get() else {
        return vec![];
    };
    let mut ifaces: Vec<usize> = Vec::new();
    for (d, dx) in st.dexes.iter().enumerate() {
        for v in VERBS {
            let Some(tid) = dx
                .find_string(format!("Lretrofit2/http/{v};").as_bytes())
                .and_then(|s| dx.find_type(s))
            else {
                continue;
            };
            for &k in idx.users(d, index::TYPE, tid as usize) {
                if !ifaces.contains(&(k as usize)) {
                    ifaces.push(k as usize);
                }
            }
        }
    }
    ifaces.sort_unstable();
    let mut out = Vec::new();
    for &k in &ifaces {
        let (class, d, c) = &st.classes[k];
        let dx = &st.dexes[*d];
        let Ok(annos) = dx.annotations(*c) else {
            continue;
        };
        let mut methods: Vec<u32> = annos.methods.keys().copied().collect();
        methods.sort_unstable();
        for mid in methods {
            let mut verb = String::new();
            let mut path = String::new();
            for a in &annos.methods[&mid] {
                let Ok(t) = dx.type_name(a.type_idx) else {
                    continue;
                };
                let Some(v) = t
                    .strip_prefix("Lretrofit2/http/")
                    .and_then(|r| r.strip_suffix(';'))
                    .filter(|v| VERBS.contains(v))
                else {
                    continue;
                };
                verb = v.to_string();
                for (n, val) in &a.elements {
                    if dx.string(*n).is_ok_and(|n| n == "value")
                        && let dex::Value::Str(s) = val
                        && let Ok(p) = dx.string(*s)
                    {
                        path = p;
                    }
                }
            }
            if verb.is_empty() {
                continue;
            }
            let Ok((_, name, proto)) = dx.method_parts(mid) else {
                continue;
            };
            let Ok((ret, types)) = dx.proto_parts(proto) else {
                continue;
            };
            let pannos = annos.params.get(&mid);
            let mut params = Vec::new();
            for (i, ty) in types.iter().enumerate() {
                let mut kind = "arg";
                let mut pname = None;
                if let Some(list) = pannos
                    && let Some(ann) = list.get(i)
                {
                    for a in ann {
                        let Ok(t) = dx.type_name(a.type_idx) else {
                            continue;
                        };
                        if let Some((k, named)) = param_kind(&t) {
                            kind = k;
                            if named {
                                for (n, val) in &a.elements {
                                    if dx.string(*n).is_ok_and(|n| n == "value")
                                        && let dex::Value::Str(s) = val
                                        && let Ok(p) = dx.string(*s)
                                    {
                                        pname = Some(p);
                                    }
                                }
                            }
                        }
                    }
                }
                params.push((kind, pname, short_ty(ty)));
            }
            out.push(Endpoint {
                class: class.clone(),
                method: name,
                verb,
                path,
                params,
                ret: short_ty(&ret),
                dex: *d,
                method_idx: mid,
            });
        }
    }
    out
}

/// The argument list of the first `call` on `line`, nesting respected.
fn call_args(line: &str, call: &str) -> Option<String> {
    let at = line.find(call)? + call.len();
    let b = line.as_bytes();
    let (mut depth, mut end) = (1i32, at);
    while end < b.len() {
        match b[end] {
            b'(' => depth += 1,
            b')' => {
                depth -= 1;
                if depth == 0 {
                    break;
                }
            }
            _ => {}
        }
        end += 1;
    }
    line.get(at..end).map(str::to_string)
}

/// Top-level comma split of an argument list (nesting and string literals respected).
fn split_args(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let (mut depth, mut quote) = (0i32, false);
    for ch in s.chars() {
        match ch {
            '"' => {
                quote = !quote;
                cur.push(ch);
            }
            '(' | '[' | '{' if !quote => {
                depth += 1;
                cur.push(ch);
            }
            ')' | ']' | '}' if !quote => {
                depth -= 1;
                cur.push(ch);
            }
            ',' if depth == 0 && !quote => {
                out.push(cur.trim().to_string());
                cur.clear();
            }
            _ => cur.push(ch),
        }
    }
    if !cur.trim().is_empty() {
        out.push(cur.trim().to_string());
    }
    out
}

/// The stored value of a `Class.FIELD` static string constant, when the app defines it.
/// Local lookup for the base-URL and call-site resolutions.
fn const_value(st: &State, expr: &str) -> Option<String> {
    let (cls, field) = expr.rsplit_once('.')?;
    let short = format!(".{}", cls.rsplit('.').next().unwrap_or(cls));
    for dx in &st.dexes {
        for c in 0..dx.class_count {
            let Ok(desc) = dx.class_descriptor(c) else {
                continue;
            };
            if !dex::java_name(&desc).ends_with(&short) {
                continue;
            }
            let Ok(data) = dx.class_data(c) else { continue };
            let vals = dx.static_values(c).unwrap_or_default();
            for (k, (f, acc)) in data.fields.iter().enumerate() {
                if acc & 0x8 == 0 {
                    break;
                }
                let Ok((_, _, name)) = dx.field_parts(*f) else {
                    continue;
                };
                if name == field
                    && let Some(dex::Value::Str(s)) = vals.get(k)
                    && let Ok(v) = dx.string(*s)
                {
                    return Some(v);
                }
            }
        }
    }
    None
}

/// The initializer of a local in decompiled text, one hop: `Type name = <expr>;`. Locals the
/// decompiler hoists out of a call still resolve this way.
fn local_init(text: &str, name: &str) -> Option<String> {
    let needle = format!(" {name} = ");
    let l = text.lines().find(|l| l.contains(&needle))?;
    let at = l.find(&needle)? + needle.len();
    Some(l[at..].trim().trim_end_matches(';').trim().to_string())
}

/// A call argument resolved to a fact: a string literal as-is, a `Class.FIELD` reference
/// through its stored value, or a local through its initializer (one hop). None when the
/// argument is computed — never a guess.
fn arg_value(st: &State, text: &str, a: &str) -> Option<String> {
    if a.starts_with('"') && a.ends_with('"') && a.len() > 1 {
        return Some(a[1..a.len() - 1].to_string());
    }
    if let Some(v) = const_value(st, a) {
        return Some(v);
    }
    let init = local_init(text, a)?;
    if init.starts_with('"') && init.ends_with('"') && init.len() > 1 {
        Some(init[1..init.len() - 1].to_string())
    } else {
        const_value(st, &init)
    }
}

/// (class, base URL) of every `Retrofit.Builder.baseUrl(...)` call: the literal, or a
/// `Class.FIELD` reference resolved to its stored value.
fn base_urls(st: &State) -> Vec<(String, String)> {
    let Some(idx) = st.index.get() else {
        return vec![];
    };
    let mut out = Vec::new();
    for (d, dx) in st.dexes.iter().enumerate() {
        for id in 0..dx.counts()[3] as u32 {
            let Ok((owner, name, _)) = dx.method_parts(id) else {
                continue;
            };
            if owner != "Lretrofit2/Retrofit$Builder;" || name != "baseUrl" {
                continue;
            }
            for &k in idx.users(d, index::METHOD, id as usize) {
                let (class, _, _) = &st.classes[k as usize];
                let Some(text) = st.class_text(class, false) else {
                    continue;
                };
                for line in text.lines() {
                    let Some(arg) = call_args(line, "baseUrl(") else {
                        continue;
                    };
                    if let Some(url) = arg_value(st, &text, arg.trim()) {
                        out.push((class.clone(), url));
                    }
                }
            }
        }
    }
    out.sort();
    out.dedup();
    out
}

/// The declared fields of a class, as `name: type` pairs — the shape of a response model.
fn model_fields(st: &State, class: &str) -> Option<Vec<String>> {
    let k = st.find(class)?;
    let (_, d, c) = &st.classes[k];
    let dx = &st.dexes[*d];
    let data = dx.class_data(*c).ok()?;
    let mut out = Vec::new();
    for (f, _) in &data.fields {
        if out.len() >= 8 {
            break;
        }
        if let Ok((_, ty, name)) = dx.field_parts(*f) {
            out.push(format!("{}: {}", name, short_ty(&ty)));
        }
    }
    (!out.is_empty()).then_some(out)
}

/// What the endpoint's callers pass and which classes they reference, read by decompiling
/// the classes that call the interface method. Heuristic — labelled `inferred` in the
/// output: positional argument matching over the decompiled call.
fn endpoint_callers(st: &State, e: &Endpoint) -> Callers {
    let mut c = Callers::default();
    let Some(idx) = st.index.get() else { return c };
    let mut ks: Vec<usize> = idx
        .users(e.dex, index::METHOD, e.method_idx as usize)
        .iter()
        .map(|&k| k as usize)
        .collect();
    ks.sort_unstable();
    let class_re = regex::Regex::new(r"(\w+)\.class").unwrap();
    for k in ks.iter().take(4) {
        let (class, _, _) = &st.classes[*k];
        // the interface's own declaration is one of the "users" of its methods; not a caller
        if *class == e.class {
            continue;
        }
        let Some(text) = st.class_text(class, false) else {
            continue;
        };
        if c.class.is_empty() {
            c.class = class.clone();
        }
        for cap in class_re.captures_iter(&text) {
            let short = format!(".{}", &cap[1]);
            let Some((full, ..)) = st.classes.iter().find(|(n, _, _)| n.ends_with(&short)) else {
                continue;
            };
            let lib = st
                .find(full)
                .is_some_and(|k| st.origin[k] == Origin::Library);
            if !lib && !c.models.contains(full) {
                c.models.push(full.clone());
            }
        }
        let call = format!(".{}(", e.method);
        for line in text.lines() {
            let Some(src) = call_args(line, &call) else {
                continue;
            };
            for (i, a) in split_args(&src).into_iter().enumerate() {
                let Some(name) = e.params.get(i).and_then(|(_, n, _)| n.clone()) else {
                    continue;
                };
                if let Some(v) = arg_value(st, &text, &a) {
                    c.args.insert(name, v);
                }
            }
        }
    }
    c
}

/// One curl line per endpoint: query parameters and fields filled from resolved call-site
/// arguments, `$name` where nothing was resolved — never a guessed value.
fn curl_line(e: &Endpoint, base: &str, args: &BTreeMap<String, String>) -> String {
    let url = format!("{}/{}", base, e.path.trim_start_matches('/'));
    let val = |n: &str| args.get(n).cloned().unwrap_or_else(|| format!("${n}"));
    let named = |want: &str| {
        e.params
            .iter()
            .filter(|(k, n, _)| *k == want && n.is_some())
            .map(|(_, n, _)| n.as_deref().unwrap_or(""))
            .collect::<Vec<_>>()
    };
    if e.verb == "GET" {
        let q: Vec<String> = named("query")
            .into_iter()
            .map(|n| format!("{n}={}", val(n)))
            .collect();
        let qs = if q.is_empty() {
            String::new()
        } else {
            format!("?{}", q.join("&"))
        };
        return format!("curl '{url}{qs}'");
    }
    let f: Vec<String> = named("field")
        .into_iter()
        .map(|n| format!("{n}={}", val(n)))
        .collect();
    let d = if f.is_empty() {
        String::new()
    } else {
        format!(" -d '{}'", f.join("&"))
    };
    format!("curl -X {} '{url}'{}", e.verb, d)
}

/// The `search api` sheet: base URLs, then one line per endpoint — verb, path, parameters,
/// return type, inferred model and arguments — and one curl line per endpoint. Labeled
/// `inferred` where the DEX cannot state a fact (generics are erased).
pub fn api_sheet(st: &State, m: &Matcher) -> Vec<Hit> {
    let bases = base_urls(st);
    let mut hits: Vec<Hit> = Vec::new();
    for (class, base) in &bases {
        let text = format!("base URL: {base}");
        if m.line(&text) {
            hits.push((class.clone(), 0, text));
        }
    }
    for e in retrofit_endpoints(st) {
        let c = endpoint_callers(st, &e);
        let base = bases
            .first()
            .map(|(_, b)| b.trim_end_matches('/'))
            .unwrap_or("");
        let params = e
            .params
            .iter()
            .map(|(kind, name, ty)| match name {
                Some(n) => format!("{n} ({kind}, {ty})"),
                None => format!("({kind}: {ty})"),
            })
            .collect::<Vec<_>>()
            .join(", ");
        let model = c.models.iter().find_map(|m2| {
            model_fields(st, m2).map(|f| {
                format!(
                    "{}{{{}}}",
                    m2.rsplit('.').next().unwrap_or(m2),
                    f.join(", ")
                )
            })
        });
        let mut line = format!(
            "{} {}/{}    params: {}    -> {}",
            e.verb,
            base,
            e.path.trim_start_matches('/'),
            params,
            e.ret
        );
        if let Some(m2) = &model {
            line.push_str(&format!("    [model inferred: {m2}]"));
        }
        if !c.class.is_empty() && !c.args.is_empty() {
            line.push_str(&format!(
                "    [args inferred from {}]",
                c.class.rsplit('.').next().unwrap_or(&c.class)
            ));
        }
        if m.line(&line) {
            let curl = curl_line(&e, base, &c.args);
            hits.push((e.class.clone(), 0, line));
            hits.push((e.class.clone(), 0, format!("    {curl}")));
        }
    }
    hits.truncate(LIMIT);
    hits
}

// ---------- named string constants ----------

/// One static string constant as stored in the DEX: `Class#field = "value"`.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub struct Const {
    /// class, Java name (`a.b.C` or a nested `a.b.C$D`)
    pub class: String,
    pub field: String,
    pub value: String,
}

/// Every static `String` field with a stored initial value, sorted and de-duplicated. The
/// stored values line up with the static-field prefix of each class's field list, so this is
/// the exact `BuildConfig.X = "..."` set — read from the DEX tables, not from decompiled
/// text. Shared by the secrets entropy tier, `search config` and the constants diff.
pub fn string_constants(dexes: &[Dex]) -> Vec<Const> {
    let mut out = Vec::new();
    for dx in dexes {
        for c in 0..dx.class_count {
            let Ok(desc) = dx.class_descriptor(c) else {
                continue;
            };
            let Ok(data) = dx.class_data(c) else { continue };
            let vals = dx.static_values(c).unwrap_or_default();
            for (k, (f, acc)) in data.fields.iter().enumerate() {
                // static fields come first; the stored values match that prefix of the list
                if acc & 0x8 == 0 {
                    break;
                }
                if let (Some(dex::Value::Str(s)), Ok((_, _, name))) =
                    (vals.get(k), dx.field_parts(*f))
                    && let Ok(value) = dx.string(*s)
                {
                    out.push(Const {
                        class: dex::java_name(&desc),
                        field: name,
                        value,
                    });
                }
            }
        }
    }
    out.sort();
    out.dedup();
    out
}

/// Shannon entropy of `s`, in bits per character.
pub fn entropy_bits(s: &str) -> f64 {
    let mut counts = [0u32; 256];
    let mut n = 0u64;
    for b in s.as_bytes() {
        counts[*b as usize] += 1;
        n += 1;
    }
    if n == 0 {
        return 0.0;
    }
    counts
        .into_iter()
        .filter(|c| *c > 0)
        .map(|c| {
            let p = c as f64 / n as f64;
            -p * p.log2()
        })
        .sum()
}

/// A string that looks like a first-party key while no pattern named it: token-shaped —
/// letters, digits and `+/=_-.:` only, which is what drops regexes, alphabets-in-prose and
/// multi-line shaders — 24–200 characters long, high-entropy, mixing character classes,
/// and not shaped like a URL or path. Long ascending or descending runs (`abcdef`,
/// `0123456789`) are alphabet fragments, not key material, and are rejected too.
pub fn looks_like_secret(v: &str) -> bool {
    (24..=200).contains(&v.chars().count())
        && v.bytes().all(|b| {
            b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'=' | b'_' | b'-' | b'.' | b':')
        })
        && entropy_bits(v) >= 4.0
        && v.chars().any(|c| c.is_ascii_lowercase())
        && v.chars().any(|c| c.is_ascii_uppercase())
        && v.chars().any(|c| c.is_ascii_digit())
        && !v.contains("://")
        && !v.starts_with('/')
        && !sequential_run(v)
}

/// Whether `v` contains a run of 5 or more consecutive code points in either direction
/// (`abcdef`, `0123456789`, `XWVUT`): digit-sequence or alphabet fragments, which real
/// key material does not contain.
fn sequential_run(v: &str) -> bool {
    let mut run = 1u32;
    let mut prev = 0u32;
    for (i, c) in v.chars().map(|c| c as u32).enumerate() {
        if i > 0 {
            run = if c == prev + 1 || c + 1 == prev {
                run + 1
            } else {
                1
            };
            if run >= 5 {
                return true;
            }
        }
        prev = c;
    }
    false
}

/// The entropy tier of `search secrets`: static string constants of the app's own code
/// (library classes excluded) that look like keys while no known pattern matched them.
/// A separate, lower-confidence list — capped, sorted, and never mixed with the pattern
/// hits; values the patterns already report on their `name = "value"` line are left out.
pub fn entropy_secrets(st: &State) -> Vec<Const> {
    let known = regex::Regex::new(SECRET_RE).unwrap();
    let mut out = Vec::new();
    for c in string_constants(&st.dexes) {
        if st.origin_of(&c.class) == Origin::Library || !looks_like_secret(&c.value) {
            continue;
        }
        if known.is_match(&format!(r#"{} = "{}""#, c.field, c.value)) {
            continue;
        }
        out.push(c);
        if out.len() >= 50 {
            break;
        }
    }
    out
}

/// Read `list` (class ids) on all cores and keep matching lines. A scan over every class with
/// no cache yet fills the cache on the way.
fn scan(st: &State, m: &Matcher, list: &[usize], prog: &Progress) -> Vec<Hit> {
    prog.total.store(list.len(), Ordering::Relaxed);
    let reader = st.cache.read().unwrap().clone();
    let writer =
        (reader.is_none() && list.len() == st.classes.len() && CACHE_WRITE.load(Ordering::Relaxed))
            .then(|| cache::Writer::create(&st.cache_dir, st.classes.len()))
            .flatten();
    let next = AtomicUsize::new(0);
    let found = Mutex::new(Vec::new());
    let full = AtomicBool::new(false);
    std::thread::scope(|s| {
        for _ in 0..threads() {
            let _ = std::thread::Builder::new()
                .stack_size(64 << 20)
                .spawn_scoped(s, || {
                    let mut f = reader.as_ref().and_then(|r| r.file());
                    let mut mine = Vec::new();
                    loop {
                        if prog.cancel.load(Ordering::Relaxed) || full.load(Ordering::Relaxed) {
                            break;
                        }
                        let n = next.fetch_add(1, Ordering::Relaxed);
                        let Some(&k) = list.get(n) else { break };
                        let text = match (&reader, f.as_mut()) {
                            (Some(r), Some(f)) => st.java_of(k, Some((r, f))),
                            _ => st.java_of(k, None),
                        };
                        if let Some(text) = text {
                            if let Some(w) = &writer {
                                w.put(k, &text);
                            }
                            for (ln, l) in text.lines().enumerate() {
                                if m.line(l) {
                                    mine.push((
                                        st.classes[k].0.clone(),
                                        ln + 1,
                                        l.trim().to_string(),
                                    ));
                                }
                            }
                            // keep scanning to finish the cache, but stop collecting
                            if mine.len() >= LIMIT && writer.is_none() {
                                full.store(true, Ordering::Relaxed);
                            }
                        }
                        prog.done.fetch_add(1, Ordering::Relaxed);
                    }
                    found.lock().unwrap().extend(mine);
                });
        }
    });
    if let Some(w) = writer
        && !prog.cancel.load(Ordering::Relaxed)
        && next.load(Ordering::Relaxed) >= list.len()
        && let Some(r) = w.finish()
    {
        *st.cache.write().unwrap() = Some(Arc::new(r));
    }
    let mut v = found.into_inner().unwrap();
    v.sort();
    v
}

#[derive(Clone, Copy, PartialEq)]
pub enum Format {
    Text,
    Csv,
    Json,
}

/// Lines `[from, to)` around a hit: `ctx` lines either side, or the whole enclosing method.
pub fn excerpt(lines: &[&str], at: usize, ctx: usize, method: bool) -> (usize, usize) {
    let indent = |l: &str| l.len() - l.trim_start().len();
    if method {
        const NOT_METHOD: [&str; 9] = [
            "if ",
            "for ",
            "while ",
            "switch ",
            "try ",
            "catch ",
            "} catch",
            "else",
            "synchronized ",
        ];
        let hit_ind = indent(lines.get(at).copied().unwrap_or(""));
        let head = (0..=at.min(lines.len().saturating_sub(1)))
            .rev()
            .find(|&k| {
                let l = lines[k];
                let t = l.trim();
                indent(l) < hit_ind.max(1)
                    && t.ends_with('{')
                    && t.contains('(')
                    && !NOT_METHOD.iter().any(|n| t.starts_with(n))
            });
        if let Some(h) = head {
            let ind = indent(lines[h]);
            let end = (h + 1..lines.len())
                .find(|&k| indent(lines[k]) == ind && lines[k].trim() == "}")
                .map_or(lines.len(), |e| e + 1);
            return (h, end);
        }
    }
    (at.saturating_sub(ctx), (at + ctx + 1).min(lines.len()))
}

pub fn json_str(s: &str) -> String {
    let mut o = String::with_capacity(s.len() + 2);
    o.push('"');
    for c in s.chars() {
        match c {
            '"' => o += "\\\"",
            '\\' => o += "\\\\",
            '\n' => o += "\\n",
            '\r' => o += "\\r",
            '\t' => o += "\\t",
            c if (c as u32) < 0x20 => {
                let _ = write!(o, "\\u{:04x}", c as u32);
            }
            c => o.push(c),
        }
    }
    o.push('"');
    o
}

pub fn csv_field(s: &str) -> String {
    format!("\"{}\"", s.replace('"', "\"\""))
}

/// Write hits with their surrounding code. `text_of` gives a target's full text.
pub fn export(
    hits: &[Hit],
    ctx: usize,
    method: bool,
    fmt: Format,
    mut text_of: impl FnMut(&str) -> Option<String>,
) -> String {
    let mut out = String::new();
    match fmt {
        Format::Csv => out += "target,line,match,excerpt\n",
        Format::Json => out += "[\n",
        Format::Text => {}
    }
    let mut cur: Option<(String, Option<String>)> = None;
    for (n, (t, ln, text)) in hits.iter().enumerate() {
        if cur.as_ref().is_none_or(|c| &c.0 != t) {
            cur = Some((t.clone(), if ctx > 0 || method { text_of(t) } else { None }));
        }
        let body = cur.as_ref().and_then(|c| c.1.as_deref());
        let snippet = match (body, *ln) {
            (Some(b), l) if l > 0 => {
                let lines: Vec<&str> = b.lines().collect();
                let (a, z) = excerpt(&lines, l - 1, ctx, method);
                lines[a..z].join("\n")
            }
            _ => text.clone(),
        };
        match fmt {
            Format::Text => {
                let _ = writeln!(out, "== {t}:{ln}\n{snippet}\n");
            }
            Format::Csv => {
                let _ = writeln!(
                    out,
                    "{},{ln},{},{}",
                    csv_field(t),
                    csv_field(text),
                    csv_field(&snippet)
                );
            }
            Format::Json => {
                let sep = if n + 1 < hits.len() { "," } else { "" };
                let _ = writeln!(
                    out,
                    "  {{\"target\":{},\"line\":{ln},\"match\":{},\"excerpt\":{}}}{sep}",
                    json_str(t),
                    json_str(text),
                    json_str(&snippet)
                );
            }
        }
    }
    if fmt == Format::Json {
        out += "]\n";
    }
    out
}

/// Append `rows` (already-rendered, indented JSON objects) to an array produced by
/// `export(.., Format::Json, ..)`; the array stays a valid JSON array.
pub fn json_extend(array: &mut String, rows: &[String]) {
    if rows.is_empty() {
        return;
    }
    let body = array.trim_end();
    let had_rows = body.ends_with('}');
    let open = body.strip_suffix(']').unwrap_or(body);
    let mut out = String::from(open);
    for (k, r) in rows.iter().enumerate() {
        if k > 0 || had_rows {
            out.push(',');
            out.push('\n');
        }
        out.push_str(r);
    }
    out.push_str("\n]\n");
    *array = out;
}

/// `name="value"` of the first `name=` in `s`.
pub fn attr(s: &str, name: &str) -> Option<String> {
    let k = s.find(&format!("{name}=\""))? + name.len() + 2;
    Some(s[k..].split('"').next()?.to_string())
}

/// Classes and methods per code source, counted from the DEX: the app's own packages,
/// unknown (often obfuscated) code, and each known SDK prefix. Top counts first — the
/// "vendor noise vs mine" triage for big multi-dex apps.
pub fn sdk_share(st: &State) -> Vec<(String, usize, usize)> {
    let mut rows: BTreeMap<String, (usize, usize)> = BTreeMap::new();
    for (k, (name, d, c)) in st.classes.iter().enumerate() {
        let group = match st.origin[k] {
            Origin::App => "app code".to_string(),
            Origin::Other => "other code".to_string(),
            Origin::Library => LIBRARIES
                .iter()
                .find(|p| name.starts_with(*p))
                .map_or("libraries".to_string(), |p| {
                    p.trim_end_matches('.').to_string()
                }),
        };
        let e = rows.entry(group).or_default();
        e.0 += 1;
        e.1 += st.dexes[*d].class_data(*c).map_or(0, |x| x.methods.len());
    }
    let mut out: Vec<(String, usize, usize)> =
        rows.into_iter().map(|(g, (c, m))| (g, c, m)).collect();
    out.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    out
}

/// Security-relevant summary of the manifest and APK layout, as readable text.
pub fn overview(st: &State) -> String {
    let m = st
        .texts
        .get("AndroidManifest.xml")
        .map(String::as_str)
        .unwrap_or("");
    // elements as (tag, attributes text, depth-ordered); the decoder writes one element per `<`
    let elems: Vec<(&str, &str)> = m
        .split('<')
        .skip(1)
        .filter_map(|e| {
            let e = e.split('>').next()?;
            let tag = e.split_whitespace().next()?;
            Some((tag, e))
        })
        .collect();
    let a = |e: &str, n: &str| attr(e, &format!("android:{n}"));
    let mut o = String::new();
    let _ = writeln!(o, "// Overview of {}\n", st.path);
    let _ = writeln!(o, "package           {}", st.package);
    if let Some((_, e)) = elems.iter().find(|x| x.0 == "manifest") {
        let _ = writeln!(
            o,
            "version           {} ({})",
            a(e, "versionName").unwrap_or_default(),
            a(e, "versionCode").unwrap_or_default()
        );
    }
    if let Some((_, e)) = elems.iter().find(|x| x.0 == "uses-sdk") {
        let _ = writeln!(
            o,
            "min / target SDK  {} / {}",
            a(e, "minSdkVersion").unwrap_or("?".into()),
            a(e, "targetSdkVersion").unwrap_or("?".into())
        );
    }
    let _ = writeln!(
        o,
        "classes           {} top-level, {} methods, {} dex",
        st.classes.len(),
        st.methods,
        st.dexes.len()
    );
    let _ = writeln!(o, "\n// code by origin (classes / methods), top first");
    for (g, c, m) in sdk_share(st).into_iter().take(12) {
        let _ = writeln!(o, "{g:<28}{c:>6} / {m}");
    }
    let _ = writeln!(
        o,
        "sdks              {}",
        crate::fingerprint::summarize(&crate::fingerprint::run(
            st,
            false,
            crate::fingerprint::Catalog::Both,
            None
        ))
    );
    if let Some((_, e)) = elems.iter().find(|x| x.0 == "application") {
        let _ = writeln!(o, "\n// application flags");
        for f in [
            "debuggable",
            "allowBackup",
            "usesCleartextTraffic",
            "networkSecurityConfig",
            "requestLegacyExternalStorage",
            "name",
        ] {
            if let Some(v) = a(e, f) {
                let warn = matches!(
                    (f, v.as_str()),
                    ("debuggable", "true")
                        | ("usesCleartextTraffic", "true")
                        | ("allowBackup", "true")
                );
                let _ = writeln!(o, "{f:<29}{v}{}", if warn { "    <- review" } else { "" });
            }
        }
    }
    const DANGEROUS: [&str; 16] = [
        "READ_CONTACTS",
        "WRITE_CONTACTS",
        "READ_SMS",
        "SEND_SMS",
        "RECEIVE_SMS",
        "READ_CALL_LOG",
        "CALL_PHONE",
        "RECORD_AUDIO",
        "CAMERA",
        "ACCESS_FINE_LOCATION",
        "ACCESS_COARSE_LOCATION",
        "ACCESS_BACKGROUND_LOCATION",
        "READ_PHONE_STATE",
        "READ_EXTERNAL_STORAGE",
        "BODY_SENSORS",
        "REQUEST_INSTALL_PACKAGES",
    ];
    let perms: Vec<String> = elems
        .iter()
        .filter(|x| x.0.starts_with("uses-permission"))
        .filter_map(|x| a(x.1, "name"))
        .collect();
    let _ = writeln!(o, "\n// permissions ({})", perms.len());
    for p in &perms {
        let flag = DANGEROUS.iter().any(|d| p.ends_with(d));
        let _ = writeln!(o, "{p}{}", if flag { "    <- dangerous" } else { "" });
    }
    // components: exported explicitly, or implicitly through an intent-filter
    let _ = writeln!(o, "\n// exported components (reachable by other apps)");
    let mut deep = Vec::new();
    // (tag, name, exported attribute, has an intent-filter)
    let mut cur: Option<(String, String, Option<String>, bool)> = None;
    let flush = |c: Option<(String, String, Option<String>, bool)>, o: &mut String| {
        if let Some((tag, name, exp, filt)) = c {
            // before Android 12 a component with an intent-filter and no `exported` is exported
            match (exp.as_deref(), filt) {
                (Some("true"), _) => {
                    let _ = writeln!(o, "{tag:<10}{name}");
                }
                (None, true) => {
                    let _ = writeln!(o, "{tag:<10}{name}    (exported via intent-filter)");
                }
                _ => {}
            }
        }
    };
    for (tag, e) in &elems {
        match *tag {
            "activity" | "activity-alias" | "service" | "receiver" | "provider" => {
                flush(cur.take(), &mut o);
                cur = Some((
                    tag.to_string(),
                    a(e, "name").unwrap_or_default(),
                    a(e, "exported"),
                    false,
                ));
            }
            "intent-filter" => {
                if let Some(c) = cur.as_mut() {
                    c.3 = true;
                }
            }
            "data" => {
                let (s, h, p) = (
                    a(e, "scheme"),
                    a(e, "host"),
                    a(e, "path").or(a(e, "pathPrefix")).or(a(e, "pathPattern")),
                );
                if s.is_some() || h.is_some() {
                    deep.push(format!(
                        "{}://{}{}",
                        s.unwrap_or("*".into()),
                        h.unwrap_or("*".into()),
                        p.unwrap_or_default()
                    ));
                }
            }
            _ => {}
        }
    }
    flush(cur.take(), &mut o);
    deep.sort();
    deep.dedup();
    let _ = writeln!(o, "\n// deep links ({})", deep.len());
    for d in &deep {
        let _ = writeln!(o, "{d}");
    }
    let _ = writeln!(
        o,
        "
// signature"
    );
    o += &crate::sign::summary(&st.file, &st.entries, |p| st.read_entry(p));
    let libs: Vec<&String> = st
        .entries
        .iter()
        .filter(|e| e.starts_with("lib/") && e.ends_with(".so"))
        .collect();
    let _ = writeln!(o, "\n// native libraries ({}), with meanings", libs.len());
    for l in &libs {
        let _ = match native_lib_meaning(l) {
            Some(m) => writeln!(o, "{l}    {m}"),
            None => writeln!(o, "{l}"),
        };
    }
    let assets = st
        .entries
        .iter()
        .filter(|e| e.starts_with("assets/"))
        .count();
    let _ = writeln!(o, "\n// assets: {assets} files");
    o
}

#[cfg(test)]
#[path = "../tests/apkscope/session.rs"]
mod tests;

/// Smali of class `c` and its nested classes, outer first.
pub fn smali(dx: &Dex, c: usize) -> String {
    let mut out = String::new();
    let mut stack = vec![c];
    while let Some(x) = stack.pop() {
        let _ = writeln!(
            out,
            ".class {}
",
            dx.class_descriptor(x).unwrap_or_default()
        );
        for m in dx.methods(x).unwrap_or_default() {
            let _ = writeln!(
                out,
                ".method {:#x} {}",
                m.access,
                dx.method_ref(m.method_idx).unwrap_or_default()
            );
            if let Some(code) = &m.code {
                let _ = writeln!(out, "    .registers {}", code.registers);
                for i in bytecode::decode(code.insns).unwrap_or_default() {
                    let _ = writeln!(
                        out,
                        "    {:04x}: {}",
                        i.off,
                        crate::render(dx, &i).unwrap_or_else(|e| e.to_string())
                    );
                }
            }
            out += ".end method

";
        }
        stack.extend(dx.nesting().kids[x].iter().rev());
    }
    out
}
