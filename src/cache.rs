//! On-disk cache of decompiled classes, one per APK: `code.bin` holds deflated Java text,
//! `code.idx` the (offset, length) of each top-level class. The index is written last, so a
//! cache without it (interrupted fill) is ignored and rebuilt.

use std::fs::{self, File};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

/// `%LOCALAPPDATA%\apkscope\cache` (or `$XDG_CACHE_HOME/apkscope`, `~/.cache/apkscope`)
pub fn root() -> PathBuf {
    let base = std::env::var_os("LOCALAPPDATA")
        .or_else(|| std::env::var_os("XDG_CACHE_HOME"))
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".cache")))
        .unwrap_or_else(std::env::temp_dir);
    base.join("apkscope").join("cache")
}

/// Cache folder for one APK: changes when the file, the deobfuscation choice or apkscope changes.
/// `tag` = hash of the user's renames and comments (0 = none).
pub fn dir_for(apk: &str, deobf: bool, tag: u64) -> PathBuf {
    let meta = fs::metadata(apk).ok();
    let size = meta.as_ref().map_or(0, |m| m.len());
    let mtime = meta.and_then(|m| m.modified().ok()).and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok()).map_or(0, |d| d.as_secs());
    let name = Path::new(apk).file_stem().map_or("apk".into(), |s| s.to_string_lossy().into_owned());
    let safe: String = name.chars().map(|c| if c.is_ascii_alphanumeric() || c == '-' || c == '_' { c } else { '_' }).take(40).collect();
    root().join(format!("{safe}-{size:x}-{mtime:x}-{}-{}{}", if deobf { "d" } else { "n" }, env!("CARGO_PKG_VERSION"), if tag == 0 { String::new() } else { format!("-u{:x}", tag & 0xffff_ffff) }))
}

/// Total size of every cache, in bytes.
pub fn total_size() -> u64 {
    fn walk(p: &Path) -> u64 {
        fs::read_dir(p).map_or(0, |rd| rd.flatten().map(|e| if e.path().is_dir() { walk(&e.path()) } else { e.metadata().map_or(0, |m| m.len()) }).sum())
    }
    walk(&root())
}

pub fn clear_all() -> std::io::Result<()> {
    match fs::remove_dir_all(root()) {
        Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(e),
        _ => Ok(()),
    }
}

pub struct Reader {
    bin: PathBuf,
    slots: Vec<(u64, u32)>,
}

impl Reader {
    pub fn open(dir: &Path, classes: usize) -> Option<Reader> {
        let mut raw = Vec::new();
        File::open(dir.join("code.idx")).ok()?.read_to_end(&mut raw).ok()?;
        if raw.len() != classes * 12 {
            return None;
        }
        let slots = raw.chunks_exact(12).map(|c| (u64::from_le_bytes(c[..8].try_into().unwrap()), u32::from_le_bytes(c[8..].try_into().unwrap()))).collect();
        Some(Reader { bin: dir.join("code.bin"), slots })
    }

    /// A handle for one reading thread.
    pub fn file(&self) -> Option<File> {
        File::open(&self.bin).ok()
    }

    pub fn get(&self, f: &mut File, k: usize) -> Option<String> {
        let &(off, len) = self.slots.get(k)?;
        if len == 0 {
            return None;
        }
        let mut buf = vec![0; len as usize];
        f.seek(SeekFrom::Start(off)).ok()?;
        f.read_exact(&mut buf).ok()?;
        String::from_utf8(miniz_oxide::inflate::decompress_to_vec(&buf).ok()?).ok()
    }
}

/// Filled by the threads of a full scan; `finish` makes it readable.
pub struct Writer {
    dir: PathBuf,
    out: Mutex<(File, u64)>,
    slots: Mutex<Vec<(u64, u32)>>,
}

impl Writer {
    pub fn create(dir: &Path, classes: usize) -> Option<Writer> {
        fs::create_dir_all(dir).ok()?;
        let _ = fs::remove_file(dir.join("code.idx"));
        let f = File::create(dir.join("code.bin")).ok()?;
        Some(Writer { dir: dir.to_path_buf(), out: Mutex::new((f, 0)), slots: Mutex::new(vec![(0, 0); classes]) })
    }

    pub fn put(&self, k: usize, text: &str) {
        // level 1: compression must not slow the scan down
        let z = miniz_oxide::deflate::compress_to_vec(text.as_bytes(), 1);
        let off = {
            let mut o = self.out.lock().unwrap();
            let off = o.1;
            if o.0.write_all(&z).is_err() {
                return;
            }
            o.1 += z.len() as u64;
            off
        };
        if let Some(s) = self.slots.lock().unwrap().get_mut(k) {
            *s = (off, z.len() as u32);
        }
    }

    /// Write the index; only a complete scan should call this.
    pub fn finish(self) -> Option<Reader> {
        let (mut f, _) = self.out.into_inner().ok()?;
        f.flush().ok()?;
        let slots = self.slots.into_inner().ok()?;
        let mut raw = Vec::with_capacity(slots.len() * 12);
        for &(o, l) in &slots {
            raw.extend_from_slice(&o.to_le_bytes());
            raw.extend_from_slice(&l.to_le_bytes());
        }
        fs::write(self.dir.join("code.idx"), raw).ok()?;
        Reader::open(&self.dir, slots.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_and_incomplete_cache_ignored() {
        let dir = std::env::temp_dir().join(format!("apkscope-cache-test-{}", std::process::id()));
        let w = Writer::create(&dir, 3).unwrap();
        w.put(2, "class C {}");
        w.put(0, "class A { int x; }");
        // no finish yet: not readable
        assert!(Reader::open(&dir, 3).is_none());
        let r = w.finish().unwrap();
        let mut f = r.file().unwrap();
        assert_eq!(r.get(&mut f, 0).as_deref(), Some("class A { int x; }"));
        assert_eq!(r.get(&mut f, 1), None);
        assert_eq!(r.get(&mut f, 2).as_deref(), Some("class C {}"));
        let _ = fs::remove_dir_all(dir);
    }
}
