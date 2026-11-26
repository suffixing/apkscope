//! `--hash`: what "same output" means and how differences are found. Every run's
//! stdout — for the `build` case, the rebuilt APK as entry list + CRCs — is digested
//! with SHA-256; `hash_diffs` then compares the digests across the apkscope columns
//! and reports every case where they disagree. To change what "same output" means,
//! change `apk_digest` — nothing else needs to know.

use std::{fs, path::Path};

use sha2::{Digest as _, Sha256};

use crate::column::Column;
use crate::measure::ApkBench;

/// One case whose output differs across the compared refs. `cols` holds every ref
/// column's digest, so the report shows which side changed.
pub(crate) struct HashDiff {
    pub(crate) apk: String,
    pub(crate) label: &'static str,
    pub(crate) cols: Vec<(String, String)>,
}

pub(crate) fn hash_diffs(results: &[ApkBench], columns: &[Column]) -> Vec<HashDiff> {
    let ref_idx: Vec<usize> = columns
        .iter()
        .enumerate()
        .filter(|(_, c)| c.is_apkscope())
        .map(|(i, _)| i)
        .collect();
    if ref_idx.len() < 2 {
        return Vec::new();
    }
    let mut diffs = Vec::new();
    for r in results {
        for case in &r.cases {
            let cols: Vec<(String, String)> = ref_idx
                .iter()
                .filter_map(|&i| {
                    case.cells[i]
                        .hash
                        .clone()
                        .map(|h| (columns[i].name.clone(), h))
                })
                .collect();
            let distinct: std::collections::HashSet<&str> =
                cols.iter().map(|(_, h)| h.as_str()).collect();
            if cols.len() == ref_idx.len() && distinct.len() > 1 {
                diffs.push(HashDiff {
                    apk: r
                        .apk
                        .file_name()
                        .map(|s| s.to_string_lossy())
                        .unwrap_or_default()
                        .into_owned(),
                    label: case.def.label,
                    cols,
                });
            }
        }
    }
    diffs
}

/// The `build` case's digest: SHA-256 over the rebuilt APK's entry list and CRCs — the
/// parts that say "same content" — so re-signing or fresh zip timestamps cannot make two
/// identical rebuilds look different.
pub(crate) fn apk_digest(path: &Path) -> Result<String, String> {
    let file = fs::File::open(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let mut zip = zip::ZipArchive::new(file).map_err(|e| format!("{}: {e}", path.display()))?;
    let mut entries: Vec<(Vec<u8>, u32)> = Vec::with_capacity(zip.len());
    for i in 0..zip.len() {
        let e = zip
            .by_index(i)
            .map_err(|e| format!("{}: entry {i}: {e}", path.display()))?;
        // raw name bytes: a stable identity even for the rare non-UTF-8 entry name
        entries.push((e.name_raw().to_vec(), e.crc32()));
    }
    entries.sort();
    let mut h = Sha256::new();
    for (name, crc) in entries {
        h.update(&name);
        h.update(crc.to_le_bytes());
    }
    Ok(hex(&h.finalize()))
}

pub(crate) fn digest_hex(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    hex(&h.finalize())
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        s.push(DIGITS[(b >> 4) as usize] as char);
        s.push(DIGITS[(b & 15) as usize] as char);
    }
    s
}
