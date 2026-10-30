//! Just enough ELF to inspect Android native libraries: architecture, needed libraries,
//! exported symbols (and the Java methods behind `Java_...` exports), and readable strings.

pub struct Elf {
    pub machine: &'static str,
    pub bits: u8,
    pub needed: Vec<String>,
    /// defined, global function and object symbols
    pub exports: Vec<String>,
}

fn rd(d: &[u8], off: usize, n: usize) -> Option<u64> {
    let b = d.get(off..off + n)?;
    Some(b.iter().rev().fold(0u64, |a, &x| (a << 8) | x as u64))
}

fn cstr(d: &[u8], off: usize) -> Option<String> {
    let s = d.get(off..)?;
    let end = s.iter().position(|&b| b == 0)?;
    Some(String::from_utf8_lossy(&s[..end]).into_owned())
}

pub fn parse(d: &[u8]) -> Result<Elf, String> {
    if d.len() < 64 || &d[..4] != b"\x7fELF" {
        return Err("not an ELF file".into());
    }
    if d[5] != 1 {
        return Err("big-endian ELF is not supported".into());
    }
    let wide = d[4] == 2;
    let w = if wide { 8 } else { 4 };
    let machine = match rd(d, 18, 2) {
        Some(0x28) => "arm (armeabi-v7a)",
        Some(0xb7) => "arm64 (arm64-v8a)",
        Some(0x03) => "x86",
        Some(0x3e) => "x86_64",
        Some(0xf3) => "riscv",
        _ => "unknown",
    };
    let shoff = rd(d, if wide { 0x28 } else { 0x20 }, w).ok_or("bad header")? as usize;
    let shentsize = rd(d, if wide { 0x3a } else { 0x2e }, 2).ok_or("bad header")? as usize;
    let shnum = rd(d, if wide { 0x3c } else { 0x30 }, 2).ok_or("bad header")? as usize;
    // (type, offset, size, link, entsize)
    let sections: Vec<(u32, usize, usize, usize, usize)> = (0..shnum)
        .filter_map(|i| {
            let o = shoff + i * shentsize;
            let ty = rd(d, o + 4, 4)? as u32;
            let (off, size, link, ent) = if wide {
                (rd(d, o + 0x18, 8)?, rd(d, o + 0x20, 8)?, rd(d, o + 0x28, 4)?, rd(d, o + 0x38, 8)?)
            } else {
                (rd(d, o + 0x10, 4)?, rd(d, o + 0x14, 4)?, rd(d, o + 0x18, 4)?, rd(d, o + 0x24, 4)?)
            };
            Some((ty, off as usize, size as usize, link as usize, ent as usize))
        })
        .collect();
    let mut exports = Vec::new();
    let mut needed = Vec::new();
    for &(ty, off, size, link, ent) in &sections {
        let strtab = sections.get(link).map_or(0, |s| s.1);
        match ty {
            // SHT_DYNSYM
            11 if ent > 0 => {
                for k in 1..size / ent {
                    let o = off + k * ent;
                    let (name, info, shndx) = if wide {
                        (rd(d, o, 4), d.get(o + 4).copied(), rd(d, o + 6, 2))
                    } else {
                        (rd(d, o, 4), d.get(o + 12).copied(), rd(d, o + 14, 2))
                    };
                    let (Some(name), Some(info), Some(shndx)) = (name, info, shndx) else { continue };
                    let (bind, kind) = (info >> 4, info & 0xf);
                    // defined (not imported), global or weak, function or object
                    if shndx != 0 && (bind == 1 || bind == 2) && (kind == 1 || kind == 2) {
                        if let Some(n) = cstr(d, strtab + name as usize).filter(|n| !n.is_empty()) {
                            exports.push(n);
                        }
                    }
                }
            }
            // SHT_DYNAMIC: DT_NEEDED entries
            6 if ent > 0 => {
                for k in 0..size / ent {
                    let o = off + k * ent;
                    let (tag, val) = (rd(d, o, w), rd(d, o + w, w));
                    if tag == Some(1) {
                        if let Some(n) = val.and_then(|v| cstr(d, strtab + v as usize)) {
                            needed.push(n);
                        }
                    }
                }
            }
            _ => {}
        }
    }
    exports.sort();
    exports.dedup();
    Ok(Elf { machine, bits: if wide { 64 } else { 32 }, needed, exports })
}

/// `Java_com_example_Foo_bar__I` -> ("com.example.Foo", "bar"), per the JNI name mangling rules.
pub fn jni_target(sym: &str) -> Option<(String, String)> {
    let body = sym.strip_prefix("Java_")?;
    // the overload signature starts at the first unescaped `__`
    let mut parts: Vec<String> = vec![String::new()];
    let b: Vec<char> = body.chars().collect();
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            '_' if b.get(i + 1) == Some(&'_') => break,
            '_' => match b.get(i + 1) {
                Some('1') => {
                    parts.last_mut()?.push('_');
                    i += 1;
                }
                Some('2') => {
                    parts.last_mut()?.push(';');
                    i += 1;
                }
                Some('3') => {
                    parts.last_mut()?.push('[');
                    i += 1;
                }
                Some('0') => {
                    let hex: String = b.get(i + 2..i + 6)?.iter().collect();
                    parts.last_mut()?.push(char::from_u32(u32::from_str_radix(&hex, 16).ok()?)?);
                    i += 5;
                }
                _ => parts.push(String::new()),
            },
            c => parts.last_mut()?.push(c),
        }
        i += 1;
    }
    let method = parts.pop()?;
    (!parts.is_empty() && !method.is_empty()).then(|| (parts.join("."), method))
}

/// Printable ASCII runs of at least `min` bytes.
pub fn strings(d: &[u8], min: usize) -> Vec<String> {
    let mut out = Vec::new();
    let mut start = None;
    for (i, &c) in d.iter().enumerate() {
        let ok = (0x20..0x7f).contains(&c) || c == b'\t';
        match (ok, start) {
            (true, None) => start = Some(i),
            (false, Some(s)) => {
                if i - s >= min {
                    out.push(String::from_utf8_lossy(&d[s..i]).into_owned());
                }
                start = None;
            }
            _ => {}
        }
    }
    if let Some(s) = start.filter(|&s| d.len() - s >= min) {
        out.push(String::from_utf8_lossy(&d[s..]).into_owned());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn jni_names() {
        assert_eq!(jni_target("Java_com_example_Foo_bar"), Some(("com.example.Foo".into(), "bar".into())));
        // _1 is a literal underscore, __ starts the overload signature
        assert_eq!(jni_target("Java_com_my_1app_Native_init__ILjava_lang_String_2"), Some(("com.my_app.Native".into(), "init".into())));
        assert_eq!(jni_target("JNI_OnLoad"), None);
    }

    #[test]
    fn string_runs() {
        assert_eq!(strings(b"\x00\x01https://a.b/c\x00ab\x00token=xyz", 6), vec!["https://a.b/c".to_string(), "token=xyz".to_string()]);
    }

    #[test]
    fn rejects_non_elf() {
        assert!(parse(b"not an elf at all, just some bytes here.....................................").is_err());
    }
}
