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

/// The section headers the parsers read: (type, offset, size, link, entsize).
type Section = (u32, usize, usize, usize, usize);

fn sections(d: &[u8]) -> Result<Vec<Section>, String> {
    if d.len() < 64 || &d[..4] != b"\x7fELF" {
        return Err("not an ELF file".into());
    }
    if d[5] != 1 {
        return Err("big-endian ELF is not supported".into());
    }
    let wide = d[4] == 2;
    let shoff = rd(d, if wide { 0x28 } else { 0x20 }, if wide { 8 } else { 4 })
        .ok_or("bad header")? as usize;
    let shentsize = rd(d, if wide { 0x3a } else { 0x2e }, 2).ok_or("bad header")? as usize;
    let shnum = rd(d, if wide { 0x3c } else { 0x30 }, 2).ok_or("bad header")? as usize;
    Ok((0..shnum)
        .filter_map(|i| {
            let o = shoff + i * shentsize;
            let ty = rd(d, o + 4, 4)? as u32;
            let (off, size, link, ent) = if wide {
                (
                    rd(d, o + 0x18, 8)?,
                    rd(d, o + 0x20, 8)?,
                    rd(d, o + 0x28, 4)?,
                    rd(d, o + 0x38, 8)?,
                )
            } else {
                (
                    rd(d, o + 0x10, 4)?,
                    rd(d, o + 0x14, 4)?,
                    rd(d, o + 0x18, 4)?,
                    rd(d, o + 0x24, 4)?,
                )
            };
            Some((ty, off as usize, size as usize, link as usize, ent as usize))
        })
        .collect())
}

/// Defined global function and object symbol names from `.dynsym`, in table order.
fn dynsyms(d: &[u8], sections: &[Section]) -> Vec<String> {
    let mut out = Vec::new();
    let wide = d[4] == 2;
    for &(ty, off, size, link, ent) in sections {
        let strtab = sections.get(link).map_or(0, |s| s.1);
        // SHT_DYNSYM
        if ty != 11 || ent == 0 {
            continue;
        }
        for k in 1..size / ent {
            let o = off + k * ent;
            let (name, info, shndx) = if wide {
                (rd(d, o, 4), d.get(o + 4).copied(), rd(d, o + 6, 2))
            } else {
                (rd(d, o, 4), d.get(o + 12).copied(), rd(d, o + 14, 2))
            };
            let (Some(name), Some(info), Some(shndx)) = (name, info, shndx) else {
                continue;
            };
            let (bind, kind) = (info >> 4, info & 0xf);
            // defined (not imported), global or weak, function or object
            if shndx != 0
                && (bind == 1 || bind == 2)
                && (kind == 1 || kind == 2)
                && let Some(n) = cstr(d, strtab + name as usize).filter(|n| !n.is_empty())
            {
                out.push(n);
            }
        }
    }
    out
}

pub fn parse(d: &[u8]) -> Result<Elf, String> {
    if d.len() < 64 || &d[..4] != b"\x7fELF" {
        return Err("not an ELF file".into());
    }
    if d[5] != 1 {
        return Err("big-endian ELF is not supported".into());
    }
    let wide = d[4] == 2;
    let machine = match rd(d, 18, 2) {
        Some(0x28) => "arm (armeabi-v7a)",
        Some(0xb7) => "arm64 (arm64-v8a)",
        Some(0x03) => "x86",
        Some(0x3e) => "x86_64",
        Some(0xf3) => "riscv",
        _ => "unknown",
    };
    let secs = sections(d)?;
    let mut exports = dynsyms(d, &secs);
    let mut needed = Vec::new();
    let w = if wide { 8 } else { 4 };
    for &(ty, off, size, link, ent) in &secs {
        let strtab = secs.get(link).map_or(0, |s| s.1);
        // SHT_DYNAMIC: DT_NEEDED entries
        if ty == 6 && ent > 0 {
            for k in 0..size / ent {
                let o = off + k * ent;
                let (tag, val) = (rd(d, o, w), rd(d, o + w, w));
                if tag == Some(1)
                    && let Some(n) = val.and_then(|v| cstr(d, strtab + v as usize))
                {
                    needed.push(n);
                }
            }
        }
    }
    exports.sort();
    exports.dedup();
    Ok(Elf {
        machine,
        bits: if wide { 64 } else { 32 },
        needed,
        exports,
    })
}

/// The `Java_...` JNI entrypoints of a native library: the one subset of the
/// dynsym exports a name-mangling reader can decode into a Java class. The
/// fingerprint pass asks for these only, so it walks the symbol table without
/// collecting, sorting or deduplicating the rest of it.
pub fn jni_symbols(d: &[u8]) -> Vec<String> {
    let Ok(secs) = sections(d) else {
        return Vec::new();
    };
    dynsyms(d, &secs)
        .into_iter()
        .filter(|n| n.starts_with("Java_"))
        .collect()
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
                    parts
                        .last_mut()?
                        .push(char::from_u32(u32::from_str_radix(&hex, 16).ok()?)?);
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
#[path = "../tests/apkscope/elf.rs"]
mod tests;
