use super::*;

#[test]
fn jni_names() {
    assert_eq!(
        jni_target("Java_com_example_Foo_bar"),
        Some(("com.example.Foo".into(), "bar".into()))
    );
    // _1 is a literal underscore, __ starts the overload signature
    assert_eq!(
        jni_target("Java_com_my_1app_Native_init__ILjava_lang_String_2"),
        Some(("com.my_app.Native".into(), "init".into()))
    );
    assert_eq!(jni_target("JNI_OnLoad"), None);
}

#[test]
fn string_runs() {
    assert_eq!(
        strings(b"\x00\x01https://a.b/c\x00ab\x00token=xyz", 6),
        vec!["https://a.b/c".to_string(), "token=xyz".to_string()]
    );
}

#[test]
fn rejects_non_elf() {
    assert!(
        parse(b"not an elf at all, just some bytes here.....................................")
            .is_err()
    );
}

#[test]
fn jni_symbols_reads_only_java_entrypoints() {
    // a minimal ELF64: null section, .dynsym, .strtab, with the symbol shapes
    // the fingerprint pass distinguishes: a JNI export, a plain export, a weak
    // JNI export, an undefined (imported) Java_ name and a local one
    let strtab: &[u8] = b"\0Java_com_example_Foo_bar\0_ZN1a3barEv\0Java_weak\0Java_undef\0";
    const GLOBAL_FUNC: u8 = 0x12;
    const WEAK_FUNC: u8 = 0x22;
    const LOCAL_FUNC: u8 = 0x02;
    let syms: &[(u32, u8, u16)] = &[
        (0, GLOBAL_FUNC, 0),  // the null entry every symbol table starts with
        (1, GLOBAL_FUNC, 1),  // Java_com_example_Foo_bar, defined global
        (26, GLOBAL_FUNC, 1), // a plain C++ export, not a JNI entrypoint
        (38, WEAK_FUNC, 1),   // Java_weak, defined weak
        (48, GLOBAL_FUNC, 0), // Java_undef: shndx 0, an import
        (1, LOCAL_FUNC, 1),   // a local Java_…: not an export
    ];
    let mut d = vec![0u8; 0x200 + 3 * 64];
    d[..4].copy_from_slice(b"\x7fELF");
    d[4] = 2; // ELF64
    d[5] = 1; // little endian
    d[18..20].copy_from_slice(&0xb7u16.to_le_bytes()); // arm64
    d[0x28..0x30].copy_from_slice(&0x200u64.to_le_bytes()); // e_shoff
    d[0x3a..0x3c].copy_from_slice(&64u16.to_le_bytes()); // e_shentsize
    d[0x3c..0x3e].copy_from_slice(&3u16.to_le_bytes()); // e_shnum
    for (k, &(name, info, shndx)) in syms.iter().enumerate() {
        let o = 0x80 + k * 24;
        d[o..o + 4].copy_from_slice(&name.to_le_bytes());
        d[o + 4] = info;
        d[o + 6..o + 8].copy_from_slice(&shndx.to_le_bytes());
    }
    d[0x120..0x120 + strtab.len()].copy_from_slice(strtab);
    // section 1: .dynsym, linked to section 2 (the string table). Elf64_Shdr
    // layout: sh_offset at 0x18, sh_size at 0x20, sh_link at 0x28, sh_entsize at 0x38
    let s = 0x200 + 64;
    d[s + 4..s + 8].copy_from_slice(&11u32.to_le_bytes());
    d[s + 0x18..s + 0x20].copy_from_slice(&0x80u64.to_le_bytes());
    d[s + 0x20..s + 0x28].copy_from_slice(&((syms.len() * 24) as u64).to_le_bytes());
    d[s + 0x28..s + 0x2c].copy_from_slice(&2u32.to_le_bytes());
    d[s + 0x38..s + 0x40].copy_from_slice(&24u64.to_le_bytes());
    // section 2: .strtab
    let s = 0x200 + 128;
    d[s + 4..s + 8].copy_from_slice(&3u32.to_le_bytes());
    d[s + 0x18..s + 0x20].copy_from_slice(&0x120u64.to_le_bytes());
    d[s + 0x20..s + 0x28].copy_from_slice(&(strtab.len() as u64).to_le_bytes());

    assert_eq!(
        jni_symbols(&d),
        vec![
            "Java_com_example_Foo_bar".to_string(),
            "Java_weak".to_string()
        ],
        "table order, defined global and weak JNI names only"
    );
    // the full parser still reports every export, sorted
    let elf = parse(&d).unwrap();
    assert_eq!(
        elf.exports,
        vec![
            "Java_com_example_Foo_bar".to_string(),
            "Java_weak".to_string(),
            "_ZN1a3barEv".to_string()
        ]
    );
}
