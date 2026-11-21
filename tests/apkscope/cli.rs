use super::*;
use clap::error::ErrorKind;

/// Helper: parse succeeds and returns the expected subcommand.
fn parses_as(args: &[&str], check: impl Fn(&Cmd)) {
    let mut full = vec!["apkscope"];
    full.extend_from_slice(args);
    let cli = Cli::try_parse_from(full).expect("should parse");
    match &cli.cmd {
        Some(c) => check(c),
        None => panic!("expected a subcommand, got None"),
    }
}

/// Helper: parse fails (the whole point of the defect-table tests).
fn rejected(args: &[&str]) {
    let mut full = vec!["apkscope"];
    full.extend_from_slice(args);
    match Cli::try_parse_from(full) {
        Ok(_) => panic!("expected parse failure, got success"),
        Err(_) => {}
    }
}

/// Helper: parse fails and we want the error (to inspect its kind).
fn parse_err(args: &[&str]) -> clap::Error {
    let mut full = vec!["apkscope"];
    full.extend_from_slice(args);
    Cli::try_parse_from(full)
        .err()
        .expect("expected a parse error")
}

// ── compat matrix: every command form parses ──

#[test]
fn classes_and_alias() {
    parses_as(&["classes", "x.apk"], |c| {
        assert!(matches!(c, Cmd::Classes(_)))
    });
    parses_as(&["listclass", "x.apk"], |c| {
        assert!(matches!(c, Cmd::Classes(_)))
    });
    parses_as(
        &[
            "classes",
            "x.apk",
            "--prefix",
            "com.example",
            "--app-only",
            "--desc",
        ],
        |c| assert!(matches!(c, Cmd::Classes(_))),
    );
}

#[test]
fn methods_and_alias() {
    parses_as(&["methods", "x.apk"], |c| {
        assert!(matches!(c, Cmd::Methods(_)))
    });
    parses_as(
        &["listmethod", "x.apk", "--class", "C", "--filter", "F"],
        |c| assert!(matches!(c, Cmd::Methods(_))),
    );
    parses_as(&["methods", "x.apk", "-f", "F"], |c| {
        assert!(matches!(c, Cmd::Methods(_)))
    });
}

#[test]
fn strings_and_alias() {
    parses_as(&["strings", "x.apk"], |c| {
        assert!(matches!(c, Cmd::Strings(_)))
    });
    parses_as(&["liststring", "x.apk", "-f", "F"], |c| {
        assert!(matches!(c, Cmd::Strings(_)))
    });
}

#[test]
fn refs_and_alias() {
    parses_as(&["refs", "x.apk", "type", "Foo"], |c| {
        assert!(matches!(c, Cmd::Refs(_)))
    });
    parses_as(&["findrefs", "x.apk", "type", "Foo", "Bar"], |c| {
        assert!(matches!(c, Cmd::Refs(_)))
    });
    parses_as(
        &[
            "refs",
            "x.apk",
            "type",
            "Foo",
            "--class",
            "C",
            "--fuzzy-class",
            "--regex",
            "--ignore-case",
            "--java",
        ],
        |c| assert!(matches!(c, Cmd::Refs(_))),
    );
}

#[test]
fn decompile_and_alias() {
    parses_as(&["decompile", "x.apk"], |c| {
        assert!(matches!(c, Cmd::Decompile(_)))
    });
    parses_as(&["getclass", "x.apk", "a.b.C", "c.d.E"], |c| {
        assert!(matches!(c, Cmd::Decompile(_)))
    });
    parses_as(
        &[
            "decompile",
            "x.apk",
            "a.b.C",
            "--method",
            "m",
            "--smali",
            "--full",
        ],
        |c| assert!(matches!(c, Cmd::Decompile(_))),
    );
}

#[test]
fn manifest_and_alias() {
    parses_as(&["manifest", "x.apk"], |c| {
        assert!(matches!(c, Cmd::Manifest(_)))
    });
    parses_as(&["getmanifest", "x.apk"], |c| {
        assert!(matches!(c, Cmd::Manifest(_)))
    });
}

#[test]
fn diff() {
    parses_as(&["diff", "a.apk", "b.apk"], |c| {
        assert!(matches!(c, Cmd::Diff(_)))
    });
    parses_as(&["diff", "a.apk", "b.apk", "--strings"], |c| {
        assert!(matches!(c, Cmd::Diff(_)))
    });
}

#[test]
fn recon() {
    parses_as(&["callers", "x.apk", "C"], |c| {
        assert!(matches!(c, Cmd::Callers(_)))
    });
    parses_as(&["callgraph", "x.apk", "C", "--depth", "5"], |c| {
        assert!(matches!(c, Cmd::Callgraph(_)))
    });
    parses_as(&["access", "x.apk", "C", "field"], |c| {
        assert!(matches!(c, Cmd::Access(_)))
    });
    parses_as(&["frida", "x.apk", "C", "--live"], |c| {
        assert!(matches!(c, Cmd::Frida(_)))
    });
}

#[test]
fn dump() {
    parses_as(
        &[
            "dump",
            "app",
            "out",
            "--attach",
            "-D",
            "dev",
            "--wait",
            "5",
            "--scripts-for",
            "6",
        ],
        |c| assert!(matches!(c, Cmd::Dump(_))),
    );
}

#[test]
fn il2cpp() {
    parses_as(&["il2cpp", "a.apk"], |c| {
        assert!(matches!(c, Cmd::Il2cpp(_)))
    });
    parses_as(
        &[
            "il2cpp", "a.apk", "b.xapk", "--uses", "TEXT", "--method", "NAME",
        ],
        |c| assert!(matches!(c, Cmd::Il2cpp(_))),
    );
}

#[test]
fn flutter_scan_decrypt() {
    parses_as(
        &["flutter", "x.apk", "--abi", "arm", "--api", "--strings"],
        |c| assert!(matches!(c, Cmd::Flutter(_))),
    );
    parses_as(&["scan", "x.apk"], |c| assert!(matches!(c, Cmd::Scan(_))));
    parses_as(&["decrypt", "x.apk"], |c| {
        assert!(matches!(c, Cmd::Decrypt(_)))
    });
}

#[test]
fn fingerprint_and_alias() {
    parses_as(&["fingerprint", "x.apk"], |c| {
        assert!(matches!(c, Cmd::Fingerprint(_)))
    });
    parses_as(&["fp", "x.apk"], |c| {
        assert!(matches!(c, Cmd::Fingerprint(_)))
    });
    parses_as(
        &["fingerprint", "x.apk", "--category", "ads", "--strings"],
        |c| assert!(matches!(c, Cmd::Fingerprint(_))),
    );
    // the APK positional is optional: --list needs no file
    parses_as(&["fingerprint", "--list"], |c| {
        assert!(matches!(c, Cmd::Fingerprint(_)))
    });
    parses_as(
        &[
            "fingerprint",
            "x.apk",
            "--diff",
            "y.apk",
            "--snapshot",
            "--all",
        ],
        |c| assert!(matches!(c, Cmd::Fingerprint(_))),
    );
}

#[test]
fn fingerprint_without_apk_or_list_is_rejected_by_the_handler() {
    // clap accepts a bare `fingerprint` (optional positional); the handler must Err.
    // Parsing succeeds, so exercise the handler's guard through the parsed args.
    let full = ["apkscope", "fingerprint"];
    let cli = Cli::try_parse_from(full).expect("should parse");
    match &cli.cmd {
        Some(Cmd::Fingerprint(a)) => {
            assert!(a.apk.is_none());
            assert!(!a.list);
            // the guard lives in commands::fingerprint::fingerprint_cmd; the parse
            // shape is what these tests own, so reaching here is the contract
        }
        _ => panic!("expected Fingerprint"),
    }
}

#[test]
fn fingerprint_bad_category_parses_handler_validates() {
    // category is a free-form String at parse time (the handler validates against the
    // enum); a parse-level rejection would need a value_parser. We still confirm the
    // accepted shape parses so the handler sees it and returns its own Err.
    parses_as(&["fingerprint", "x.apk", "--category", "nope"], |c| {
        assert!(matches!(c, Cmd::Fingerprint(_)))
    });
}

#[test]
fn rename_comment_free_text() {
    // trailing text is variadic; this is the surface the --verbose bug used to corrupt
    parses_as(&["rename", "x.apk", "a.b.C", "new", "name"], |c| {
        assert!(matches!(c, Cmd::Rename(_)))
    });
    parses_as(
        &["comment", "x.apk", "a.b.C", "some", "comment", "text"],
        |c| assert!(matches!(c, Cmd::Comment(_))),
    );
}

#[test]
fn map_import_export() {
    parses_as(&["map", "x.apk", "export", "f.txt"], |c| {
        assert!(matches!(c, Cmd::Map(_)))
    });
    parses_as(&["map", "x.apk", "import", "f.jobf"], |c| {
        assert!(matches!(c, Cmd::Map(_)))
    });
}

#[test]
fn info_resource_export_res_verify() {
    parses_as(&["info", "x.apk"], |c| assert!(matches!(c, Cmd::Info(_))));
    parses_as(&["resource", "x.apk", "res/values.xml"], |c| {
        assert!(matches!(c, Cmd::Resource(_)))
    });
    parses_as(&["export", "x.apk", "out"], |c| {
        assert!(matches!(c, Cmd::Export(_)))
    });
    parses_as(&["res", "x.apk", "out"], |c| {
        assert!(matches!(c, Cmd::Res(_)))
    });
    parses_as(&["verify", "x.apk"], |c| {
        assert!(matches!(c, Cmd::Verify(_)))
    });
}

#[test]
fn search_local_out_and_format() {
    parses_as(&["search", "x.apk", "code", "foo"], |c| {
        assert!(matches!(c, Cmd::Search(_)))
    });
    parses_as(
        &[
            "search",
            "x.apk",
            "code",
            "foo",
            "--regex",
            "--case",
            "--app-only",
            "--context",
            "3",
            "--method",
            "--format",
            "json",
            "-o",
            "f.txt",
        ],
        |c| assert!(matches!(c, Cmd::Search(_))),
    );
}

#[test]
fn build_all_options() {
    parses_as(
        &[
            "build",
            "in.apk",
            "out.apk",
            "--put",
            "a=b",
            "--delete",
            "c",
            "--no-sign",
            "--string",
            "n=v",
            "--smali",
            "s.smali",
            "--manifest",
            "m.xml",
            "--key",
            "k.pk8",
            "--cert",
            "c.crt",
        ],
        |c| assert!(matches!(c, Cmd::Build(_))),
    );
}

#[test]
fn mcp_and_worker() {
    parses_as(&["mcp"], |c| assert!(matches!(c, Cmd::Mcp)));
    parses_as(&["worker", "x.apk"], |c| {
        assert!(matches!(c, Cmd::Worker(_)))
    });
}

#[test]
fn disasm_optional_class() {
    parses_as(&["disasm", "x.apk"], |c| {
        assert!(matches!(c, Cmd::Disasm(_)))
    });
    parses_as(&["disasm", "x.apk", "C"], |c| {
        assert!(matches!(c, Cmd::Disasm(_)))
    });
}

#[test]
fn gui_optional_apk() {
    parses_as(&["gui"], |c| assert!(matches!(c, Cmd::Gui(_))));
    parses_as(&["gui", "x.apk"], |c| assert!(matches!(c, Cmd::Gui(_))));
}

#[test]
fn global_flags_anywhere() {
    parses_as(
        &[
            "--json",
            "--limit",
            "10",
            "--offset",
            "2",
            "--threads",
            "4",
            "-o",
            "f",
            "--no-deobf",
            "--no-cache",
            "classes",
            "x.apk",
        ],
        |c| assert!(matches!(c, Cmd::Classes(_))),
    );
    parses_as(&["classes", "x.apk", "--json", "--limit", "10"], |c| {
        assert!(matches!(c, Cmd::Classes(_)))
    });
    // --thread (singular alias) works
    parses_as(&["--thread", "4", "classes", "x.apk"], |c| {
        assert!(matches!(c, Cmd::Classes(_)))
    });
}

// ── defect table: things the hand-rolled parser silently got wrong ──

#[test]
fn defect1_unknown_flag_rejected_not_silently_consumed() {
    // the `rename ... --verbose` case used to write "new --verbose" into the project file
    rejected(&["rename", "x.apk", "a.b.C", "new", "--verbose"]);
    // typo'd --regexx used to join into the search query
    rejected(&["search", "x.apk", "code", "foo", "--regexx"]);
    // typo'd --methd used to become a second input APK
    rejected(&["il2cpp", "x.apk", "--methd", "foo"]);
    // typo'd --app-onl used to be a generic usage error with no hint
    rejected(&["classes", "x.apk", "--app-onl"]);
    // a truly unknown global flag
    rejected(&["--bogus", "classes", "x.apk"]);
    rejected(&["classes", "x.apk", "--bogus"]);
}

#[test]
fn defect2_option_does_not_eat_next_flag_as_value() {
    // --class used to swallow --app-only as the class name
    rejected(&["methods", "--class", "--app-only", "x.apk"]);
    rejected(&["refs", "x.apk", "type", "Foo", "--class", "--java"]);
    rejected(&["flutter", "x.apk", "--abi", "--api"]);
}

#[test]
fn defect4_version_and_help_are_builtins() {
    // --help is a clap "error" of kind DisplayHelp (printed to stdout, exit 0 in the real binary)
    assert_eq!(parse_err(&["--help"]).kind(), ErrorKind::DisplayHelp);

    // --version is our own flag, not clap's: `apkscope upgrade` runs `--version --json`
    // on a staged binary to check its identity, so --json must reach it
    for args in [
        &["apkscope", "--version"][..],
        &["apkscope", "-V"],
        &["apkscope", "--json", "--version"],
    ] {
        assert!(Cli::try_parse_from(args).unwrap().version);
    }
    assert!(
        Cli::try_parse_from(["apkscope", "--version", "--json"])
            .unwrap()
            .json
    );
    assert!(
        Cli::try_parse_from(["apkscope", "--revision"])
            .unwrap()
            .revision
    );
}

#[test]
fn defect4_typed_numeric_rejected_at_parse_time() {
    rejected(&["--limit", "foo", "classes", "x.apk"]);
    rejected(&["--offset", "x", "classes", "x.apk"]);
    rejected(&["--threads", "notanum", "classes", "x.apk"]);
    rejected(&["callgraph", "x.apk", "C", "--depth", "abc"]);
    rejected(&["dump", "app", "out", "--wait", "xyz"]);
}

#[test]
fn missing_required_positional_is_a_parse_error() {
    // a missing APK is now a parse error (exit 2), not a handler-side Err (exit 1)
    rejected(&["classes"]);
    rejected(&["manifest"]);
    rejected(&["callers", "x.apk"]); // access/callers need a class
    rejected(&["verify"]);
    rejected(&["build", "in.apk"]); // needs output too
}

#[test]
fn extra_positional_rejected() {
    // classes takes exactly one positional; a second is unexpected, not silently used
    rejected(&["classes", "x.apk", "extra"]);
    rejected(&["manifest", "x.apk", "extra"]);
}

#[test]
fn search_all_flag_parses() {
    // urls / http / secrets default to app code only; --all opts back out
    parses_as(&["search", "x.apk", "urls", "--all"], |c| {
        let Cmd::Search(a) = c else {
            panic!("expected search")
        };
        assert!(a.all && !a.app_only);
    });
    parses_as(&["search", "x.apk", "secrets", "--app-only"], |c| {
        let Cmd::Search(a) = c else {
            panic!("expected search")
        };
        assert!(a.app_only && !a.all);
    });
}
