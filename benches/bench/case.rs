//! The case set: what gets measured, one [`CaseDef`] per row of the PR table.
//!
//! A case is fully described by its entry in `CASES` — the `--case` id, the row label,
//! the two flags, and the function that builds the run's argv — and nothing else in
//! the harness knows the individual cases: the cold-run flags, the run loop, the
//! medians, the `--hash` digests and every output format work off the registry.
//! To add a case, add one entry (and its `args` function) here, and give the case
//! table in `BENCHMARKS.md` its row.

use std::path::Path;

/// Everything a case's [`CaseDef::args`] builder needs to assemble one run's argv.
pub(crate) struct CaseInput<'a> {
    /// the APK under test
    pub(crate) apk: &'a Path,
    /// the class every column decompiles, picked once from the first column's
    /// `classes` output so outputs — and `--hash` digests — compare
    pub(crate) class: Option<&'a str>,
    /// where the `build` case writes its rebuilt APK
    pub(crate) out: Option<&'a Path>,
}

/// One row of the bench: what runs, what the row is called, who can run it.
/// An `opt_in` case runs only when named with `--case` — rows whose command does
/// not exist on every ref (the default `origin/main` base included) would fail
/// otherwise.
pub(crate) struct CaseDef {
    /// the `--case` name
    pub(crate) id: &'static str,
    /// row label, in the PR-table shape: `apkscope info`, `apkscope decompile` (one class)…
    pub(crate) label: &'static str,
    /// the case needs a class name picked from `classes` output
    pub(crate) needs_class: bool,
    /// only apkscope does it; `--tool` columns show —
    pub(crate) apkscope_only: bool,
    /// runs only when explicitly named with `--case`
    pub(crate) opt_in: bool,
    /// the case-specific argv, spliced after the cold-run flags every run gets
    pub(crate) args: fn(&CaseInput) -> Vec<String>,
}

impl CaseDef {
    /// The argv (after the binary) for one cold run of this case: the cold-run flags
    /// every column gets, then the case's own.
    pub(crate) fn argv(&self, input: &CaseInput) -> Vec<String> {
        let mut a = vec!["-q".to_string(), "--no-cache".to_string()];
        a.extend((self.args)(input));
        a
    }
}

const CASES: &[CaseDef] = &[
    CaseDef {
        id: "info",
        label: "`apkscope info`",
        needs_class: false,
        apkscope_only: true,
        opt_in: false,
        args: info_args,
    },
    CaseDef {
        id: "classes",
        label: "`apkscope classes`",
        needs_class: false,
        apkscope_only: true,
        opt_in: false,
        args: classes_args,
    },
    CaseDef {
        id: "strings",
        label: "`apkscope strings`",
        needs_class: false,
        apkscope_only: true,
        opt_in: false,
        args: strings_args,
    },
    CaseDef {
        id: "decompile",
        label: "`apkscope decompile` (one class)",
        needs_class: true,
        apkscope_only: true,
        opt_in: false,
        args: decompile_args,
    },
    CaseDef {
        id: "smali",
        label: "`apkscope smali` (one class)",
        needs_class: true,
        apkscope_only: true,
        opt_in: false,
        args: smali_args,
    },
    CaseDef {
        id: "build",
        label: "`apkscope build`",
        needs_class: false,
        apkscope_only: true,
        opt_in: false,
        args: build_args,
    },
    // the whole-APK row: `apkscope decompile <apk>` for apkscope, `<tool> <apk>` for tools
    CaseDef {
        id: "whole",
        label: "the whole APK",
        needs_class: false,
        apkscope_only: false,
        opt_in: false,
        args: whole_args,
    },
    // the SDK/tracker fingerprint, heavy mode: both catalogs plus the DEX string-pool
    // scan. Opt-in: the command lands with #51, so a default run against `origin/main`
    // (the `--pr` base) has no such command and the row would fail
    CaseDef {
        id: "fingerprint",
        label: "`apkscope fingerprint --all --strings`",
        needs_class: false,
        apkscope_only: true,
        opt_in: true,
        args: fingerprint_args,
    },
];

/// The full case set, in table order.
pub(crate) fn all_cases() -> &'static [CaseDef] {
    CASES
}

/// The `--case` lookup.
pub(crate) fn case_def(id: &str) -> Option<&'static CaseDef> {
    CASES.iter().find(|c| c.id == id)
}

fn info_args(i: &CaseInput) -> Vec<String> {
    vec!["info".into(), i.apk.display().to_string()]
}

fn classes_args(i: &CaseInput) -> Vec<String> {
    vec!["classes".into(), i.apk.display().to_string()]
}

fn strings_args(i: &CaseInput) -> Vec<String> {
    vec!["strings".into(), i.apk.display().to_string()]
}

fn decompile_args(i: &CaseInput) -> Vec<String> {
    vec![
        "decompile".into(),
        i.apk.display().to_string(),
        i.class.unwrap_or_default().into(),
    ]
}

fn smali_args(i: &CaseInput) -> Vec<String> {
    vec![
        "smali".into(),
        i.apk.display().to_string(),
        i.class.unwrap_or_default().into(),
    ]
}

fn build_args(i: &CaseInput) -> Vec<String> {
    vec![
        "build".into(),
        i.apk.display().to_string(),
        i.out.expect("build case output path").display().to_string(),
    ]
}

fn whole_args(i: &CaseInput) -> Vec<String> {
    vec!["decompile".into(), i.apk.display().to_string()]
}

/// Both catalogs plus the DEX string-pool scan: the mode whose matching work
/// an Aho-Corasick-shaped PR moves the most.
fn fingerprint_args(i: &CaseInput) -> Vec<String> {
    vec![
        "fingerprint".into(),
        "--all".into(),
        "--strings".into(),
        i.apk.display().to_string(),
    ]
}
