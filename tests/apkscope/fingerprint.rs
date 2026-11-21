//! Tests for `apkscope fingerprint`.
//!
//! Internal test module (sibling pattern: `#[cfg(test)] #[path = ...] mod tests;` in
//! `src/fingerprint/mod.rs`). Uses `crate::` paths because there is no `lib.rs`.
//!
//! The matcher is exercised end-to-end via the CLI on synthetic APKs (scripts/
//! synth_fake_apk.py); these tests cover the pure parts: catalog shape, category
//! parsing, snapshot stability, and diff keying.

use crate::fingerprint::{self, Category, Confidence, FINGERPRINTS, exodus};

#[test]
fn catalogs_are_nonempty_and_unique() {
    assert!(
        !FINGERPRINTS.is_empty(),
        "curated catalog should not be empty"
    );
    let mut ids: Vec<&str> = FINGERPRINTS.iter().map(|f| f.id).collect();
    ids.sort();
    let before = ids.len();
    ids.dedup();
    assert_eq!(
        ids.len(),
        before,
        "duplicate fingerprint ids in the curated catalog"
    );
    assert!(
        exodus::TRACKERS.len() > 400,
        "Exodus import should be substantial"
    );
    let mut names = exodus::TRACKERS.iter().map(|t| t.name).collect::<Vec<_>>();
    names.sort_unstable();
    // names may repeat across ids in the source; ids must not
    let mut tids = exodus::TRACKERS.iter().map(|t| t.id).collect::<Vec<_>>();
    tids.sort_unstable();
    tids.dedup();
    assert_eq!(tids.len(), exodus::TRACKERS.len(), "duplicate Exodus ids");
}

#[test]
fn catalog_entries_have_signals() {
    for fp in FINGERPRINTS {
        assert!(!fp.id.is_empty(), "entry with empty id");
        assert!(
            !fp.dex.is_empty()
                || !fp.native_libs.is_empty()
                || !fp.manifest_meta.is_empty()
                || !fp.assets.is_empty()
                || !fp.manifest_activities.is_empty(),
            "{} has no dex/native/meta/asset/activity signal",
            fp.id
        );
    }
    for t in exodus::TRACKERS {
        assert!(
            !t.alts.is_empty(),
            "Exodus tracker {} has no alternatives",
            t.name
        );
    }
}

#[test]
fn exodus_alternatives_are_slash_form() {
    // every alternative must be a slash-form package path or class fragment: no dots,
    // no leading/trailing slash, non-empty
    for t in exodus::TRACKERS {
        for a in t.alts {
            assert!(!a.is_empty(), "{}: empty alternative", t.name);
            assert!(
                !a.contains('.'),
                "{}: dot-form alternative {a} leaked through",
                t.name
            );
            assert!(
                !a.starts_with('/') && !a.ends_with('/'),
                "{}: bad edges in {a}",
                t.name
            );
        }
    }
}

#[test]
fn category_parse_roundtrips() {
    let all = [
        Category::Ads,
        Category::Analytics,
        Category::Crash,
        Category::Framework,
        Category::Integrity,
        Category::License,
        Category::Monetization,
        Category::Network,
        Category::Push,
        Category::Auth,
        Category::Media,
        Category::Storage,
        Category::Di,
        Category::Util,
        Category::Obfuscator,
    ];
    for c in all {
        assert_eq!(Category::parse(c.as_str()), Some(c));
    }
    assert_eq!(Category::parse("nonsense"), None);
}

#[test]
fn confidence_ordering_for_sort() {
    let rank = |c: Confidence| c.rank();
    assert!(rank(Confidence::Confirmed) < rank(Confidence::Strong));
    assert!(rank(Confidence::Strong) < rank(Confidence::Weak));
}

#[test]
fn snapshot_is_stable_and_ignores_weak() {
    // two detection sets that differ only in ordering hash the same; weak entries
    // and evidence details do not affect the snapshot
    let d = |id: &'static str, conf: Confidence| crate::fingerprint::Detection {
        id,
        category: Category::Ads,
        confidence: conf,
        version: None,
        evidence: vec![],
        origin: fingerprint::Origin::Curated,
        exodus_id: None,
    };
    let a = vec![d("x", Confidence::Confirmed), d("y", Confidence::Strong)];
    let b = vec![d("y", Confidence::Strong), d("x", Confidence::Confirmed)];
    assert_eq!(fingerprint::snapshot(&a), fingerprint::snapshot(&b));
    let with_weak = vec![
        d("x", Confidence::Confirmed),
        d("weakling", Confidence::Weak),
    ];
    let without = vec![d("x", Confidence::Confirmed)];
    assert_eq!(
        fingerprint::snapshot(&with_weak),
        fingerprint::snapshot(&without),
        "weak detections must not enter the snapshot"
    );
    let versioned = vec![crate::fingerprint::Detection {
        id: "x",
        category: Category::Ads,
        confidence: Confidence::Confirmed,
        version: Some("1.2.3".into()),
        evidence: vec![],
        origin: fingerprint::Origin::Curated,
        exodus_id: None,
    }];
    assert_ne!(
        fingerprint::snapshot(&versioned),
        fingerprint::snapshot(&a),
        "a pinned version must change the snapshot"
    );
}

#[test]
fn diff_buckets_by_id() {
    let d = |id: &'static str, v: Option<&str>| crate::fingerprint::Detection {
        id,
        category: Category::Ads,
        confidence: Confidence::Confirmed,
        version: v.map(str::to_string),
        evidence: vec![],
        origin: fingerprint::Origin::Curated,
        exodus_id: None,
    };
    let a = vec![
        d("kept", None),
        d("gone", None),
        d("same", Some("1.0.0")),
        d("bump", Some("1.0.0")),
    ];
    let b = vec![
        d("kept", None),
        d("added", None),
        d("same", Some("1.0.0")),
        d("bump", Some("1.1.0")),
    ];
    let (added, removed, changed) = fingerprint::diff(&a, &b);
    assert_eq!(added.iter().map(|d| d.id).collect::<Vec<_>>(), ["added"]);
    assert_eq!(removed.iter().map(|d| d.id).collect::<Vec<_>>(), ["gone"]);
    assert_eq!(changed.len(), 1);
    assert_eq!(changed[0].0.version.as_deref(), Some("1.0.0"));
    assert_eq!(changed[0].1.version.as_deref(), Some("1.1.0"));
}

#[test]
fn banner_pins_okhttp_and_firebase() {
    use crate::fingerprint::pin;
    let pool = [
        "some string".to_string(),
        "okhttp/4.12.0".to_string(),
        "another".to_string(),
    ];
    let (v, ev) = pin::banner("okhttp", &pool).expect("okhttp banner should pin");
    assert_eq!(v, "4.12.0");
    assert_eq!(ev, "okhttp/4.12.0");

    let fb = [
        "firebase-common".to_string(),
        "20.4.2".to_string(),
        "firebase-analytics".to_string(),
        "21.5.0".to_string(),
    ];
    let (v, ev) = pin::banner("firebase_core", &fb).expect("firebase pairs should pin");
    assert!(v.contains("firebase-analytics 21.5.0"), "got {v}");
    assert!(ev.contains("firebase-common 20.4.2"), "got {ev}");
}

#[test]
fn gms_version_table_and_lookup() {
    use crate::fingerprint::pin;
    assert_eq!(pin::gms_version(12451000), Some("12.4.51"));
    assert_eq!(pin::gms_version(999), None);
    let values =
        "<resources><integer name=\"google_play_services_version\">12451000</integer></resources>";
    assert_eq!(pin::gms_version_from_texts(values), Some("12.4.51"));
    assert_eq!(pin::gms_version_from_texts("nothing here"), None);
}

#[test]
fn list_catalog_mentions_both_catalogs() {
    let lines = fingerprint::list_catalog(fingerprint::Catalog::Curated, None);
    assert!(lines.iter().any(|l| l.contains("curated")));
    assert!(lines.iter().any(|l| l.contains("Exodus")));
    assert!(lines.iter().any(|l| l.contains("exodus-privacy.eu.org")));
    // --all lists the Exodus names, not just the counts
    let all = fingerprint::list_catalog(fingerprint::Catalog::Both, None);
    assert!(
        all.len() > lines.len(),
        "--all should list more rows than the curated-only catalog"
    );
    // --category filters both halves
    let ads = fingerprint::list_catalog(fingerprint::Catalog::Both, Some(Category::Ads));
    assert!(ads.iter().any(|l| l.contains("ads (")));
    assert!(!ads.iter().any(|l| l.contains("framework (")));
}

#[test]
fn json_catalog_is_valid_object_shape() {
    let j = fingerprint::json_catalog(fingerprint::Catalog::Curated, None);
    assert!(
        j.starts_with("{\n"),
        "JSON catalog should be an object, got: {}",
        &j[..30]
    );
    assert!(j.contains("\"counts\":"));
    assert!(j.contains("\"curated\": ["));
    assert!(j.contains("\"exodus_license\": \"ODbL 1.0"));
    assert!(j.trim_end().ends_with('}'), "should close the object");
    // every double quote balanced — cheap structural check without a JSON crate
    assert_eq!(j.matches('"').count() % 2, 0, "unbalanced quotes in json_catalog");
    let both = fingerprint::json_catalog(fingerprint::Catalog::Both, None);
    assert!(both.contains("\"exodus\": ["));
    assert!(both.contains("\"exodus_id\":"));
}

#[test]
fn json_report_is_valid_object_shape() {
    let d = |id: &'static str| crate::fingerprint::Detection {
        id,
        category: Category::Ads,
        confidence: Confidence::Confirmed,
        version: Some("1.0.0".into()),
        evidence: vec![],
        origin: fingerprint::Origin::Curated,
        exodus_id: None,
    };
    let an = crate::fingerprint::Analysis {
        detections: vec![d("x"), d("y")],
        obf_ratio: 0.75,
        file: "app.apk".into(),
    };
    let j = fingerprint::json_report(&an);
    assert!(j.starts_with("{\n"), "report should be an object");
    assert!(j.contains("\"file\": \"app.apk\""));
    assert!(j.contains("\"count\": 2"));
    assert!(j.contains("\"obfuscation\": \"heavy\""));
    assert!(j.contains("\"sdks\": ["));
    assert!(j.contains("\"version\": \"1.0.0\""));
    assert_eq!(j.matches('"').count() % 2, 0, "unbalanced quotes in json_report");
    assert!(j.trim_end().ends_with('}'));
}

#[test]
fn elf_symbol_evidence_is_capped_in_text_report() {
    let ev = |kind: &'static str, value: &str| crate::fingerprint::Evidence {
        kind,
        value: value.to_string(),
        count: 1,
    };
    let d = crate::fingerprint::Detection {
        id: "androidx",
        category: Category::Framework,
        confidence: Confidence::Confirmed,
        version: None,
        evidence: (0..10)
            .map(|i| ev("elf_symbol", &format!("Java_androidx_camera_Core_native{i}")))
            .chain([ev("dex_package", "Landroidx/")])
            .collect(),
        origin: fingerprint::Origin::Curated,
        exodus_id: None,
    };
    let an = crate::fingerprint::Analysis {
        detections: vec![d],
        obf_ratio: 0.0,
        file: "app.apk".into(),
    };
    let lines = fingerprint::text_report(&an, false);
    let sym_lines = lines.iter().filter(|l| l.contains("elf_symbol")).count();
    assert_eq!(sym_lines, 3, "elf_symbol evidence should cap at 3 lines");
    assert!(
        lines.iter().any(|l| l.contains("x7 more JNI symbols")),
        "the capped tail should count the rest, got:\n{}",
        lines.join("\n")
    );
    assert!(
        lines.iter().any(|l| l.contains("SDK") && l.contains("CATEGORY")),
        "report should have a header row"
    );
    assert!(
        lines.iter().all(|l| l == l.trim_end()),
        "no trailing whitespace"
    );
    assert!(
        !lines.iter().any(|l| l.contains('\u{2014}')),
        "report must stay ASCII for non-UTF8 consoles"
    );
}
