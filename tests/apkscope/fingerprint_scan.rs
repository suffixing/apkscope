//! Tests for `src/fingerprint/scan.rs` — the Aho-Corasick pass.
//!
//! The automaton counts must equal the per-signature scans they replaced, so the
//! main test compares every needle in both catalogs — curated dex roots, every
//! Exodus alternative, every net-signature host, every curated URL — against the
//! brute-force scan over a synthetic corpus built to hit the edges: nested
//! package roots, a class equal to a needle, `$` inner classes, needles embedded
//! mid-name, a host repeated inside one pool string. The remaining tests pin
//! the multi-match behaviors the equivalence relies on: anchored searches
//! reporting every overlapping prefix, per-haystack (not per-occurrence)
//! counting, hit recording in pool order, and the category filter shrinking the
//! automata to the live needles.

use std::collections::{BTreeMap, BTreeSet};

use super::{Mode, MultiScan, Plan, dex_root, is_fragment, net_hosts};
use crate::fingerprint::{Catalog, Category, FINGERPRINTS, Pool, Signals, exodus};

/// A Signals value with only the two corpora the scan pass reads.
fn signals(classes: &[&str], pool: &[&str]) -> Signals {
    Signals {
        class_names: classes.iter().map(|s| s.to_string()).collect(),
        permissions: BTreeSet::new(),
        activities: BTreeSet::new(),
        services: BTreeSet::new(),
        meta_keys: BTreeSet::new(),
        native_libs: BTreeSet::new(),
        jni_targets: BTreeMap::new(),
        entries: Vec::new(),
        maven: BTreeMap::new(),
        obf_ratio: 0.0,
        pool: Pool::from_strs(pool),
        dart_snapshot: None,
        values_text: String::new(),
    }
}

#[test]
fn automaton_counts_equal_the_per_signature_scans() {
    let classes = [
        // package paths the automaton must count, nested roots included
        "com/facebook/ads/Adapter",
        "com/facebook/ads/Adapter$Inner", // `$` keeps the class under the package
        "com/google/android/gms/ads/AdView",
        "com/google/android/gms/auth/api/signin/SignIn",
        "com/google/firebase/analytics/FirebaseAnalytics", // a scan tracker's path
        "com/krux/androidsdk/KruxService",
        "org/mozilla/telemetry/Telemetry",
        "androidx/lifecycle/Lifecycle",
        "androidx/camera/Camera",
        "com/applovin/impl/sdk/AppLovinService",
        "io/radar/sdk/Radar", // scan tracker, fragment-shaped alt
        "io/xmode/BcnConfig", // scan tracker
        "LigatusManager",     // fragment with no package at all
        // edges that must NOT count as prefixes
        "com/facebook",          // class exactly equal to the needle: not *under* it
        "xcom/facebook/ads/Foo", // needle embedded, not at byte 0
        "com/facebookx/Other",   // shares the head, no `/` boundary
        // filler so the corpus is not all hits
        "a/b/C",
        "a/b/c/D",
        "io/other/Thing",
    ];
    let pool = [
        "https://pubads.g.doubleclick.net/xyz",
        // the same host twice in one string: one haystack, one count
        "pubads.g.doubleclick.net again pubads.g.doubleclick.net",
        "api.mixpanel.com",
        "decide.mixpanel.com",
        "okhttp/4.12.0",
        "firebase-common",
        "20.4.2",
        "kotlin/1.9.24",
        "krxd.net",
        "plain string with no host",
    ];
    let s = signals(&classes, &pool);
    let mut plan = Plan::build(Catalog::Both, None, true);
    plan.run(&s);

    for fp in FINGERPRINTS {
        for p in fp.dex {
            assert_eq!(
                plan.dex_count(p) as usize,
                s.classes_under(p),
                "dex count for {p} of {}",
                fp.id
            );
        }
        for u in fp.urls {
            let n = (0..s.pool.len())
                .map(|i| s.pool.str(i))
                .filter(|x| x.contains(*u))
                .count();
            assert_eq!(
                plan.host_count(u) as usize,
                n,
                "url count for {u} of {}",
                fp.id
            );
        }
    }
    for t in exodus::TRACKERS {
        for alt in t.alts {
            let n = if is_fragment(t.scan, alt) {
                s.class_names.iter().filter(|c| c.contains(*alt)).count()
            } else {
                let needle = format!("{alt}/");
                s.class_names
                    .iter()
                    .filter(|c| c.starts_with(&needle))
                    .count()
            };
            assert_eq!(
                plan.exodus_alt_count(t.scan, alt) as usize,
                n,
                "alternative count for {alt} of {}",
                t.name
            );
        }
        for host in net_hosts(t.net) {
            let n = (0..s.pool.len())
                .map(|i| s.pool.str(i))
                .filter(|x| x.contains(host.as_str()))
                .count();
            assert_eq!(
                plan.host_count(&host) as usize,
                n,
                "net host count for {host} of {}",
                t.name
            );
        }
    }
}

#[test]
fn anchored_prefixes_count_nested_roots_independently() {
    // `com/google` and `com/google/android` overlap at byte 0: the anchored
    // search must report both, or nested package roots would undercount
    let mut m = MultiScan::new(Mode::Prefix);
    m.add("com/google", false);
    m.add("com/google/android", false);
    m.add("com/facebook", false);
    m.finish(false);
    let corpus = [
        "com/google/android/gms/Ads".to_string(),
        "com/google".to_string(),      // equal to the needle: not under it
        "com/googlex/Ads".to_string(), // no `/` boundary
        "xcom/google/Ads".to_string(), // embedded, not a prefix
        "com/facebook/Foo".to_string(),
    ];
    m.scan(&corpus);
    assert_eq!(m.count("com/google"), 1);
    assert_eq!(m.count("com/google/android"), 1);
    assert_eq!(m.count("com/facebook"), 1);
}

#[test]
fn substring_counts_are_per_haystack_not_per_occurrence() {
    let mut m = MultiScan::new(Mode::Substring);
    m.add("okhttp", false);
    m.add("glide", true); // hit-recording needle
    m.finish(false);
    let corpus = [
        "okhttp twice okhttp".to_string(),
        "xglide".to_string(),
        "glide glide".to_string(),
    ];
    m.scan(&corpus);
    assert_eq!(m.count("okhttp"), 1, "one haystack, one count");
    assert_eq!(m.count("glide"), 2);
    // recorded hits: pool indices in scan order, count-only needles record none
    assert_eq!(m.hit_indices("glide"), &[1, 2]);
    assert!(m.hit_indices("okhttp").is_empty());
}

#[test]
fn dex_root_normalizes_descriptors() {
    assert_eq!(dex_root("Lcom/facebook/ads/"), "com/facebook/ads");
    assert_eq!(dex_root("Lcom/facebook/ads/;"), "com/facebook/ads");
    assert_eq!(dex_root("com/facebook/ads/"), "com/facebook/ads");
}

#[test]
fn net_hosts_unescapes_splits_and_filters() {
    assert_eq!(
        net_hosts("a4\\.tl|accengage\\.com| ad4push\\.com |"),
        ["a4.tl", "accengage.com", "ad4push.com"]
    );
    // short, wildcard and grouping alternatives are skipped
    assert!(net_hosts("ab|a\\.*|foo(bar\\.com").is_empty());
}

#[test]
fn joined_pool_scan_counts_equal_the_per_string_scan() {
    // the pool automaton scans the joined buffer, the fragment automaton scans
    // string by string: on the same corpus and the same needles the two must
    // report identical counts and hit indices, or the pool pass would drift
    let corpus = [
        "okhttp/4.12.0",
        "okhttp twice okhttp", // one string, two hits: one count
        "",
        "xglide",
        "glide glide",
        "glide",
        "kotlin/1.9.24",
        "",
        "plain string",
    ];
    for (mode, needle, record) in [
        ("counts-only", "okhttp", false),
        ("hit-recording", "glide", true),
        ("at-the-edges", "kotlin", true),
        ("never-matching", "absent.host", false),
    ] {
        let mut per_string = MultiScan::new(Mode::Substring);
        let mut joined = MultiScan::new(Mode::Substring);
        per_string.add(needle, record);
        joined.add(needle, record);
        per_string.finish(false);
        joined.finish(true);
        let owned: Vec<String> = corpus.iter().map(|s| s.to_string()).collect();
        per_string.scan(&owned);
        joined.scan_joined(&Pool::from_strs(&corpus));
        assert_eq!(
            per_string.count(needle),
            joined.count(needle),
            "{mode}: count"
        );
        assert_eq!(
            per_string.hit_indices(needle),
            joined.hit_indices(needle),
            "{mode}: hit indices"
        );
    }
    // a needle split across the separator of two strings is not in either one
    let mut m = MultiScan::new(Mode::Substring);
    m.add("hostcom", false);
    m.finish(false);
    let pool = Pool::from_strs(&["ho", "stcom"]);
    m.scan_joined(&pool);
    assert_eq!(m.count("hostcom"), 0, "no match may straddle the separator");
}

#[test]
fn category_filter_registers_only_that_category() {
    let s = signals(&["com/facebook/ads/Adapter", "androidx/Foo"], &[]);
    let mut plan = Plan::build(Catalog::Both, Some(Category::Ads), true);
    plan.run(&s);
    assert!(plan.dex_count("Lcom/facebook/ads/") > 0);
    // androidx is a framework descriptor: unregistered under an ads filter
    assert_eq!(plan.dex_count("Landroidx/"), 0);
    // and the unfiltered plan sees both
    let mut both = Plan::build(Catalog::Both, None, true);
    both.run(&s);
    assert!(both.dex_count("Landroidx/") > 0);
}
