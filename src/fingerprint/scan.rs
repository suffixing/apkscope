//! Multi-pattern matching for the whole catalog: one Aho-Corasick pass per corpus
//! instead of a linear scan per signature.
//!
//! The matcher in `mod.rs` used to walk every class name (and, with `--strings`,
//! every DEX string-pool entry) once per signature: the Exodus list alone is 429
//! trackers with 587 code alternatives and ~800 host fragments, so a large APK
//! paid class-count x signature-count substring searches. This module inverts the
//! loop: all needles go into one automaton, each corpus is streamed through it
//! exactly once, and the matchers read per-needle hit counts.
//!
//! Two match modes, one per automaton:
//!
//! - [`Mode::Prefix`]: a class name *starts with* `needle + "/"` — the curated
//!   `Lcom/facebook/` descriptors and Exodus package paths. Anchored search (the
//!   match must begin at byte 0) that stops at the first transition miss, so a
//!   class name that shares no first byte with any needle costs one transition.
//! - [`Mode::Substring`]: a haystack *contains* the needle anywhere — Exodus
//!   class-name fragments (`LigatusManager`, `sizmek`) and the host strings.
//!
//! Counting is per *haystack*, not per occurrence: a pool string containing the
//! same host twice counts once, exactly like the `contains().filter().count()`
//! this replaces. Needles that opt in also record *which* haystacks hit (the
//! banner prefixes) — that is how `pin` extracts version banners from the
//! prefiltered strings instead of rescanning the pool.
//!
//! The pool corpus arrives as one joined buffer ([`super::Pool`]) rather than a
//! `String` per entry: the automaton runs one search over the whole buffer
//! instead of millions of short ones. The strings are joined with `\n`, a byte
//! no needle and no pool string contains (the collector keeps printable ASCII
//! only), so no match can straddle two strings and every match maps to exactly
//! one pool index through a binary search over the string starts.
//!
//! Automata are built per corpus: the pool automaton — the one whose corpus is
//! APK-sized, and whose ~900 needles are past prefilter territory (those need
//! under ~100 patterns) — is a dense DFA, whose constant-time transitions scan
//! about twice as fast as the NFA the default heuristic picks, for a few
//! milliseconds of build time. The class-name automatons keep the default NFA:
//! their corpora are a hundredth of the pool's, where the NFA's smaller table is
//! the better trade.
//!
//! Everything here is behavior-preserving: the counts feed the same evidence
//! rules, so reports (and `--hash` digests) are byte-identical to the
//! per-signature scans.

use std::collections::HashMap;

use aho_corasick::automaton::OverlappingState;
use aho_corasick::{AhoCorasick, AhoCorasickKind, Anchored, Input, MatchKind, StartKind};

use super::{Catalog, Category, FINGERPRINTS, Pool, Signals, exodus, pin};

/// How one automaton matches its needles against a haystack.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    /// haystack starts with `needle + "/"` (anchored, boundary-checked)
    Prefix,
    /// haystack contains `needle` anywhere
    Substring,
}

/// One registered needle.
struct Entry {
    /// haystacks that matched, counted once each
    count: u32,
    /// matching haystack indices in scan order — kept only for needles that
    /// asked for hit recording (the banner prefixes)
    record: bool,
    hits: Vec<usize>,
}

/// A set of needles over one automaton: register, build once, scan a corpus,
/// read counts. Needles are deduplicated — two catalogs describing the same
/// package path share a slot — and every consumer reads the count it would have
/// computed on its own.
struct MultiScan {
    ac: Option<AhoCorasick>,
    mode: Mode,
    /// needles in slot order — the automaton's pattern ids index `entries`
    /// directly, since patterns are added in the same order
    needles: Vec<Box<str>>,
    /// needle -> slot
    slots: HashMap<Box<str>, usize>,
    entries: Vec<Entry>,
}

impl MultiScan {
    fn new(mode: Mode) -> MultiScan {
        MultiScan {
            ac: None,
            mode,
            needles: Vec::new(),
            slots: HashMap::new(),
            entries: Vec::new(),
        }
    }

    /// Register one needle. `record` asks for the matching haystack indices to be
    /// kept (the banner pass; `false` keeps only the count).
    fn add(&mut self, needle: &str, record: bool) {
        if needle.is_empty() || self.slots.contains_key(needle) {
            return;
        }
        self.slots.insert(needle.into(), self.needles.len());
        self.needles.push(needle.into());
        self.entries.push(Entry {
            count: 0,
            record,
            hits: Vec::new(),
        });
    }

    /// Build the automaton over the registered needles. Pattern ids equal slots,
    /// so a match's pattern id indexes `entries` directly. The prefix automaton
    /// is built for anchored searches (they only ever start at byte 0).
    ///
    /// `dfa` builds a dense DFA: the per-byte transition is constant-time, which
    /// pays on the corpus-sized pool pass; the class-name corpora are small
    /// enough that the NFA's cheaper build and smaller table win there.
    fn finish(&mut self, dfa: bool) {
        if self.needles.is_empty() {
            self.ac = None;
            return;
        }
        let pats: Vec<&str> = self.needles.iter().map(|n| &**n).collect();
        let mut b = AhoCorasick::builder();
        b.match_kind(MatchKind::Standard);
        if dfa {
            b.kind(Some(AhoCorasickKind::DFA));
        }
        if self.mode == Mode::Prefix {
            b.start_kind(StartKind::Anchored);
        }
        let built = b.build(pats.as_slice()).expect("needle set builds");
        self.ac = Some(built);
    }

    fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Stream a corpus through the automaton, once per haystack. Overlapping
    /// matches are all reported (nested package roots, hosts inside hosts); each
    /// (needle, haystack) pair still counts once, through the `seen` marks.
    fn scan(&mut self, haystacks: &[String]) {
        let Some(ac) = self.ac.as_ref() else {
            return;
        };
        // one mark per needle, keyed by haystack generation: counts each
        // (needle, haystack) pair once even when a haystack matches a needle twice
        let mut seen: Vec<u32> = vec![0; self.entries.len()];
        let mut mark: u32 = 0;
        for (hi, h) in haystacks.iter().enumerate() {
            mark += 1;
            match self.mode {
                Mode::Prefix => {
                    // anchored: only matches starting at byte 0 are reported, and
                    // the search stops at the first transition miss; the overlapping
                    // state loop is the API for iterating every anchored match
                    let input = Input::new(h).anchored(Anchored::Yes);
                    let mut state = OverlappingState::start();
                    loop {
                        ac.try_find_overlapping(input.clone(), &mut state)
                            .expect("anchored overlapping search over class names");
                        let Some(m) = state.get_match() else {
                            break;
                        };
                        let slot = m.pattern().as_usize();
                        // boundary: the needle must be followed by `/` — a class
                        // *under* the package, not one equal to it or embedding it
                        if seen[slot] != mark && m.end() < h.len() && h.as_bytes()[m.end()] == b'/'
                        {
                            seen[slot] = mark;
                            let e = &mut self.entries[slot];
                            e.count += 1;
                            if e.record {
                                e.hits.push(hi);
                            }
                        }
                    }
                }
                Mode::Substring => {
                    for m in ac.find_overlapping_iter(h) {
                        let slot = m.pattern().as_usize();
                        if seen[slot] == mark {
                            continue;
                        }
                        seen[slot] = mark;
                        let e = &mut self.entries[slot];
                        e.count += 1;
                        if e.record {
                            e.hits.push(hi);
                        }
                    }
                }
            }
        }
    }

    /// Stream the joined string pool through the automaton in one pass. A match
    /// cannot cross a `\n` separator — no needle and no pool string contains
    /// one — so each match belongs to exactly one pool string. Offsets grow
    /// monotonically through the match stream, so the pool index each match maps
    /// to never goes backwards, and the per-(needle, string) counting holds with
    /// one last-seen mark per needle.
    fn scan_joined(&mut self, pool: &Pool) {
        let Some(ac) = self.ac.as_ref() else {
            return;
        };
        // u32::MAX is no pool index: a needle that has not hit anything yet
        // always differs from the current one
        let mut seen: Vec<u32> = vec![u32::MAX; self.entries.len()];
        for m in ac.find_overlapping_iter(pool.buf.as_bytes()) {
            let slot = m.pattern().as_usize();
            let idx = pool.index_of(m.start()) as u32;
            if seen[slot] == idx {
                continue;
            }
            seen[slot] = idx;
            let e = &mut self.entries[slot];
            e.count += 1;
            if e.record {
                e.hits.push(idx as usize);
            }
        }
    }

    /// Haystacks that matched `needle` (0 for unregistered needles — a catalog
    /// filtered by category registers only its live needles).
    fn count(&self, needle: &str) -> u32 {
        self.slots
            .get(needle)
            .map_or(0, |&slot| self.entries[slot].count)
    }

    /// The haystack indices that matched `needle`, in scan order.
    fn hit_indices(&self, needle: &str) -> &[usize] {
        self.slots
            .get(needle)
            .map_or(&[], |&slot| self.entries[slot].hits.as_slice())
    }
}

/// Is this Exodus alternative a class-name fragment (substring semantics) rather
/// than a package path (prefix semantics)? `scan` flags a tracker whose
/// alternatives include fragments; an uppercase first letter is the other tell.
/// One definition of the split, shared by registration and matching.
fn is_fragment(scan: bool, alt: &str) -> bool {
    scan || alt.chars().next().is_some_and(|c| c.is_uppercase())
}

/// A curated DEX descriptor (`Lcom/facebook/;`) as the bare slash-form root
/// (`com/facebook`) the prefix automaton and the matcher agree on. The same
/// chain `classes_under` used to apply inline.
pub(super) fn dex_root(desc: &str) -> &str {
    desc.trim_start_matches('L')
        .trim_end_matches(';')
        .trim_end_matches('/')
}

/// The Exodus network signature as plain host alternatives: `\.` unescaped,
/// split on `|`, and true regex fragments (short, `*`, `(`) skipped — the same
/// filter the matcher applies, in the one place both sides call.
pub(super) fn net_hosts(net: &str) -> Vec<String> {
    let host = net.replace("\\.", ".");
    host.split('|')
        .map(str::trim)
        .filter(|a| a.len() >= 4 && !a.contains('*') && !a.contains('('))
        .map(str::to_string)
        .collect()
}

/// The scan plan for one `analyze` call: which needles from which catalogs, in
/// which automata. Built from the catalog selection (`--exodus` / `--all`), the
/// `--category` filter and whether the DEX string pool was collected.
pub(super) struct Plan {
    /// curated dex roots + Exodus package paths, counted as class-name prefixes
    prefixes: MultiScan,
    /// Exodus class-name fragments, counted as substrings of class names
    fragments: MultiScan,
    /// hosts and banner prefixes over the DEX string pool; banner needles also
    /// record their hit indices
    pool: MultiScan,
}

impl Plan {
    /// Build the automata for the selected catalogs. `strings` mirrors
    /// `Signals::collect`'s flag: without it there is no pool corpus, so no pool
    /// needles are registered either.
    pub(super) fn build(catalog: Catalog, category: Option<Category>, strings: bool) -> Plan {
        let mut prefixes = MultiScan::new(Mode::Prefix);
        let mut fragments = MultiScan::new(Mode::Substring);
        let mut pool = MultiScan::new(Mode::Substring);
        if matches!(catalog, Catalog::Curated | Catalog::Both) {
            for fp in FINGERPRINTS {
                if category.is_some_and(|c| fp.category != c) {
                    continue;
                }
                for d in fp.dex {
                    prefixes.add(dex_root(d), false);
                }
                if strings {
                    for u in fp.urls {
                        pool.add(u, false);
                    }
                }
            }
            if strings {
                // banner prefixes record hits: `pin` reads exactly those pool strings
                for p in pin::BANNER_PREFIXES {
                    pool.add(p, true);
                }
            }
        }
        if matches!(catalog, Catalog::Exodus | Catalog::Both) {
            for t in exodus::TRACKERS {
                if category.is_some_and(|c| t.cat != c) {
                    continue;
                }
                for alt in t.alts {
                    if is_fragment(t.scan, alt) {
                        fragments.add(alt, false);
                    } else {
                        prefixes.add(alt, false);
                    }
                }
                if strings {
                    for host in net_hosts(t.net) {
                        pool.add(&host, false);
                    }
                }
            }
        }
        prefixes.finish(false);
        fragments.finish(false);
        pool.finish(true);
        Plan {
            prefixes,
            fragments,
            pool,
        }
    }

    /// Run the automata over a full signal set: the class-name corpus, then the
    /// DEX string pool when it was collected.
    pub(super) fn run(&mut self, s: &Signals) {
        self.scan_classes(&s.class_names);
        self.scan_haystack(&s.pool);
    }

    /// Stream the class names through the prefix automaton (and the fragment
    /// automaton when it has needles).
    pub(super) fn scan_classes(&mut self, class_names: &[String]) {
        self.prefixes.scan(class_names);
        if !self.fragments.is_empty() {
            self.fragments.scan(class_names);
        }
    }

    /// Stream the DEX string pool through the host/banner automaton: host counts
    /// and the banner prefixes' hit indices. `run` calls this; separate so the
    /// banner tests can drive it with just a pool.
    pub(super) fn scan_haystack(&mut self, pool: &Pool) {
        self.pool.scan_joined(pool);
    }

    /// Classes under a curated dex descriptor (`Lcom/facebook/`): the descriptor
    /// root's prefix count.
    pub(super) fn dex_count(&self, desc: &str) -> u32 {
        self.prefixes.count(dex_root(desc))
    }

    /// One Exodus alternative's match count: fragments count as substrings,
    /// package paths as prefixes — the split [`is_fragment`] defines.
    pub(super) fn exodus_alt_count(&self, scan: bool, alt: &str) -> u32 {
        if is_fragment(scan, alt) {
            self.fragments.count(alt)
        } else {
            self.prefixes.count(alt)
        }
    }

    /// DEX string-pool entries containing `host` (a curated URL or an Exodus
    /// net-signature alternative, as produced by [`net_hosts`]).
    pub(super) fn host_count(&self, host: &str) -> u32 {
        self.pool.count(host)
    }

    /// Pool indices whose string contains a banner prefix, in pool order — the
    /// prefiltered corpus `pin` extracts versions from.
    pub(super) fn banner_hits(&self, prefix: &str) -> &[usize] {
        self.pool.hit_indices(prefix)
    }
}

#[cfg(test)]
#[path = "../../tests/apkscope/fingerprint_scan.rs"]
mod tests;
