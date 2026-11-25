//! `apkscope fingerprint` — known-SDK / framework / tracker fingerprinting.
//!
//! Thin handler matching `commands/flutter.rs`: the whole `FingerprintArgs`
//! (the APK positional is optional, `--list` needs no file) goes to
//! `crate::fingerprint`, which owns validation, analysis and emission.

use crate::cli::FingerprintArgs;
use crate::fingerprint;

pub fn fingerprint_cmd(a: &FingerprintArgs) -> Result<(), String> {
    fingerprint::fingerprint(a)
}
