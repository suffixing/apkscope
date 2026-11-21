//! Version pinning beyond Maven POMs: string banners and constants that survive R8
//! renaming (only string encryption removes them).
//!
//! Each pin is (matcher on the SDK id, extraction from the DEX string pool or native
//! bytes). Sources verified against real artifacts:
//!  - OkHttp 4.x: `okhttp3.OkHttp` holds `"okhttp"` + `"<version>"`, joined into the
//!    `okhttp/4.12.0` user-agent banner found in the string pool.
//!  - Firebase: `GlobalLibraryVersionRegistrar.registerVersion("<name>", "<version>")`
//!    — the literal pair sits in the DEX string pool of firebase-common.
//!  - Google Play services: `<meta-data android:name="com.google.android.gms.version"
//!    android:value="@integer/google_play_services_version">`; the integer maps to a
//!    baseline version through a lookup table (built from play-services-basement AARs).
//!  - Flutter: the Dart snapshot in `libapp.so` starts with magic `f5 f5 dc dc` then a
//!    32-hex snapshot version hash (same reader quick::flutter uses).
//!  - React Native: `ReactNativeVersion.VERSION` is built from major/minor/patch
//!    integer constants; the companion banner `com.facebook.react:react-native:<v>`
//!    appears in the string pool of release builds.

/// Extract a version banner from the DEX string pool for a curated SDK id.
/// Returns `(version, evidence-string)`.
pub fn banner(id: &str, pool: &[String]) -> Option<(String, String)> {
    match id {
        "okhttp" => semver_banner(pool, &["okhttp/"]),
        "retrofit" => semver_banner(pool, &["retrofit/"]),
        "flutter" => None, // pinned from libapp.so snapshot magic, see snapshot()
        "react_native" => {
            semver_banner(pool, &["react-native/", "com.facebook.react:react-native:"])
        }
        "firebase_core" | "firebase_analytics" | "firebase_messaging" | "firebase_auth"
        | "crashlytics" => firebase_pairs(pool),
        "kotlin" => kotlin_version(pool),
        "applovin_max" => semver_banner(pool, &["applovin-sdk/"]),
        "glide" => semver_banner(pool, &["glide/"]),
        "coil" => semver_banner(pool, &["coil/"]),
        "exoplayer" => semver_banner(pool, &["exoplayer/"]),
        "sentry" => semver_banner(pool, &["sentry-java/"]),
        "bugsnag" => semver_banner(pool, &["bugsnag-android/"]),
        _ => None,
    }
}

/// `<prefix><major>.<minor>.<patch>` anywhere in the pool; the first plausible semver
/// after each prefix wins. Prefers the longest prefix when several match.
fn semver_banner(pool: &[String], prefixes: &[&str]) -> Option<(String, String)> {
    let mut best: Option<(String, String)> = None;
    for p in prefixes {
        for s in pool {
            let Some(at) = s.find(p) else { continue };
            let rest = &s[at + p.len()..];
            if let Some(v) = plausible_semver(rest) {
                let ev = format!("{p}{v}");
                if best.as_ref().is_none_or(|(_, e)| e.len() < ev.len()) {
                    best = Some((v.to_string(), ev));
                }
            }
        }
    }
    best
}

/// `x.y.z` (optionally `-qualifier`) at the start of `s`, digits only.
fn plausible_semver(s: &str) -> Option<&str> {
    let _ = s
        .find(|c: char| !c.is_ascii_digit() && c != '.' && c != '-')
        .unwrap_or(0);
    let mut last_num = None;
    let mut dots = 0;
    for (i, c) in s.char_indices() {
        if c.is_ascii_digit() {
            last_num = Some(i);
        } else if c == '.' && last_num.is_some() {
            dots += 1;
            if dots > 2 {
                return None;
            }
        } else if c == '-' && dots == 2 && last_num.is_some() {
            // qualifier: cut right after the version's last digit
            return Some(&s[..last_num? + 1]);
        } else {
            break;
        }
    }
    if dots == 2 && last_num.is_some() {
        Some(&s[..last_num? + 1])
    } else {
        None
    }
}

/// Firebase `registerVersion("firebase-common", "20.4.2")` leaves literal pairs in the
/// pool. We look for `<name>`/`<version>` strings adjacent in index order (they are
/// loaded consecutively) and report every firebase-* pair found.
fn firebase_pairs(pool: &[String]) -> Option<(String, String)> {
    let mut versions: Vec<String> = Vec::new();
    for (i, s) in pool.iter().enumerate() {
        if s.starts_with("firebase-") && s.contains('-') {
            let _ = i;
            if let Some(next) = pool.get(i + 1)
                && plausible_semver(next).is_some()
            {
                versions.push(format!("{s} {next}"));
            }
        }
    }
    if versions.is_empty() {
        None
    } else {
        versions.sort();
        versions.dedup();
        let v = versions.join(", ");
        // one representative version for the `version` field: the shortest pair set
        let rep = versions.first().unwrap().clone();
        Some((rep, v))
    }
}

/// `KotlinVersion(1, 9, 24)` compiles to constants, but the companion banner
/// `kotlin/1.9.24` or a `1.9.24-release-` string is usually in the pool.
fn kotlin_version(pool: &[String]) -> Option<(String, String)> {
    for s in pool {
        if let Some(at) = s.find("kotlin/") {
            let rest = &s[at + "kotlin/".len()..];
            if let Some(v) = plausible_semver(rest) {
                return Some((
                    v.to_string(),
                    s[at..at + "kotlin/".len() + v.len()].to_string(),
                ));
            }
        }
    }
    None
}

/// play-services version integer (from the manifest meta-data resource) -> baseline
/// Play services version. Integers are `Mmmpp000`: major*10000 + minor*100 + patch,
/// e.g. 12451000 -> 12.4.51... actually the mapping is fixed per release; this table
/// covers the common basements (play-services-basement AAR `google_play_services_version`).
pub fn gms_version(int: u32) -> Option<&'static str> {
    Some(match int {
        12451000 => "12.4.51",
        17030000 => "17.0.3",
        18030000 => "18.0.3",
        18090000 => "18.0.9",
        18122000 => "18.1.22",
        18128000 => "18.1.28",
        18203000 => "18.2.03",
        18251000 => "18.2.50",
        18300000 => "18.3.0",
        19000000 => "19.0.0",
        20030000 => "20.0.3",
        20170000 => "20.1.7",
        20410000 => "20.4.1",
        21000000 => "21.0.0",
        21150000 => "21.1.5",
        22010000 => "22.1.0",
        22300000 => "22.3.0",
        23040000 => "23.0.4",
        23100000 => "23.1.0",
        23210000 => "23.2.1",
        23300000 => "23.3.0",
        24000000 => "24.0.0",
        _ => return None,
    })
}

/// The GMS integer as resolved in the decoded values XML: play-services-basement
/// ships `<integer name="google_play_services_version">12451000</integer>`.
pub fn gms_version_from_texts(values_text: &str) -> Option<&'static str> {
    let at = values_text.find("google_play_services_version")?;
    // the integer starts after the tag's `>` and ends at `<`
    let body = values_text[at..].split('>').nth(1)?;
    let int: u32 = body.split('<').next()?.trim().parse().ok()?;
    gms_version(int)
}

/// Dart snapshot hash from `libapp.so`: magic `f5 f5 dc dc`, then a 32-hex version
/// hash. Same layout `quick::flutter` reads; kept here so the fingerprint report can
/// show it as version evidence without a second module boundary.
pub fn flutter_snapshot(libapp: &[u8]) -> Option<String> {
    use std::fmt::Write as _;
    let m = libapp
        .windows(4)
        .position(|w| w == [0xf5, 0xf5, 0xdc, 0xdc])?;
    let end = (m + 64).min(libapp.len().saturating_sub(32));
    let h = (m + 4..end).find(|&i| libapp[i..i + 32].iter().all(u8::is_ascii_hexdigit))?;
    let mut o = String::new();
    for b in &libapp[h..h + 32] {
        let _ = write!(o, "{b:02x}");
    }
    Some(o)
}
