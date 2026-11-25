//! Known-SDK / framework / tracker fingerprinting.
//!
//! Detects third-party services (AdMob, React Native, Flutter, Firebase, Play Billing,
//! LVL, pairip, RevenueCat, ... plus the 428-tracker Exodus Privacy list) by stable
//! artifacts in the APK: DEX class-package prefixes, native-library names and their
//! `.dynsym` symbols, the binary AndroidManifest (permissions, components, meta-data
//! keys), asset / `res/raw` path patterns, magic bytes, Maven POMs, and version banners
//! in the DEX string pool.
//!
//! Confidence tiers account for R8/ProGuard obfuscation: package-prefix matches
//! downgrade when most matching classes are R8-renamed, and obfuscation-independent
//! signals (native libs, manifest, assets, ELF symbols, Maven) keep their strength.
//! Matches are never binary: `matched_classes` counts how many of the signature's
//! classes are actually present, so partially-shrunk libraries report as `partial`.
//!
//! Matching runs through [`scan`]: every catalog needle goes into one Aho-Corasick
//! automaton per corpus (class-name prefixes, class-name fragments, string-pool
//! hosts and version banners), and each corpus is streamed once — see that module
//! for why that replaced the per-signature linear scans, and what it keeps
//! byte-identical.
//!
//! Two sources are merged:
//!  - [`FINGERPRINTS`]: a hand-curated catalog with version pinning and multi-signal
//!    evidence (the `--exodus` off by default, `--all` merges both).
//!  - [`exodus::TRACKERS`]: the generated Exodus Privacy list (ODbL 1.0), matched with
//!    their exact semantics (unanchored dot-form signatures over slash-form names).
//!
//! `--snapshot` emits a stable content hash of the detected set for diffing two builds;
//! `--diff other.apk` reports added / removed / version-changed SDKs.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::io::Read as _;

use crate::cli;
use crate::elf;
use crate::session;

mod exodus;
mod pin;
mod scan;

// ─────────────────────────── catalog ───────────────────────────

/// Coarse grouping for the report and `--category` filter. Values double as the
/// `--category` filter names and the JSON `category` field.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Category {
    Ads,
    Analytics,
    Crash,
    Framework,
    Integrity,
    License,
    Monetization,
    Network,
    Push,
    Auth,
    Media,
    Storage,
    Di,
    Util,
    Obfuscator,
}

impl Category {
    pub fn as_str(self) -> &'static str {
        match self {
            Category::Ads => "ads",
            Category::Analytics => "analytics",
            Category::Crash => "crash",
            Category::Framework => "framework",
            Category::Integrity => "integrity",
            Category::License => "license",
            Category::Monetization => "monetization",
            Category::Network => "network",
            Category::Push => "push",
            Category::Auth => "auth",
            Category::Media => "media",
            Category::Storage => "storage",
            Category::Di => "di",
            Category::Util => "util",
            Category::Obfuscator => "obfuscator",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "ads" => Category::Ads,
            "analytics" => Category::Analytics,
            "crash" => Category::Crash,
            "framework" => Category::Framework,
            "integrity" => Category::Integrity,
            "license" => Category::License,
            "monetization" => Category::Monetization,
            "network" => Category::Network,
            "push" => Category::Push,
            "auth" => Category::Auth,
            "media" => Category::Media,
            "storage" => Category::Storage,
            "di" => Category::Di,
            "util" => Category::Util,
            "obfuscator" => Category::Obfuscator,
            _ => return None,
        })
    }
}

/// A known service entry. Every signal slice is `&'static` so the whole catalog is a
/// single `const FINGERPRINTS: &[Fingerprint]` with no allocations.
#[derive(Clone, Copy)]
pub struct Fingerprint {
    pub id: &'static str,
    pub category: Category,
    /// DEX class descriptors (`Lcom/google/android/gms/ads/`); prefix match.
    pub dex: &'static [&'static str],
    /// Native library path suffixes (`libreactnativejni.so`); substring match on the
    /// basename so `lib/arm64-v8a/<x>` and `lib/armeabi-v7a/<x>` both hit.
    pub native_libs: &'static [&'static str],
    /// Manifest `<meta-data android:name=...>` keys.
    pub manifest_meta: &'static [&'static str],
    /// Manifest `<activity android:name=...>` values.
    pub manifest_activities: &'static [&'static str],
    /// Manifest `<service android:name=...>` values.
    pub manifest_services: &'static [&'static str],
    /// Manifest `<uses-permission android:name=...>` values. Generic permissions
    /// (INTERNET) alone never confirm an SDK; they only corroborate.
    pub permissions: &'static [&'static str],
    /// Asset / `res/raw` path prefixes (`assets/flutter_assets/`).
    pub assets: &'static [&'static str],
    /// Hosts / URL substrings that, found in the DEX string pool or native strings,
    /// corroborate the SDK.
    pub urls: &'static [&'static str],
    /// Maven coordinates (`group:artifact`) looked up under
    /// `META-INF/maven/<group>/<artifact>/pom.properties` for version pinning.
    pub maven: &'static [&'static str],
}

impl Fingerprint {
    const fn empty() -> Self {
        Fingerprint {
            id: "",
            category: Category::Util,
            dex: &[],
            native_libs: &[],
            manifest_meta: &[],
            manifest_activities: &[],
            manifest_services: &[],
            permissions: &[],
            assets: &[],
            urls: &[],
            maven: &[],
        }
    }
}

// Hand-curated catalog, same convention as `re::scan`'s tables: a module-level `const`
// array, no external data file. Add an entry by appending one `Fingerprint { ... }`.
pub const FINGERPRINTS: &[Fingerprint] = &[
    // ── Ads ──────────────────────────────────────────────────────
    Fingerprint {
        id: "google_admob",
        category: Category::Ads,
        dex: &["Lcom/google/android/gms/ads/"],
        manifest_meta: &["com.google.android.gms.ads.APPLICATION_ID"],
        manifest_activities: &["com.google.android.gms.ads.AdActivity"],
        permissions: &["com.google.android.gms.permission.AD_ID"],
        urls: &[
            "pubads.g.doubleclick.net",
            "googleads.g.doubleclick.net",
            "pagead2.googlesyndication.com",
        ],
        maven: &["com.google.android.gms:play-services-ads"],
        ..Fingerprint::empty()
    },
    Fingerprint {
        id: "facebook_audience_network",
        category: Category::Ads,
        dex: &["Lcom/facebook/ads/"],
        manifest_activities: &["com.facebook.ads.AudienceNetworkActivity"],
        urls: &["an.facebook.com"],
        maven: &["com.facebook.android:audience-network-sdk"],
        ..Fingerprint::empty()
    },
    Fingerprint {
        id: "applovin_max",
        category: Category::Ads,
        dex: &["Lcom/applovin/"],
        manifest_activities: &[
            "com.applovin.adview.AppLovinInterstitialActivity",
            "com.applovin.adview.AppLovinConfirmationActivity",
        ],
        manifest_services: &["com.applovin.impl.sdk.AppLovinService"],
        maven: &["com.applovin:applovin-sdk"],
        ..Fingerprint::empty()
    },
    Fingerprint {
        id: "ironsource",
        category: Category::Ads,
        dex: &["Lcom/ironsource/"],
        maven: &["com.ironsource.sdk:mediationsdk"],
        ..Fingerprint::empty()
    },
    Fingerprint {
        id: "unity_ads",
        category: Category::Ads,
        dex: &["Lcom/unity3d/ads/"],
        maven: &["com.unity3d:unity-ads"],
        ..Fingerprint::empty()
    },
    Fingerprint {
        id: "mintegral",
        category: Category::Ads,
        dex: &["Lcom/mintegral/", "Lcom/mbridge/"],
        ..Fingerprint::empty()
    },
    Fingerprint {
        id: "vungle",
        category: Category::Ads,
        dex: &["Lcom/vungle/"],
        native_libs: &["libvungle.so"],
        ..Fingerprint::empty()
    },
    Fingerprint {
        id: "chartboost",
        category: Category::Ads,
        dex: &["Lcom/chartboost/"],
        ..Fingerprint::empty()
    },
    Fingerprint {
        id: "adcolony",
        category: Category::Ads,
        dex: &["Lcom/adcolony/"],
        native_libs: &["libadcolony.so"],
        ..Fingerprint::empty()
    },
    Fingerprint {
        id: "tapjoy",
        category: Category::Ads,
        dex: &["Lcom/tapjoy/"],
        ..Fingerprint::empty()
    },
    Fingerprint {
        id: "inmobi",
        category: Category::Ads,
        dex: &["Lcom/inmobi/"],
        ..Fingerprint::empty()
    },
    // ── Analytics / attribution ───────────────────────────────────
    Fingerprint {
        id: "google_analytics",
        category: Category::Analytics,
        dex: &["Lcom/google/android/gms/analytics/"],
        urls: &["www.google-analytics.com", "ssl.google-analytics.com"],
        maven: &["com.google.android.gms:play-services-analytics"],
        ..Fingerprint::empty()
    },
    Fingerprint {
        id: "firebase_analytics",
        category: Category::Analytics,
        dex: &[
            "Lcom/google/firebase/analytics/",
            "Lcom/google/android/gms/measurement/",
        ],
        manifest_meta: &[
            "firebase_data_collection_default_enabled",
            "firebase_analytics_collection_enabled",
        ],
        maven: &["com.google.firebase:firebase-analytics"],
        ..Fingerprint::empty()
    },
    Fingerprint {
        id: "mixpanel",
        category: Category::Analytics,
        dex: &["Lcom/mixpanel/android/"],
        urls: &["api.mixpanel.com", "decide.mixpanel.com"],
        maven: &["com.mixpanel.android:mixpanel-android"],
        ..Fingerprint::empty()
    },
    Fingerprint {
        id: "amplitude",
        category: Category::Analytics,
        dex: &["Lcom/amplitude/"],
        urls: &["api.amplitude.com", "api2.amplitude.com"],
        maven: &["com.amplitude:android-sdk"],
        ..Fingerprint::empty()
    },
    Fingerprint {
        id: "flurry",
        category: Category::Analytics,
        dex: &["Lcom/flurry/"],
        urls: &["data.flurry.com"],
        ..Fingerprint::empty()
    },
    Fingerprint {
        id: "segment",
        category: Category::Analytics,
        dex: &["Lcom/segment/analytics/"],
        urls: &["api.segment.io"],
        maven: &["com.segment.analytics.android:analytics"],
        ..Fingerprint::empty()
    },
    Fingerprint {
        id: "countly",
        category: Category::Analytics,
        dex: &["Lly/count/android/"],
        ..Fingerprint::empty()
    },
    Fingerprint {
        id: "matomo",
        category: Category::Analytics,
        dex: &["Lorg/matomo/sdk/"],
        ..Fingerprint::empty()
    },
    Fingerprint {
        id: "umeng_analytics",
        category: Category::Analytics,
        dex: &["Lcom/umeng/"],
        ..Fingerprint::empty()
    },
    Fingerprint {
        id: "adjust",
        category: Category::Analytics,
        dex: &["Lcom/adjust/sdk/"],
        manifest_meta: &["com.adjust.sdk.AppToken"],
        urls: &["app.adjust.net"],
        maven: &["com.adjust.sdk:adjust-android"],
        ..Fingerprint::empty()
    },
    Fingerprint {
        id: "appsflyer",
        category: Category::Analytics,
        dex: &["Lcom/appsflyer/"],
        manifest_meta: &["AF_APP_ID", "AF_DEV_KEY"],
        urls: &["appsflyer.com", "api.appsflyer.com"],
        maven: &["com.appsflyer:af-android-sdk"],
        ..Fingerprint::empty()
    },
    Fingerprint {
        id: "branch_io",
        category: Category::Analytics,
        dex: &["Lio/branch/referral/"],
        urls: &["api.branch.io"],
        maven: &["io.branch.sdk.android:library"],
        ..Fingerprint::empty()
    },
    Fingerprint {
        id: "kochava",
        category: Category::Analytics,
        dex: &["Lcom/kochava/base/"],
        ..Fingerprint::empty()
    },
    // ── Crash reporting ───────────────────────────────────────────
    Fingerprint {
        id: "bugsnag",
        category: Category::Crash,
        dex: &["Lcom/bugsnag/android/"],
        urls: &["notify.bugsnag.com", "sessions.bugsnag.com"],
        maven: &["com.bugsnag:bugsnag-android"],
        ..Fingerprint::empty()
    },
    Fingerprint {
        id: "sentry",
        category: Category::Crash,
        dex: &["Lio/sentry/android/"],
        urls: &["sentry.io"],
        maven: &["io.sentry:sentry-android"],
        ..Fingerprint::empty()
    },
    Fingerprint {
        id: "crashlytics",
        category: Category::Crash,
        dex: &["Lcom/crashlytics/", "Lcom/google/firebase/crashlytics/"],
        manifest_meta: &["io.fabric.ApiKey"],
        urls: &["e.crashlytics.com", "settings.crashlytics.com"],
        maven: &["com.google.firebase:firebase-crashlytics"],
        ..Fingerprint::empty()
    },
    // ── Frameworks ────────────────────────────────────────────────
    Fingerprint {
        id: "react_native",
        category: Category::Framework,
        dex: &["Lcom/facebook/react/"],
        native_libs: &["libreactnativejni.so", "libhermes.so", "libjsc.so"],
        assets: &["assets/index.android.bundle"],
        urls: &["react-native"],
        maven: &["com.facebook.react:react-native"],
        ..Fingerprint::empty()
    },
    Fingerprint {
        id: "flutter",
        category: Category::Framework,
        dex: &["Lio/flutter/"],
        native_libs: &["libflutter.so", "libapp.so"],
        assets: &["assets/flutter_assets/"],
        ..Fingerprint::empty()
    },
    Fingerprint {
        id: "unity",
        category: Category::Framework,
        dex: &["Lcom/unity3d/player/"],
        native_libs: &["libunity.so", "libmain.so", "libil2cpp.so"],
        assets: &["assets/bin/Data/"],
        urls: &["unity3d.com"],
        ..Fingerprint::empty()
    },
    Fingerprint {
        id: "cordova",
        category: Category::Framework,
        dex: &["Lorg/apache/cordova/"],
        assets: &["www/cordova.js", "assets/www/"],
        ..Fingerprint::empty()
    },
    Fingerprint {
        id: "ionic_capacitor",
        category: Category::Framework,
        dex: &["Lcom/getcapacitor/"],
        ..Fingerprint::empty()
    },
    Fingerprint {
        id: "nativescript",
        category: Category::Framework,
        dex: &["Lcom/tns/"],
        native_libs: &["libNativeScript.so"],
        ..Fingerprint::empty()
    },
    Fingerprint {
        id: "kotlin",
        category: Category::Framework,
        dex: &["Lkotlin/", "Lkotlinx/"],
        maven: &["org.jetbrains.kotlin:kotlin-stdlib"],
        ..Fingerprint::empty()
    },
    Fingerprint {
        id: "kotlin_coroutines",
        category: Category::Framework,
        dex: &["Lkotlinx/coroutines/"],
        maven: &["org.jetbrains.kotlinx:kotlinx-coroutines-android"],
        ..Fingerprint::empty()
    },
    Fingerprint {
        id: "androidx",
        category: Category::Framework,
        dex: &["Landroidx/"],
        maven: &["androidx.core:core-ktx"],
        ..Fingerprint::empty()
    },
    // ── Integrity / license / monetization ────────────────────────
    Fingerprint {
        id: "pairip",
        category: Category::Integrity,
        dex: &["Lcom/google/pairip/"],
        native_libs: &["libpairipcore.so", "libpairip.so"],
        ..Fingerprint::empty()
    },
    Fingerprint {
        id: "google_play_integrity",
        category: Category::Integrity,
        dex: &["Lcom/google/android/play/core/integrity/"],
        maven: &["com.google.android.play:integrity"],
        ..Fingerprint::empty()
    },
    Fingerprint {
        id: "google_safetynet",
        category: Category::Integrity,
        dex: &["Lcom/google/android/gms/safetynet/"],
        maven: &["com.google.android.gms:play-services-safetynet"],
        ..Fingerprint::empty()
    },
    Fingerprint {
        id: "google_play_billing",
        category: Category::Monetization,
        dex: &["Lcom/android/billingclient/api/"],
        permissions: &["com.android.vending.BILLING"],
        maven: &["com.android.billingclient:billing"],
        ..Fingerprint::empty()
    },
    Fingerprint {
        id: "google_play_licensing_lvl",
        category: Category::License,
        dex: &["Lcom/android/vending/licensing/"],
        permissions: &["com.android.vending.CHECK_LICENSE"],
        ..Fingerprint::empty()
    },
    Fingerprint {
        id: "revenuecat",
        category: Category::Monetization,
        dex: &["Lcom/revenuecat/purchases/"],
        manifest_meta: &["com.revenuecat.purchases.API_KEY"],
        urls: &["api.revenuecat.com"],
        maven: &["com.revenuecat.purchases:purchases"],
        ..Fingerprint::empty()
    },
    Fingerprint {
        id: "amazon_iap",
        category: Category::Monetization,
        dex: &["Lcom/amazon/device/iap/"],
        ..Fingerprint::empty()
    },
    Fingerprint {
        id: "stripe",
        category: Category::Monetization,
        dex: &["Lcom/stripe/android/"],
        urls: &["api.stripe.com"],
        maven: &["com.stripe:stripe-android"],
        ..Fingerprint::empty()
    },
    Fingerprint {
        id: "braintree",
        category: Category::Monetization,
        dex: &["Lcom/braintreepayments/api/"],
        urls: &["api.braintreegateway.com", "payments.braintree-api.com"],
        ..Fingerprint::empty()
    },
    Fingerprint {
        id: "adyen",
        category: Category::Monetization,
        dex: &["Lcom/adyen/"],
        ..Fingerprint::empty()
    },
    // ── Push ──────────────────────────────────────────────────────
    Fingerprint {
        id: "firebase_messaging",
        category: Category::Push,
        dex: &["Lcom/google/firebase/messaging/"],
        manifest_services: &["com.google.firebase.messaging.FirebaseMessagingService"],
        maven: &["com.google.firebase:firebase-messaging"],
        ..Fingerprint::empty()
    },
    Fingerprint {
        id: "onesignal",
        category: Category::Push,
        dex: &["Lcom/onesignal/"],
        manifest_meta: &["com.onesignal.AppId"],
        urls: &["api.onesignal.com"],
        maven: &["com.onesignal:OneSignal"],
        ..Fingerprint::empty()
    },
    Fingerprint {
        id: "urban_airship",
        category: Category::Push,
        dex: &["Lcom/urbanairship/"],
        ..Fingerprint::empty()
    },
    Fingerprint {
        id: "pusher",
        category: Category::Push,
        dex: &["Lcom/pusher/"],
        urls: &["api.pusher.com"],
        ..Fingerprint::empty()
    },
    // ── Auth ──────────────────────────────────────────────────────
    Fingerprint {
        id: "firebase_auth",
        category: Category::Auth,
        dex: &["Lcom/google/firebase/auth/"],
        maven: &["com.google.firebase:firebase-auth"],
        ..Fingerprint::empty()
    },
    Fingerprint {
        id: "google_signin",
        category: Category::Auth,
        dex: &["Lcom/google/android/gms/auth/api/signin/"],
        maven: &["com.google.android.gms:play-services-auth"],
        ..Fingerprint::empty()
    },
    Fingerprint {
        id: "facebook_login",
        category: Category::Auth,
        dex: &["Lcom/facebook/login/"],
        manifest_activities: &["com.facebook.FacebookActivity"],
        maven: &["com.facebook.android:facebook-login"],
        ..Fingerprint::empty()
    },
    Fingerprint {
        id: "auth0",
        category: Category::Auth,
        dex: &["Lcom/auth0/android/"],
        urls: &["auth0.com"],
        maven: &["com.auth0.android:auth0"],
        ..Fingerprint::empty()
    },
    Fingerprint {
        id: "okta",
        category: Category::Auth,
        dex: &["Lcom/okta/"],
        ..Fingerprint::empty()
    },
    // ── Firebase platform catch-all / GMS core ────────────────────
    Fingerprint {
        id: "firebase_core",
        category: Category::Framework,
        dex: &["Lcom/google/firebase/"],
        manifest_meta: &[
            "firebase_app_id",
            "google_app_id",
            "google_api_key",
            "google_crash_reporting_api_key",
        ],
        maven: &["com.google.firebase:firebase-core"],
        ..Fingerprint::empty()
    },
    Fingerprint {
        id: "google_play_services_core",
        category: Category::Framework,
        dex: &["Lcom/google/android/gms/common/"],
        manifest_meta: &["com.google.android.gms.version"],
        maven: &["com.google.android.gms:play-services-base"],
        ..Fingerprint::empty()
    },
    // ── Network / media / storage / util / DI ─────────────────────
    Fingerprint {
        id: "okhttp",
        category: Category::Network,
        dex: &["Lokhttp3/", "Lcom/squareup/okhttp/"],
        maven: &["com.squareup.okhttp3:okhttp"],
        ..Fingerprint::empty()
    },
    Fingerprint {
        id: "retrofit",
        category: Category::Network,
        dex: &["Lretrofit2/"],
        maven: &["com.squareup.retrofit2:retrofit"],
        ..Fingerprint::empty()
    },
    Fingerprint {
        id: "gson",
        category: Category::Util,
        dex: &["Lcom/google/gson/"],
        maven: &["com.google.code.gson:gson"],
        ..Fingerprint::empty()
    },
    Fingerprint {
        id: "moshi",
        category: Category::Util,
        dex: &["Lcom/squareup/moshi/"],
        maven: &["com.squareup.moshi:moshi"],
        ..Fingerprint::empty()
    },
    Fingerprint {
        id: "protobuf_javalite",
        category: Category::Util,
        dex: &["Lcom/google/protobuf/"],
        maven: &["com.google.protobuf:protobuf-javalite"],
        ..Fingerprint::empty()
    },
    Fingerprint {
        id: "exoplayer",
        category: Category::Media,
        dex: &["Lcom/google/android/exoplayer2/", "Landroidx/media3/"],
        maven: &[
            "com.google.android.exoplayer:exoplayer-core",
            "androidx.media3:media3-exoplayer",
        ],
        ..Fingerprint::empty()
    },
    Fingerprint {
        id: "glide",
        category: Category::Media,
        dex: &["Lcom/bumptech/glide/"],
        maven: &["com.github.bumptech.glide:glide"],
        ..Fingerprint::empty()
    },
    Fingerprint {
        id: "picasso",
        category: Category::Media,
        dex: &["Lcom/squareup/picasso/"],
        maven: &["com.squareup.picasso:picasso"],
        ..Fingerprint::empty()
    },
    Fingerprint {
        id: "coil",
        category: Category::Media,
        dex: &["Lcoil/"],
        maven: &["io.coil-kt:coil"],
        ..Fingerprint::empty()
    },
    Fingerprint {
        id: "fb_fresco",
        category: Category::Media,
        dex: &["Lcom/facebook/drawee/", "Lcom/facebook/imagepipeline/"],
        maven: &["com.facebook.fresco:fresco"],
        ..Fingerprint::empty()
    },
    Fingerprint {
        id: "realm_db",
        category: Category::Storage,
        dex: &["Lio/realm/"],
        native_libs: &["librealm-jni.so"],
        ..Fingerprint::empty()
    },
    Fingerprint {
        id: "room",
        category: Category::Storage,
        dex: &["Landroidx/room/"],
        maven: &["androidx.room:room-runtime"],
        ..Fingerprint::empty()
    },
    Fingerprint {
        id: "sqlcipher",
        category: Category::Storage,
        dex: &["Lnet/sqlcipher/"],
        native_libs: &["libsqlcipher.so"],
        ..Fingerprint::empty()
    },
    Fingerprint {
        id: "tink_crypto",
        category: Category::Util,
        dex: &["Lcom/google/crypto/tink/"],
        maven: &["com.google.crypto.tink:tink-android"],
        ..Fingerprint::empty()
    },
    Fingerprint {
        id: "hilt",
        category: Category::Di,
        dex: &["Ldagger/hilt/"],
        maven: &["com.google.dagger:hilt-android"],
        ..Fingerprint::empty()
    },
    Fingerprint {
        id: "dagger",
        category: Category::Di,
        dex: &["Ldagger/internal/", "Ldagger/producers/"],
        maven: &["com.google.dagger:dagger"],
        ..Fingerprint::empty()
    },
    Fingerprint {
        id: "koin",
        category: Category::Di,
        dex: &["Lorg/koin/"],
        maven: &["io.insert-koin:koin-android"],
        ..Fingerprint::empty()
    },
    Fingerprint {
        id: "lottie",
        category: Category::Media,
        dex: &["Lcom/airbnb/lottie/"],
        maven: &["com.airbnb.android:lottie"],
        ..Fingerprint::empty()
    },
    Fingerprint {
        id: "shimmer",
        category: Category::Util,
        dex: &["Lcom/facebook/shimmer/"],
        ..Fingerprint::empty()
    },
    // ── Obfuscators / packers (separate, high-signal) ─────────────
    Fingerprint {
        id: "dexguard",
        category: Category::Obfuscator,
        dex: &["Lcom/dexguard/"],
        ..Fingerprint::empty()
    },
    Fingerprint {
        id: "bangcle",
        category: Category::Obfuscator,
        dex: &["Lcom/bangcle/"],
        native_libs: &["libsecexe.so", "libsecmain.so"],
        ..Fingerprint::empty()
    },
    Fingerprint {
        id: "jiagu_360",
        category: Category::Obfuscator,
        dex: &["Lcom/qihoo/"],
        native_libs: &["libjiagu.so", "libjiagu_aion.so"],
        ..Fingerprint::empty()
    },
    Fingerprint {
        id: "appdome",
        category: Category::Obfuscator,
        dex: &["Lcom/appdome/"],
        native_libs: &["libFiberLib.so"],
        ..Fingerprint::empty()
    },
    Fingerprint {
        id: "promon_shield",
        category: Category::Obfuscator,
        dex: &["Lcom/nq/"],
        native_libs: &["libnskp.so", "libnqckpxx.so"],
        ..Fingerprint::empty()
    },
];

// ─────────────────────────── detection model ───────────────────────────

/// Where a detection came from; the report labels Exodus entries so the ODbL
/// attribution is visible in output.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum Origin {
    Curated,
    Exodus,
}

impl Origin {
    fn as_str(self) -> &'static str {
        match self {
            Origin::Curated => "curated",
            Origin::Exodus => "exodus",
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Confidence {
    /// Two or more independent signal kinds, or an exact version pin. R8 cannot
    /// produce this by accident.
    Confirmed,
    /// One obfuscation-independent signal (native lib, manifest entry, asset layout,
    /// ELF symbol, snapshot magic). Renaming cannot remove it, but it is single-source.
    Strong,
    /// Package names only, or string-pool hosts only. Corroborating, not conclusive.
    Weak,
}

impl Confidence {
    pub fn as_str(self) -> &'static str {
        match self {
            Confidence::Confirmed => "confirmed",
            Confidence::Strong => "strong",
            Confidence::Weak => "weak",
        }
    }

    fn rank(self) -> u8 {
        match self {
            Confidence::Confirmed => 0,
            Confidence::Strong => 1,
            Confidence::Weak => 2,
        }
    }
}

/// One piece of evidence for a detection.
#[derive(Clone, Debug)]
pub struct Evidence {
    /// "dex_package" | "native_lib" | "manifest_meta" | "activity" | "service" |
    /// "permission" | "asset" | "url" | "elf_symbol" | "maven" | "banner" | "snapshot"
    pub kind: &'static str,
    pub value: String,
    pub count: usize,
}

/// One matched service / tracker.
pub struct Detection {
    pub id: &'static str,
    pub category: Category,
    pub confidence: Confidence,
    pub version: Option<String>,
    pub evidence: Vec<Evidence>,
    pub origin: Origin,
    /// Exodus numeric id when `origin == Exodus`, for cross-referencing their reports
    pub exodus_id: Option<u32>,
}

// ─────────────────────────── signals ───────────────────────────

/// The opt-in DEX string pool as one scan buffer: every printable pool string
/// joined with `\n`, plus the offset where each string starts. Hosts and banners
/// are matched by streaming this buffer through one automaton pass — a search
/// per pool string cost one automaton reset per entry — and the pool costs one
/// allocation instead of a `String` per entry.
///
/// `\n` is the separator because it can appear in neither side: needles are
/// hostnames and banner prefixes, and the collector keeps printable ASCII pool
/// strings only. No automaton match can therefore straddle two strings, and a
/// match offset maps to exactly one pool index.
pub struct Pool {
    /// the joined pool strings, `\n` between them
    buf: String,
    /// byte offset of each pool string's first byte, ascending
    starts: Vec<u32>,
}

impl Pool {
    /// A pool from whole strings — the tests and the fixtures build one this way.
    #[cfg(test)]
    pub fn from_strs<S: AsRef<str>>(strs: &[S]) -> Pool {
        let mut buf = String::new();
        let mut starts = Vec::with_capacity(strs.len());
        for s in strs {
            starts.push(buf.len() as u32);
            buf.push_str(s.as_ref());
            buf.push('\n');
        }
        Pool { buf, starts }
    }

    fn is_empty(&self) -> bool {
        self.starts.is_empty()
    }

    /// Pool size in strings — the scan tests read it for their brute-force counts.
    #[cfg(test)]
    fn len(&self) -> usize {
        self.starts.len()
    }

    /// Pool string `i`, in pool order.
    fn str(&self, i: usize) -> &str {
        let start = self.starts[i] as usize;
        let end = self
            .starts
            .get(i + 1)
            .map_or(self.buf.len(), |&e| e as usize);
        // the separator is not part of the string
        &self.buf[start..end - 1]
    }

    fn get(&self, i: usize) -> Option<&str> {
        (i < self.starts.len()).then(|| self.str(i))
    }

    /// The pool string a buffer offset falls inside — the separator after string
    /// `i` still maps to `i`.
    fn index_of(&self, off: usize) -> usize {
        self.starts.partition_point(|&s| s as usize <= off) - 1
    }
}

/// Everything the matcher needs, collected once per APK. Built from a loaded
/// [`session::State`] so the CLI, the viewer and MCP share one path: DEX tables come
/// from `st.dexes`, the manifest from the decoded text in `st.texts`, zip entries from
/// `st.entries`, and native libraries through reopened handles on the APK.
pub struct Signals {
    /// slash-form class names (`com/facebook/react/ReactApplication`) across all DEX
    pub class_names: Vec<String>,
    /// declared permissions
    pub permissions: BTreeSet<String>,
    /// `<activity android:name=...>` values
    pub activities: BTreeSet<String>,
    /// `<service android:name=...>` values
    pub services: BTreeSet<String>,
    /// `<meta-data android:name=...>` keys
    pub meta_keys: BTreeSet<String>,
    /// native-library basenames (`libapp.so`) across ABIs
    pub native_libs: BTreeSet<String>,
    /// every library's `Java_...` JNI entrypoints, decoded once to the class they
    /// bind (slash form): the evidence rules read this map instead of re-decoding
    /// every symbol per fingerprint
    pub jni_targets: BTreeMap<String, String>,
    /// every zip entry path
    pub entries: Vec<String>,
    /// `group:artifact` -> version from `META-INF/maven/.../pom.properties`
    pub maven: BTreeMap<String, String>,
    /// whole-APK obfuscation ratio (R8-looking simple class names / all classes)
    pub obf_ratio: f64,
    /// opt-in DEX string pool (URLs, banners, version strings) as one scan buffer
    pub pool: Pool,
    /// Dart snapshot version hash from `libapp.so` (Flutter version pin; magic
    /// `f5 f5 dc dc` + 32 hex chars), when the app is a Flutter AOT build
    pub dart_snapshot: Option<String>,
    /// joined decoded `res/values*.xml` text, for resource-referenced integers
    /// (`@integer/google_play_services_version`)
    pub values_text: String,
}

impl Signals {
    /// Collect from a loaded session. `strings` also concatenates every DEX string-pool
    /// entry into one buffer for host/URL matching (the expensive part, opt-in).
    pub fn collect(st: &session::State, strings: bool) -> Signals {
        let mut class_names = Vec::new();
        let mut obf = 0usize;
        for (name, _dex, _idx) in &st.classes {
            // java name `a.b.C` -> slash form `a/b/C`
            let slash = name.replace('.', "/");
            let mut parts = slash.split('/').collect::<Vec<_>>();
            // strip inner-class `$` suffixes so `Foo$Bar` counts under `Foo`
            if let Some(last) = parts.last_mut()
                && let Some((outer, _)) = last.split_once('$')
            {
                *last = outer;
            }
            let simple = parts.last().copied().unwrap_or_default();
            if crate::deobf::obfuscated(simple) {
                obf += 1;
            }
            class_names.push(slash);
        }

        // manifest: parse the decoded text (session already decoded it)
        let mut permissions = BTreeSet::new();
        let mut activities = BTreeSet::new();
        let mut services = BTreeSet::new();
        let mut meta_keys = BTreeSet::new();
        if let Some(m) = st.texts().get("AndroidManifest.xml") {
            for e in m.split('<').skip(1) {
                let e = e.split('>').next().unwrap_or("");
                let tag = e.split_whitespace().next().unwrap_or("");
                let name = session::attr(e, "android:name");
                match tag {
                    "uses-permission" | "uses-permission-sdk-23" | "uses-permission-sdk-m" => {
                        if let Some(v) = name {
                            permissions.insert(v);
                        }
                    }
                    "activity" | "activity-alias" => {
                        if let Some(v) = name {
                            activities.insert(v);
                        }
                    }
                    "service" => {
                        if let Some(v) = name {
                            services.insert(v);
                        }
                    }
                    "meta-data" => {
                        if let Some(v) = name {
                            meta_keys.insert(v);
                        }
                    }
                    _ => {}
                }
            }
        }

        // native libraries: the basenames for evidence, and every library's JNI
        // entrypoints decoded once (instead of per fingerprint). The libraries
        // inflate on all cores — one zip handle per worker over a reopened input,
        // a shared work queue — because inflating every ABI's copy is the bulk of
        // the pass; the result is the same union of symbols the serial reads saw.
        let mut native_libs = BTreeSet::new();
        for (lib, _size) in st.native_libs() {
            let base = lib.rsplit('/').next().unwrap_or(&lib).to_string();
            native_libs.insert(base);
        }
        let jni_targets = jni_targets(st);

        // Flutter AOT: the Dart snapshot version hash in libapp.so (same reader as
        // quick::flutter; a build pin that survives everything)
        let dart_snapshot = st
            .native_libs()
            .iter()
            .find(|(n, _)| n.ends_with("/libapp.so"))
            .and_then(|(n, _)| st.read_entry(n))
            .and_then(|b| pin::flutter_snapshot(&b));

        // Maven pom.properties: exact versions when the build left them in
        let mut maven = BTreeMap::new();
        for p in &st.entries {
            let Some(rest) = p.strip_prefix("META-INF/maven/") else {
                continue;
            };
            let Some(trimmed) = rest.strip_suffix("/pom.properties") else {
                continue;
            };
            let Some((group_path, artifact)) = trimmed.rsplit_once('/') else {
                continue;
            };
            if let Some(bytes) = st.read_entry(p) {
                let text = String::from_utf8_lossy(&bytes);
                if let Some(v) = text.lines().find_map(|l| l.trim().strip_prefix("version=")) {
                    maven.insert(
                        format!("{}:{}", group_path.replace('/', "."), artifact),
                        v.trim().to_string(),
                    );
                }
            }
        }

        // DEX string pool (opt-in): one scan buffer for host/banner matching,
        // built once and shared by every signature. The raw MUTF-8 bytes are
        // checked for printability before any copy — the filter only passes
        // pure ASCII, where MUTF-8 is UTF-8, so the buffer holds exactly the
        // strings the decoded-per-entry version collected.
        let mut pool_buf: Vec<u8> = Vec::new();
        let mut pool_starts: Vec<u32> = Vec::new();
        if strings {
            for dx in st.dexes.iter() {
                for i in 0..dx.counts()[0] as u32 {
                    if let Ok(b) = dx.string_bytes(i)
                        && b.iter().all(|&c| (0x20..0x7f).contains(&c) || c == b'\t')
                    {
                        pool_starts.push(pool_buf.len() as u32);
                        pool_buf.extend_from_slice(b);
                        pool_buf.push(b'\n');
                    }
                }
            }
        }
        let pool = Pool {
            // every kept byte is printable ASCII: the validation cannot fail
            buf: String::from_utf8(pool_buf).expect("pool strings are printable ASCII"),
            starts: pool_starts,
        };
        // decoded values XML joined: resource integers (GMS version) live here
        let values_text = st
            .texts()
            .iter()
            .filter(|(p, _)| p.starts_with("res/values") && !p.contains('-'))
            .map(|(_, t)| t.as_str())
            .collect::<Vec<_>>()
            .join("\n");

        Signals {
            class_names,
            permissions,
            activities,
            services,
            meta_keys,
            native_libs,
            jni_targets,
            entries: st.entries.clone(),
            maven,
            obf_ratio: if st.classes.is_empty() {
                0.0
            } else {
                obf as f64 / st.classes.len() as f64
            },
            pool,
            dart_snapshot,
            values_text,
        }
    }

    /// Count classes under a curated `L.../` descriptor prefix, for partial-library
    /// evidence and obfuscation-aware downgrading. Superseded by [`scan::Plan`]'s
    /// automaton; kept under `#[cfg(test)]` as the brute-force oracle the scan
    /// tests compare every catalog needle against.
    #[cfg(test)]
    fn classes_under(&self, desc_prefix: &str) -> usize {
        let slash = desc_prefix
            .trim_start_matches('L')
            .trim_end_matches(';')
            .trim_end_matches('/');
        let needle = format!("{slash}/");
        self.class_names
            .iter()
            .filter(|c| c.starts_with(&needle))
            .count()
    }
}

/// Every native library's `Java_...` JNI entrypoints, decoded once to the Java
/// class they bind (slash form) and keyed by symbol: the evidence rule walks
/// this map per fingerprint instead of re-decoding every symbol each time.
///
/// The reads run on all cores: each worker holds its own zip handle over a
/// reopened input (the session's own handle stays untouched and unedited), and
/// the workers pull library paths from one shared queue, so a 500 MB lib set
/// inflates in parallel. Every library in every ABI is still read — the union
/// of symbols is exactly what the serial per-library walk collected — and a
/// map deduplicates the rest. When a second handle cannot be opened, the
/// serial path through [`session::State::read_entry`] takes over.
fn jni_targets(st: &session::State) -> BTreeMap<String, String> {
    fn decode(bytes: &[u8], out: &mut BTreeMap<String, String>) {
        for sym in elf::jni_symbols(bytes) {
            if let Some((cls, _method)) = elf::jni_target(&sym) {
                out.insert(sym, cls.replace('.', "/"));
            }
        }
    }
    let libs: Vec<String> = st.native_libs().into_iter().map(|(lib, _)| lib).collect();
    let threads = crate::search::threads().min(libs.len()).max(1);
    let inputs: Vec<crate::input::Input> = (0..threads).filter_map(|_| st.input().ok()).collect();
    if inputs.is_empty() {
        let mut out = BTreeMap::new();
        for lib in &libs {
            if let Some(bytes) = st.read_entry(lib) {
                decode(&bytes, &mut out);
            }
        }
        return out;
    }
    let next = std::sync::atomic::AtomicUsize::new(0);
    let mut out = BTreeMap::new();
    std::thread::scope(|s| {
        let next = &next;
        let libs = &libs;
        let mut handles = Vec::new();
        for input in inputs {
            let Ok(mut zip) = zip::ZipArchive::new(input) else {
                continue;
            };
            handles.push(s.spawn(move || {
                let mut local = BTreeMap::new();
                loop {
                    let k = next.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    let Some(lib) = libs.get(k) else {
                        break;
                    };
                    if let Ok(mut e) = zip.by_name(lib) {
                        let mut buf = Vec::with_capacity(e.size() as usize);
                        if e.read_to_end(&mut buf).is_ok() {
                            decode(&buf, &mut local);
                        }
                    }
                }
                local
            }));
        }
        // every handle failed to open: finish the queue serially
        if handles.is_empty() {
            for lib in libs {
                if let Some(bytes) = st.read_entry(lib) {
                    decode(&bytes, &mut out);
                }
            }
            return;
        }
        for h in handles {
            if let Ok(local) = h.join() {
                out.extend(local);
            }
        }
    });
    out
}

// ─────────────────────────── matcher ───────────────────────────

/// Kinds that survive renaming: an R8 pass can move a class out of its package only
/// by renaming the package itself, which breaks the whole app's own code too.
const STRONG_KINDS: &[&str] = &[
    "native_lib",
    "manifest_meta",
    "activity",
    "service",
    "asset",
    "magic",
    "maven",
    "elf_symbol",
    "snapshot",
    "banner",
];

/// Generic permissions that never confirm anything on their own.
const GENERIC_PERMS: &[&str] = &[
    "android.permission.INTERNET",
    "android.permission.ACCESS_NETWORK_STATE",
    "android.permission.WAKE_LOCK",
];

/// Match one curated catalog entry against the collected signals and the scan
/// pass's per-needle counts.
fn match_curated(fp: &Fingerprint, s: &Signals, plan: &scan::Plan) -> Option<Detection> {
    let mut ev = Vec::new();
    let mut matched_classes = 0usize;

    // 1. DEX package prefixes (descriptor form in the catalog)
    for p in fp.dex {
        let n = plan.dex_count(p) as usize;
        if n > 0 {
            ev.push(Evidence {
                kind: "dex_package",
                value: p.to_string(),
                count: n,
            });
            matched_classes += n;
        }
    }

    // 2. Native libs (substring match on basename)
    for want in fp.native_libs {
        let hits: Vec<&String> = s.native_libs.iter().filter(|n| n.contains(want)).collect();
        if !hits.is_empty() {
            ev.push(Evidence {
                kind: "native_lib",
                value: hits
                    .iter()
                    .map(|h| h.as_str())
                    .collect::<Vec<_>>()
                    .join(","),
                count: hits.len(),
            });
        }
    }

    // 3. Manifest meta-data keys, activities, services, permissions
    for k in fp.manifest_meta {
        if s.meta_keys.contains(*k) {
            ev.push(Evidence {
                kind: "manifest_meta",
                value: (*k).to_string(),
                count: 1,
            });
        }
    }
    for a in fp.manifest_activities {
        if s.activities.iter().any(|x| x.contains(a)) {
            ev.push(Evidence {
                kind: "activity",
                value: (*a).to_string(),
                count: 1,
            });
        }
    }
    for a in fp.manifest_services {
        if s.services.iter().any(|x| x.contains(a)) {
            ev.push(Evidence {
                kind: "service",
                value: (*a).to_string(),
                count: 1,
            });
        }
    }
    for p in fp.permissions {
        if s.permissions.contains(*p) {
            ev.push(Evidence {
                kind: "permission",
                value: (*p).to_string(),
                count: 1,
            });
        }
    }

    // 4. Asset / res path prefixes
    for a in fp.assets {
        let n = s.entries.iter().filter(|p| p.starts_with(a)).count();
        if n > 0 {
            ev.push(Evidence {
                kind: "asset",
                value: (*a).to_string(),
                count: n,
            });
        }
    }

    // 5. Hosts in the DEX string pool (opt-in scan)
    for u in fp.urls {
        let n = plan.host_count(u) as usize;
        if n > 0 {
            ev.push(Evidence {
                kind: "url",
                value: (*u).to_string(),
                count: n,
            });
        }
    }

    // 6. ELF exports whose JNI target class falls under a `dex` package: the
    // targets are decoded once per APK (`Signals::jni_targets`), so this is a
    // walk of the precomputed map, not a decode of every symbol per fingerprint
    for (sym, cls_slash) in &s.jni_targets {
        if fp
            .dex
            .iter()
            .any(|p| cls_slash.starts_with(scan::dex_root(p)))
        {
            ev.push(Evidence {
                kind: "elf_symbol",
                value: sym.clone(),
                count: 1,
            });
        }
    }

    // 7. Maven pom.properties version pinning
    let mut version = None;
    for coord in fp.maven {
        if let Some(v) = s.maven.get(*coord) {
            version = Some(v.clone());
            ev.push(Evidence {
                kind: "maven",
                value: (*coord).to_string(),
                count: 1,
            });
        }
    }

    // 8. Flutter: the Dart snapshot hash is the strongest version pin there is
    if fp.id == "flutter"
        && let Some(h) = &s.dart_snapshot
    {
        version = Some(h.clone());
        ev.push(Evidence {
            kind: "snapshot",
            value: h.clone(),
            count: 1,
        });
    }

    // 9. Google Play services: the manifest references
    // `@integer/google_play_services_version`; the resolved integer lives in the
    // decoded values XML (`res/values/values.xml`) and maps to a baseline version
    if fp.id == "google_play_services_core"
        && let Some(v) = pin::gms_version_from_texts(&s.values_text)
    {
        version = Some(v.to_string());
        ev.push(Evidence {
            kind: "banner",
            value: format!("google_play_services_version={v}"),
            count: 1,
        });
    }

    if ev.is_empty() {
        return None;
    }

    // 10. version pinning beyond Maven: banner strings in the DEX pool (okhttp/4.12.0,
    // firebase registerVersion pairs). `pin` owns the details.
    if version.is_none()
        && !s.pool.is_empty()
        && let Some(v) = pin::banner(fp.id, &s.pool, plan)
    {
        ev.push(Evidence {
            kind: "banner",
            value: v.1.clone(),
            count: 1,
        });
        version = Some(v.0);
    }

    let dex_ev = ev.iter().any(|e| e.kind == "dex_package");
    let strong_ev = ev.iter().any(|e| STRONG_KINDS.contains(&e.kind));
    let generic_only = ev
        .iter()
        .all(|e| e.kind != "permission" || GENERIC_PERMS.contains(&e.value.as_str()))
        && ev.iter().all(|e| e.kind == "permission" || e.kind == "url");

    let confidence = if (dex_ev && matched_classes >= 3) || (strong_ev && ev.len() >= 2) {
        Confidence::Confirmed
    } else if strong_ev || (dex_ev && matched_classes >= 1) {
        Confidence::Strong
    } else if generic_only {
        // a generic permission or a lone host string: corroborating only
        Confidence::Weak
    } else {
        Confidence::Weak
    };

    Some(Detection {
        id: fp.id,
        category: fp.category,
        confidence,
        version,
        evidence: ev,
        origin: Origin::Curated,
        exodus_id: None,
    })
}

/// Match one Exodus tracker. Their semantics: unanchored dot-form signature against
/// slash-form class names (the dot also matching `/`); we pre-converted alternatives
/// to slash form, so plain package paths count as class prefixes and class-name
/// fragments as substrings — one automaton pass either way, the split `scan` owns.
/// Network signatures corroborate via the DEX pool.
fn match_exodus(t: &exodus::ExodusTracker, s: &Signals, plan: &scan::Plan) -> Option<Detection> {
    let mut ev = Vec::new();
    let mut matched = 0usize;
    for alt in t.alts {
        // class-name fragments start uppercase (or the entry is flagged `scan`);
        // package paths count the classes under them
        let n = plan.exodus_alt_count(t.scan, alt) as usize;
        if n > 0 {
            ev.push(Evidence {
                kind: "dex_package",
                value: alt.to_string(),
                count: n,
            });
            matched += n;
        }
    }

    // network signature: unescape `\.`, then substring match against the string pool
    if !t.net.is_empty() && !s.pool.is_empty() {
        for alt in scan::net_hosts(t.net) {
            let n = plan.host_count(&alt) as usize;
            if n > 0 {
                ev.push(Evidence {
                    kind: "url",
                    value: alt,
                    count: n,
                });
            }
        }
    }

    if ev.is_empty() {
        return None;
    }

    // Exodus reports a tracker on one class hit; we keep our stricter tiers: several
    // classes confirm, one class or a host string alone is weak.
    let code_hit = ev.iter().any(|e| e.kind == "dex_package");
    let confidence = if matched >= 3 {
        Confidence::Confirmed
    } else if matched >= 1 && code_hit {
        Confidence::Strong
    } else {
        Confidence::Weak
    };

    Some(Detection {
        id: t.slug,
        category: t.cat,
        confidence,
        version: None,
        evidence: ev,
        origin: Origin::Exodus,
        exodus_id: Some(t.id),
    })
}

// ─────────────────────────── run + report ───────────────────────────

/// Which catalogs to match against.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Catalog {
    Curated,
    Exodus,
    Both,
}

/// One fingerprint pass over an APK: the detections plus the whole-APK context
/// the reports print alongside them.
pub struct Analysis {
    pub detections: Vec<Detection>,
    /// fraction of classes that look R8/ProGuard-renamed
    pub obf_ratio: f64,
    /// the APK path as loaded (after bundle/base.apk resolution)
    pub file: String,
}

/// The fingerprint pass: the detections plus the whole-APK context the reports print
/// alongside them. `confirmed` detections sort first, then `strong`, then `weak`; ties
/// broken by id.
pub fn analyze(
    st: &session::State,
    strings: bool,
    catalog: Catalog,
    category: Option<Category>,
) -> Analysis {
    let s = Signals::collect(st, strings);
    // one Aho-Corasick pass per corpus replaces the per-signature scans; every
    // count below reads from it
    let mut plan = scan::Plan::build(catalog, category, strings);
    plan.run(&s);
    let mut out = Vec::new();
    if matches!(catalog, Catalog::Curated | Catalog::Both) {
        for fp in FINGERPRINTS {
            if category.is_some_and(|c| fp.category != c) {
                continue;
            }
            if let Some(d) = match_curated(fp, &s, &plan) {
                out.push(d);
            }
        }
    }
    if matches!(catalog, Catalog::Exodus | Catalog::Both) {
        for t in exodus::TRACKERS {
            if category.is_some_and(|c| t.cat != c) {
                continue;
            }
            if let Some(d) = match_exodus(t, &s, &plan) {
                out.push(d);
            }
        }
    }
    // drop Exodus entries that a curated entry already covers (same package roots):
    // the curated entry carries version pinning and richer evidence. The two paths
    // store `dex_package` in different forms — curated as a Smali descriptor
    // (`Lcom/google/android/gms/ads/`), Exodus as a slash path (`com/google/android/gms/admob`)
    // — so the raw values never substring-match. Normalize both to a bare slash path
    // (strip a leading `L`, strip trailing `/`) and test on shared package roots:
    // identical, or one is an ancestor of the other up to a path boundary, or both
    // sit under the same parent package (curated `…/gms/ads` and exodus `…/gms/admob`
    // are the same SDK, siblings under `…/gms/`).
    if matches!(catalog, Catalog::Both) {
        let normalize = |v: &str| -> String {
            v.strip_prefix('L')
                .unwrap_or(v)
                .trim_end_matches('/')
                .to_string()
        };
        let parent_of =
            |p: &str| -> Option<String> { p.rsplit_once('/').map(|(head, _)| head.to_string()) };
        let curated_roots: Vec<String> = out
            .iter()
            .filter(|d| d.origin == Origin::Curated)
            .flat_map(|d| d.evidence.iter().filter(|e| e.kind == "dex_package"))
            .map(|e| normalize(&e.value))
            .collect();
        out.retain(|d| {
            if d.origin != Origin::Exodus {
                return true;
            }
            let roots: Vec<String> = d
                .evidence
                .iter()
                .filter(|e| e.kind == "dex_package")
                .map(|e| normalize(&e.value))
                .collect();
            !curated_roots.iter().any(|c| {
                roots.iter().any(|r| {
                    if c == r {
                        return true;
                    }
                    // one is an ancestor of the other, on a path boundary
                    let (longer, shorter) = if c.len() > r.len() {
                        (c.as_str(), r.as_str())
                    } else {
                        (r.as_str(), c.as_str())
                    };
                    if longer.starts_with(shorter) && longer[shorter.len()..].starts_with('/') {
                        return true;
                    }
                    // siblings sharing a parent package (curated `…/gms/ads`,
                    // exodus `…/gms/admob` → both under `…/gms`)
                    parent_of(c).is_some_and(|pc| parent_of(r) == Some(pc))
                })
            })
        });
    }
    out.sort_by(|a, b| {
        a.confidence
            .rank()
            .cmp(&b.confidence.rank())
            .then_with(|| a.id.cmp(b.id))
    });
    Analysis {
        obf_ratio: s.obf_ratio,
        file: st.file(),
        detections: out,
    }
}

/// Full report lines for the viewer's Tools menu (same text as the CLI report).
/// `strings` defaults on there: the viewer already paid for loading, and hosts are
/// the most useful evidence for a human reading the panel.
#[cfg(feature = "gui")]
pub fn report_lines(st: &session::State, strings: bool, catalog: Catalog) -> Vec<String> {
    let an = analyze(st, strings, catalog, None);
    text_report(&an, strings)
}

/// Evidence kinds in the order the report prints them: code first, then manifest,
/// then packaging, then corroborating strings.
const EVIDENCE_ORDER: &[&str] = &[
    "dex_package",
    "elf_symbol",
    "native_lib",
    "maven",
    "banner",
    "snapshot",
    "manifest_meta",
    "activity",
    "service",
    "permission",
    "asset",
    "url",
];

/// Human-readable text report: flat lines, blank-string section separators, the same
/// shape `quick::flutter` and `re::scan` use. Column widths assume `--list`'s layout:
/// a header row lines the columns up for scanning, evidence is grouped by kind with
/// repeated `elf_symbol` values collapsed into one counted line.
pub fn text_report(an: &Analysis, strings: bool) -> Vec<String> {
    let detections = &an.detections;
    let mut out = Vec::new();
    out.push(format!(
        "// Fingerprints of {} - {} known service{} matched",
        an.file,
        detections.len(),
        if detections.len() == 1 { "" } else { "s" }
    ));
    out.push(String::new());
    if detections.is_empty() {
        out.push("no known fingerprints matched".into());
        out.push(String::new());
    } else {
        out.push(format!(
            "  {:<26} {:<12} {:<10} {}",
            "SDK", "CATEGORY", "CONFIDENCE", "VERSION"
        ));
        // group by category: the report reads as a stack of like-for-like entries
        let mut by_cat: BTreeMap<&'static str, Vec<&Detection>> = BTreeMap::new();
        for d in detections {
            by_cat.entry(d.category.as_str()).or_default().push(d);
        }
        for (cat, list) in by_cat {
            out.push(format!("  // {cat} ({}):", list.len()));
            for d in list {
                out.push(format!(
                    "  {:<26} {:<12} {:<10} {}{}",
                    d.id,
                    d.category.as_str(),
                    d.confidence.as_str(),
                    d.version.as_deref().unwrap_or("-"),
                    if d.origin == Origin::Exodus {
                        "  [exodus]"
                    } else {
                        ""
                    }
                ));
                out.extend(evidence_lines(d));
            }
            out.push(String::new());
        }
        // trailing spaces never survive `{:<10}` padding of a short last column
        for line in &mut out {
            while line.ends_with(' ') {
                line.pop();
            }
        }
    }
    out.push(format!(
        "obfuscation: {} ({}% of classes look R8/ProGuard-renamed)",
        if an.obf_ratio > 0.5 {
            "heavy"
        } else if an.obf_ratio > 0.2 {
            "moderate"
        } else {
            "light"
        },
        (an.obf_ratio * 100.0) as u64
    ));
    if !strings {
        out.push(
            "strings: DEX string pool not scanned (pass --strings for URL/banner evidence)".into(),
        );
    }
    out
}

/// Evidence of one detection, printed in `EVIDENCE_ORDER` order (code first, then
/// manifest, then packaging, then corroborating strings). `elf_symbol` lines are
/// capped at 3 with a `(xN more, M unique)` tail — big media/camera SDKs export
/// dozens of JNI entrypoints and one hit is as good as ten for identification.
fn ordered_evidence(d: &Detection) -> Vec<Evidence> {
    let mut merged: Vec<Evidence> = Vec::new();
    for e in &d.evidence {
        match merged
            .iter_mut()
            .find(|m| m.kind == e.kind && m.value == e.value)
        {
            Some(m) => m.count += e.count,
            None => merged.push(e.clone()),
        }
    }
    merged.sort_by(|a, b| {
        let ka = EVIDENCE_ORDER
            .iter()
            .position(|k| *k == a.kind)
            .unwrap_or(EVIDENCE_ORDER.len());
        let kb = EVIDENCE_ORDER
            .iter()
            .position(|k| *k == b.kind)
            .unwrap_or(EVIDENCE_ORDER.len());
        ka.cmp(&kb).then_with(|| a.value.cmp(&b.value))
    });
    merged
}

/// Print evidence lines for one detection, `elf_symbol` capped at 3 lines.
fn evidence_lines(d: &Detection) -> Vec<String> {
    let ev = ordered_evidence(d);
    let one = |e: &Evidence| {
        format!(
            "      {:<13} {}{}",
            e.kind,
            e.value,
            if e.count > 1 {
                format!(" (x{})", e.count)
            } else {
                String::new()
            }
        )
    };
    let syms = ev.iter().filter(|e| e.kind == "elf_symbol").count();
    let extra = syms.saturating_sub(3);
    let mut out = Vec::new();
    let mut shown_syms = 0usize;
    for e in &ev {
        if e.kind == "elf_symbol" {
            if shown_syms >= 3 {
                continue;
            }
            out.push(one(e));
            shown_syms += 1;
            if shown_syms == 3 && extra > 0 {
                out.push(format!("      {:<13} x{extra} more JNI symbols", "..."));
            }
        } else {
            out.push(one(e));
        }
    }
    out
}

/// JSON report, hand-built the way `session::export` does (no serde derives).
/// One object: the whole-APK context plus every detection — `--json` feeds scripts,
/// so the text report's grouping and caps do not apply here.
pub fn json_report(an: &Analysis) -> String {
    let mut out = String::from("{\n");
    let _ = writeln!(out, "  \"file\": {},", session::json_str(&an.file));
    let _ = writeln!(out, "  \"count\": {},", an.detections.len());
    let _ = writeln!(
        out,
        "  \"obfuscation\": {},",
        session::json_str(if an.obf_ratio > 0.5 {
            "heavy"
        } else if an.obf_ratio > 0.2 {
            "moderate"
        } else {
            "light"
        })
    );
    let _ = writeln!(out, "  \"obfuscated_class_ratio\": {:.2},", an.obf_ratio);
    out.push_str("  \"sdks\": [");
    for (k, d) in an.detections.iter().enumerate() {
        if k > 0 {
            out.push_str(",\n");
        }
        out.push_str("    {");
        let _ = write!(out, "\"id\": {},", session::json_str(d.id));
        let _ = write!(
            out,
            "\"category\": {},",
            session::json_str(d.category.as_str())
        );
        let _ = write!(
            out,
            "\"confidence\": {},",
            session::json_str(d.confidence.as_str())
        );
        let _ = write!(out, "\"origin\": {},", session::json_str(d.origin.as_str()));
        if let Some(id) = d.exodus_id {
            let _ = write!(out, "\"exodus_id\": {id},");
        }
        if let Some(v) = &d.version {
            let _ = write!(out, "\"version\": {},", session::json_str(v));
        }
        out.push_str("\"evidence\": [");
        for (j, e) in d.evidence.iter().enumerate() {
            if j > 0 {
                out.push(',');
            }
            out.push('{');
            let _ = write!(out, "\"type\": {},", session::json_str(e.kind));
            let _ = write!(out, "\"value\": {},", session::json_str(&e.value));
            let _ = write!(out, "\"count\":{}", e.count);
            out.push('}');
        }
        out.push_str("]}");
    }
    if !an.detections.is_empty() {
        out.push('\n');
    }
    out.push_str("  ]\n}\n");
    out
}

// ─────────────────────────── snapshot + diff ───────────────────────────

/// Stable content hash of the detected set: sha256 over the canonical serialization
/// `id\tcategory\tversion?\n` of every **confirmed-or-strong** detection, sorted.
/// Weak matches are excluded on purpose — an R8 rename between two builds of the same
/// SDK set would otherwise churn the hash. Versions count only when pinned (Maven POM
/// or banner), so an unpinned build stays comparable.
pub fn snapshot(detections: &[Detection]) -> String {
    use sha2::Digest as _;
    let mut canon: Vec<String> = detections
        .iter()
        .filter(|d| d.confidence != Confidence::Weak)
        .map(|d| {
            format!(
                "{}\t{}\t{}",
                d.id,
                d.category.as_str(),
                d.version.as_deref().unwrap_or("-")
            )
        })
        .collect();
    canon.sort();
    canon.dedup();
    let mut buf = String::new();
    for line in &canon {
        let _ = writeln!(buf, "{line}");
    }
    let d = sha2::Sha256::digest(buf.as_bytes());
    d.iter().take(8).map(|b| format!("{b:02x}")).collect()
}
/// Diff two detection sets keyed by id: (added, removed, version-changed).
pub fn diff<'a>(
    a: &'a [Detection],
    b: &'a [Detection],
) -> (
    Vec<&'a Detection>,
    Vec<&'a Detection>,
    Vec<(&'a Detection, &'a Detection)>,
) {
    let key = |d: &Detection| (d.id, d.origin);
    let ma: BTreeMap<_, &Detection> = a.iter().map(|d| (key(d), d)).collect();
    let mb: BTreeMap<_, &Detection> = b.iter().map(|d| (key(d), d)).collect();
    let mut added = Vec::new();
    let mut removed = Vec::new();
    let mut changed = Vec::new();
    for (k, d) in &mb {
        match ma.get(k) {
            None => added.push(*d),
            Some(old) if old.version != d.version => changed.push((*old, *d)),
            _ => {}
        }
    }
    for (k, d) in &ma {
        if !mb.contains_key(k) {
            removed.push(*d);
        }
    }
    (added, removed, changed)
}

/// Text lines for a diff between this APK's detections and another's.
pub fn diff_report(this: &str, other: &str, a: &[Detection], b: &[Detection]) -> Vec<String> {
    let (added, removed, changed) = diff(a, b);
    let mut out = vec![format!("// fingerprint diff: {this} -> {other}")];
    if added.is_empty() && removed.is_empty() && changed.is_empty() {
        out.push("no changes in the detected SDK set".into());
        return out;
    }
    if !added.is_empty() {
        out.push(String::new());
        out.push(format!("added ({}):", added.len()));
        for d in added {
            out.push(format!("  + {} ({})", d.id, d.category.as_str()));
        }
    }
    if !removed.is_empty() {
        out.push(String::new());
        out.push(format!("removed ({}):", removed.len()));
        for d in removed {
            out.push(format!("  - {} ({})", d.id, d.category.as_str()));
        }
    }
    if !changed.is_empty() {
        out.push(String::new());
        out.push(format!("version changed ({}):", changed.len()));
        for (old, new) in changed {
            out.push(format!(
                "  ~ {}: {} -> {}",
                new.id,
                old.version.as_deref().unwrap_or("?"),
                new.version.as_deref().unwrap_or("?")
            ));
        }
    }
    out
}

// ─────────────────────────── CLI plumbing ───────────────────────────

/// `apkscope fingerprint <apk>` — reads the global `--json` / `-o` flags. `--list`
/// needs no APK, so the entry point takes the whole arg struct and validates here.
pub fn fingerprint(a: &crate::cli::FingerprintArgs) -> Result<(), String> {
    let catalog = match (a.exodus, a.all) {
        (true, _) => Catalog::Exodus,
        (false, true) => Catalog::Both,
        (false, false) => Catalog::Curated,
    };
    let category = a.category.as_deref().and_then(Category::parse);
    if let Some(c) = &a.category
        && category.is_none()
    {
        return Err(format!("unknown category '{}' (see fingerprint --list)", c));
    }
    if a.list {
        return if cli::out_opts().json {
            cli::emit(&json_catalog(catalog, category))
        } else {
            cli::emit_list(&list_catalog(catalog, category))
        };
    }
    let Some(apk) = a.apk.as_deref() else {
        return Err("fingerprint needs an APK (or --list to print the catalogs)".into());
    };
    let st = cli::load(apk, false)?;
    if let Some(other) = &a.diff {
        let st2 = cli::load(other, false)?;
        let a1 = analyze(&st, a.strings, catalog, category);
        let a2 = analyze(&st2, a.strings, catalog, category);
        if cli::out_opts().json {
            let mut o = json_diff(&a1.file, &a2.file, &a1.detections, &a2.detections);
            // splice the snapshots in before the closing brace: `o` ends with "]\n}\n"
            let snap = format!(
                ",\n  \"snapshot\": {{\"from\": {}, \"to\": {}}}",
                session::json_str(&snapshot(&a1.detections)),
                session::json_str(&snapshot(&a2.detections))
            );
            if let Some(pos) = o.trim_end().rfind('}') {
                o.insert_str(pos, &snap);
            }
            return cli::emit(&o);
        }
        let mut lines = diff_report(&a1.file, &a2.file, &a1.detections, &a2.detections);
        if a.snapshot {
            lines.push(String::new());
            lines.push(format!(
                "snapshot {} -> {}",
                snapshot(&a1.detections),
                snapshot(&a2.detections)
            ));
        }
        return cli::emit_list(&lines);
    }
    let an = analyze(&st, a.strings, catalog, category);
    if cli::out_opts().json {
        // `--snapshot --json`: the full report plus the snapshot, nothing dropped
        let mut o = json_report(&an);
        if a.snapshot {
            let splice = format!(
                ",\n  \"snapshot\": {}",
                session::json_str(&snapshot(&an.detections))
            );
            if let Some(pos) = o.trim_end().rfind('}') {
                o.insert_str(pos, &splice);
            }
        }
        return cli::emit(&o);
    }
    let mut lines = text_report(&an, a.strings);
    if a.snapshot {
        lines.push(String::new());
        lines.push(format!("snapshot: {}", snapshot(&an.detections)));
    }
    cli::emit_list(&lines)
}

fn json_diff(this: &str, other: &str, a: &[Detection], b: &[Detection]) -> String {
    let (added, removed, changed) = diff(a, b);
    let mut o = String::from("{\n");
    let _ = writeln!(o, "  \"from\": {},", session::json_str(this));
    let _ = writeln!(o, "  \"to\": {},", session::json_str(other));
    let one = |d: &Detection| {
        let mut s = format!(
            "{{\"id\": {},\"category\": {},\"confidence\": {}",
            session::json_str(d.id),
            session::json_str(d.category.as_str()),
            session::json_str(d.confidence.as_str())
        );
        if let Some(v) = &d.version {
            s.push_str(&format!(",\"version\": {}", session::json_str(v)));
        }
        s.push('}');
        s
    };
    o.push_str("  \"added\": [");
    o += &added.iter().map(|d| one(d)).collect::<Vec<_>>().join(", ");
    o.push_str("],\n  \"removed\": [");
    o += &removed
        .iter()
        .map(|d| one(d))
        .collect::<Vec<_>>()
        .join(", ");
    o.push_str("],\n  \"changed\": [");
    o += &changed
        .iter()
        .map(|(old, new)| {
            format!(
                "{{\"id\": {},\"from\": {},\"to\": {}}}",
                session::json_str(new.id),
                session::json_str(old.version.as_deref().unwrap_or("?")),
                session::json_str(new.version.as_deref().unwrap_or("?"))
            )
        })
        .collect::<Vec<_>>()
        .join(", ");
    o.push_str("]\n}\n");
    o
}

/// `apkscope fingerprint --list` — print the catalogs, no APK needed.
/// Honors `--all` / `--exodus` (which catalogs to list) and `--category`.
pub fn list_catalog(catalog: Catalog, category: Option<Category>) -> Vec<String> {
    let mut out = Vec::new();
    out.push(format!(
        "curated: {} fingerprints (ODbL applies to the Exodus list below)",
        FINGERPRINTS.len()
    ));
    let curated: Vec<&Fingerprint> = FINGERPRINTS
        .iter()
        .filter(|fp| category.is_none_or(|c| fp.category == c))
        .collect();
    list_rows(&curated, &mut out);
    if matches!(catalog, Catalog::Exodus | Catalog::Both) {
        let trackers: Vec<&exodus::ExodusTracker> = exodus::TRACKERS
            .iter()
            .filter(|t| category.is_none_or(|c| t.cat == c))
            .collect();
        out.push(String::new());
        out.push(format!(
            "exodus: {} trackers (c) Exodus Privacy contributors, ODbL 1.0, https://exodus-privacy.eu.org",
            trackers.len()
        ));
        list_rows_exodus(&trackers, &mut out);
    } else {
        out.push(String::new());
        out.push(format!(
            "exodus: {} trackers -- pass --all or --exodus to include (ODbL 1.0, https://exodus-privacy.eu.org)",
            exodus::TRACKERS.len()
        ));
        let mut ex_by_cat: BTreeMap<&'static str, usize> = BTreeMap::new();
        for t in exodus::TRACKERS {
            if category.is_none_or(|c| t.cat == c) {
                *ex_by_cat.entry(t.cat.as_str()).or_default() += 1;
            }
        }
        for (cat, n) in ex_by_cat {
            out.push(format!("  {cat}: {n}"));
        }
    }
    out
}

/// Rows of the `--list` table: one per entry, grouped by category, one blank line
/// between categories. Same layout for curated and Exodus entries so the columns line up.
fn list_rows(entries: &[&Fingerprint], out: &mut Vec<String>) {
    let mut by_cat: BTreeMap<&'static str, Vec<&Fingerprint>> = BTreeMap::new();
    for fp in entries {
        by_cat.entry(fp.category.as_str()).or_default().push(fp);
    }
    for (cat, list) in by_cat {
        out.push(format!("  {cat} ({}):", list.len()));
        for fp in list {
            out.push(format!("    {}", fp.id));
        }
    }
}

fn list_rows_exodus(trackers: &[&exodus::ExodusTracker], out: &mut Vec<String>) {
    let mut by_cat: BTreeMap<&'static str, Vec<&exodus::ExodusTracker>> = BTreeMap::new();
    for t in trackers {
        by_cat.entry(t.cat.as_str()).or_default().push(t);
    }
    for (cat, list) in by_cat {
        out.push(format!("  {cat} ({}):", list.len()));
        for t in list {
            out.push(format!("    {}", t.name));
        }
    }
}

/// JSON catalog listing for `--list --json`: the same rows with their signal counts
/// and Maven coordinates, grouped by origin. `emitted` limits long arrays.
pub fn json_catalog(catalog: Catalog, category: Option<Category>) -> String {
    let mut o = String::from("{\n");
    let _ = writeln!(
        o,
        "  \"counts\": {{\"curated\": {}, \"exodus\": {}}},",
        FINGERPRINTS
            .iter()
            .filter(|fp| category.is_none_or(|c| fp.category == c))
            .count(),
        exodus::TRACKERS
            .iter()
            .filter(|t| category.is_none_or(|c| t.cat == c))
            .count()
    );
    let curated: Vec<&Fingerprint> = FINGERPRINTS
        .iter()
        .filter(|fp| category.is_none_or(|c| fp.category == c))
        .collect();
    let _ = write!(o, "  \"curated\": [");
    for (k, fp) in curated.iter().enumerate() {
        if k > 0 {
            o.push(',');
        }
        o.push_str("\n    {");
        let _ = write!(o, "\"id\": {}", session::json_str(fp.id));
        let _ = write!(
            o,
            ",\"category\": {}",
            session::json_str(fp.category.as_str())
        );
        let _ = write!(
            o,
            ",\"signals\":{{\"dex\":{},\"native_libs\":{},\"manifest\":{},\"assets\":{},\"urls\":{},\"maven\":{}}}",
            fp.dex.len(),
            fp.native_libs.len(),
            fp.manifest_meta.len()
                + fp.manifest_activities.len()
                + fp.manifest_services.len()
                + fp.permissions.len(),
            fp.assets.len(),
            fp.urls.len(),
            fp.maven.len()
        );
        if !fp.maven.is_empty() {
            let m = fp
                .maven
                .iter()
                .map(|c| session::json_str(c))
                .collect::<Vec<_>>()
                .join(", ");
            let _ = write!(o, ",\"maven\":[{m}]");
        }
        o.push('}');
    }
    if !curated.is_empty() {
        o.push_str("\n  ");
    }
    o.push_str("],\n");
    if matches!(catalog, Catalog::Exodus | Catalog::Both) {
        let trackers: Vec<&exodus::ExodusTracker> = exodus::TRACKERS
            .iter()
            .filter(|t| category.is_none_or(|c| t.cat == c))
            .collect();
        let _ = write!(o, "  \"exodus\": [");
        for (k, t) in trackers.iter().enumerate() {
            if k > 0 {
                o.push(',');
            }
            o.push_str("\n    {");
            let _ = write!(
                o,
                "\"id\": {},\"name\": {},\"exodus_id\": {},\"category\": {}",
                session::json_str(t.slug),
                session::json_str(t.name),
                t.id,
                session::json_str(t.cat.as_str())
            );
            o.push('}');
        }
        if !trackers.is_empty() {
            o.push_str("\n  ");
        }
        o.push_str("],\n");
    }
    o.push_str("  \"exodus_license\": \"ODbL 1.0, (c) Exodus Privacy contributors, https://exodus-privacy.eu.org\"\n}\n");
    o
}

#[cfg(test)]
#[path = "../../tests/apkscope/fingerprint.rs"]
mod tests;
