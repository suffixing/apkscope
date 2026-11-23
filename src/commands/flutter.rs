//! Flutter, scan, decrypt commands.

use crate::cli::{self, DecryptArgs, FlutterArgs, ScanArgs};
use crate::quick;
use crate::re;
use crate::session;

pub fn flutter(a: &FlutterArgs) -> Result<(), String> {
    cli::emit_list(&quick::flutter(&a.apk, a.abi.as_deref(), a.strings, a.api)?)
}

pub fn scan(a: &ScanArgs, deobf: bool) -> Result<(), String> {
    cli::run_big_stack(|| {
        cli::load(&a.apk, deobf).and_then(|st| {
            let lines = scan_lines(&re::scan(&st), a.filter.as_deref());
            cli::emit_list(&lines)
        })
    })
}

/// The scan report as lines for paging; with `filter`, only the findings that contain it
/// (case-insensitive), each section title kept above its first kept finding.
pub fn scan_lines(report: &str, filter: Option<&str>) -> Vec<String> {
    let Some(f) = filter.map(str::to_lowercase).filter(|f| !f.is_empty()) else {
        return report.lines().map(str::to_string).collect();
    };
    let mut out = Vec::new();
    let mut title: Option<&str> = None;
    for l in report.lines() {
        if l.starts_with("//") {
            title = Some(l);
        } else if l.to_lowercase().contains(&f) {
            if let Some(t) = title.take() {
                out.push(t.to_string());
            }
            out.push(l.to_string());
        }
    }
    out
}

pub fn decrypt(a: &DecryptArgs) -> Result<(), String> {
    cli::load(&a.apk, false).and_then(|st| {
        cli::emit_list(
            &re::decrypt_all(&st.dexes)
                .into_iter()
                .map(|(at, f, p)| format!("{at}  {f}  =>  {}", session::json_str(&p)))
                .collect::<Vec<_>>(),
        )
    })
}

#[cfg(test)]
#[path = "../../tests/apkscope/commands_scan.rs"]
mod tests;
