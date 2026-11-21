#![recursion_limit = "256"]
mod cache;
mod cfg;
mod cli;
mod commands;
mod deobf;
mod dex;
mod elf;
mod export;
mod fingerprint;
#[cfg(feature = "gui")]
mod gui;
mod il2cpp;
mod imports;
mod index;
mod ir;
mod java;
mod live;
mod mcp;
mod opt;
mod proguard;
mod quick;
mod re;
mod session;
mod upgrade;

use std::process::ExitCode;

// Crate-root re-exports that other modules reach via `crate::…` (cfg, deobf, index, ir,
// java, quick, re, session, mcp all depend on these being at the root).
use apkscope_core::dex::render;
use apkscope_core::{bytecode, res, sign};
// `gui.rs` and the gui-gated half of `session.rs` (both compiled only in the
// viewer build) reach these through the crate root, as in the pre-clap layout.
#[cfg(feature = "gui")]
use apkscope_core::{apksign, arsc, axml, rebuild, smali};
use clap::Parser;
use cli::{flag, load, num, opt};
use commands::{refs_query, refs_text, search_args, search_on};

// returns freed memory to the OS, so big APKs don't keep loading-time peaks resident
#[global_allocator]
static ALLOC: mimalloc::MiMalloc = mimalloc::MiMalloc;

/// Printed when this build is asked for a window it cannot open. The static Linux build
/// (musl) is compiled without the viewer on purpose: a fully static binary cannot
/// dlopen() the desktop's X11/Wayland/GL libraries, so no window is possible there.
/// Spell the limitation out and point at the builds that ship the viewer.
#[cfg(not(feature = "gui"))]
mod gui {
    pub fn no_viewer_note() {
        eprintln!(
            "apkscope: no viewer in this build (compiled without the `gui` feature).\n\
             On Linux this is the static musl binary (apkscope_linux_musl_x86_64/aarch64),\n\
             for servers, containers and musl distros: a fully static binary cannot load\n\
             the desktop's X11/Wayland/GL libraries at runtime, so it cannot open a\n\
             window. The viewer ships in the Windows exe, the glibc Linux binaries\n\
             (apkscope_linux_x86_64/aarch64) and the .deb/AppImage packages; on macOS,\n\
             build from source with `cargo build --release`.\n\
             Every other command works - see `apkscope --help` for the list."
        );
    }

    pub fn run(_: Option<&str>, _: bool) -> Result<(), String> {
        no_viewer_note();
        Err("the viewer is not available in this build".into())
    }
}

/// Every file under `dir`, by its path from there with `/` between names.
/// Shared by `apkscope build` and the viewer's resource-rebuild flow.
fn read_tree(dir: &std::path::Path) -> Result<std::collections::BTreeMap<String, Vec<u8>>, String> {
    let mut files = std::collections::BTreeMap::new();
    let mut todo = vec![dir.to_path_buf()];
    while let Some(d) = todo.pop() {
        for e in std::fs::read_dir(&d).map_err(|e| format!("{}: {e}", d.display()))? {
            let path = e.map_err(|e| e.to_string())?.path();
            if path.is_dir() {
                todo.push(path);
                continue;
            }
            let rel = path.strip_prefix(dir).map_err(|e| e.to_string())?;
            let name = rel
                .components()
                .map(|c| c.as_os_str().to_string_lossy())
                .collect::<Vec<_>>()
                .join("/");
            files.insert(
                name,
                std::fs::read(&path).map_err(|e| format!("{}: {e}", path.display()))?,
            );
        }
    }
    Ok(files)
}

fn main() -> ExitCode {
    let parsed = cli::Cli::parse();
    let deobf = cli::apply_globals(&parsed);
    if parsed.version || parsed.revision {
        cli::print_version(parsed.revision);
        return ExitCode::SUCCESS;
    }
    commands::run(parsed.cmd, deobf)
}
