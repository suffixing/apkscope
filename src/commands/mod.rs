//! Command dispatch.
//!
//! `run` takes the parsed `Cmd` (or `None` for the no-subcommand / file-association paths)
//! and routes it to the handler in the right `commands::<group>` module. Exit-code
//! mapping is unchanged from the original `main`: `Ok` → 0, command `Err` → 1
//! (`error: …` on stderr), and the `usage()` fallback → 2.

use std::process::ExitCode;

use crate::cli::Cmd;

// Re-exported to the crate root (see main.rs) so `mcp.rs` keeps using
// `crate::refs_query` / `crate::refs_text` / `crate::search_args` / `crate::search_on`
// unchanged while the CLI itself is clap-driven.
pub use query::{refs_query, refs_text};
pub use search::{search_args, search_on};

pub(super) fn finish(r: Result<(), String>) -> ExitCode {
    match r {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

pub fn run(cmd: Option<Cmd>, deobf: bool) -> ExitCode {
    match cmd {
        None => misc::no_command(deobf),
        Some(Cmd::External(a)) => misc::external(&a, deobf),
        Some(c) => finish(dispatch(c, deobf)),
    }
}

fn dispatch(cmd: Cmd, deobf: bool) -> Result<(), String> {
    use Cmd::*;
    match cmd {
        Classes(a) => query::classes(&a),
        Methods(a) => query::methods(&a),
        Strings(a) => query::strings(&a),
        Refs(a) => crate::cli::run_big_stack(|| query::refs(&a)),
        Decompile(a) => crate::cli::run_big_stack(|| query::decompile(&a, deobf)),
        Diff(a) => query::diff(&a),
        Manifest(a) => query::manifest(&a),
        Callers(a) => recon::callers(&a),
        Callgraph(a) => recon::callgraph(&a),
        Access(a) => recon::access(&a),
        Frida(a) => recon::frida(&a),
        Dump(a) => misc::dump(&a),
        Il2cpp(a) => il2cpp::il2cpp(&a),
        Flutter(a) => flutter::flutter(&a),
        Scan(a) => flutter::scan(&a, deobf),
        Fingerprint(a) => fingerprint::fingerprint_cmd(&a),
        Decrypt(a) => flutter::decrypt(&a),
        Rename(a) => edit::rename(&a),
        Comment(a) => edit::comment(&a),
        Map(a) => map::map(&a),
        Info(a) => search::info(&a, deobf),
        Resource(a) => search::resource(&a, deobf),
        Mcp => mcp::serve(),
        Worker(a) => mcp::worker(&a, deobf),
        Disasm(a) => misc::disasm(&a),
        Smali(a) => edit::smali(&a),
        Export(a) => misc::export_cmd(&a, deobf),
        Res(a) => edit::res(&a),
        Search(a) => crate::cli::run_big_stack(|| search::search(&a, deobf)),
        Build(a) => build::build(&a),
        Verify(a) => edit::verify(&a),
        Gui(a) => misc::gui_cmd(&a, deobf),
        Upgrade(a) => crate::upgrade::upgrade(a.args),
        External(_) => unreachable!("External is handled in run()"),
    }
}

mod build;
mod edit;
mod fingerprint;
mod flutter;
mod il2cpp;
mod map;
mod mcp;
mod misc;
mod query;
mod recon;
mod search;
