//! CLI definitions and shared output plumbing.
//!
//! Replaces the hand-rolled `flag()` / `opt()` / `num()` parser and the slice-shape
//! dispatch `match` that used to live in `main.rs`. Clap now owns argument parsing
//! (unknown-option rejection, `--help` / `--version`, typed numerics, the `--` separator);
//! the command handlers in `crate::commands` keep their original bodies and only change
//! how they receive arguments (typed struct fields instead of `opt(&mut args, …)`).
//!
//! Required positionals are modeled as `String` (clap enforces presence), so a missing
//! required argument is a parse error (exit 2) rather than a handler-side `Err` (exit 1).
//! Genuinely optional positionals stay `Option<String>`; variadic ones are `Vec<String>`.

use std::{
    fs::File,
    io::{BufWriter, Read, Write},
    process::ExitCode,
};

use clap::{Args, Parser, Subcommand};

use crate::dex;
use crate::session;

/// Global output options, set once from the command line.
pub struct Out {
    pub file: Option<String>,
    pub json: bool,
    pub limit: usize,
    pub offset: usize,
}

static OUT: std::sync::OnceLock<Out> = std::sync::OnceLock::new();

/// `-q`: progress and summary lines stay off stderr (see the `note!` macro).
pub static QUIET: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

pub fn quiet() -> bool {
    QUIET.load(std::sync::atomic::Ordering::Relaxed)
}

pub fn out_opts() -> &'static Out {
    OUT.get_or_init(|| Out {
        file: None,
        json: false,
        limit: usize::MAX,
        offset: 0,
    })
}

/// Write the result to `-o` or stdout.
pub fn emit(text: &str) -> Result<(), String> {
    emit_with(|w| w.write_all(text.as_bytes()))
}

/// Stream output into `-o` or stdout through one buffer.
pub fn emit_with(f: impl FnOnce(&mut dyn Write) -> std::io::Result<()>) -> Result<(), String> {
    let res = match &out_opts().file {
        Some(path) => File::create(path).and_then(|file| {
            let mut w = BufWriter::with_capacity(1 << 20, file);
            f(&mut w)?;
            w.flush()
        }),
        None => {
            let mut w = BufWriter::with_capacity(1 << 20, std::io::stdout().lock());
            f(&mut w).and_then(|_| w.flush())
        }
    };
    match res {
        // a closed pipe (`| head`) is not an error
        Err(e) if e.kind() == std::io::ErrorKind::BrokenPipe => Ok(()),
        r => r.map_err(|e| format!("{}: {e}", out_opts().file.as_deref().unwrap_or("stdout"))),
    }
}

/// Write each piece as `run` produces it (in order), instead of collecting everything first:
/// the reader gets the first lines while later DEX files are still being worked on.
pub fn emit_stream<T>(
    run: impl FnOnce(&mut dyn FnMut(Result<T, String>)) -> Result<(), String>,
    put: impl Fn(&mut dyn Write, T) -> std::io::Result<()>,
) -> Result<(), String> {
    let (mut io_err, mut piece_err, mut res) = (None, None, Ok(()));
    emit_with(|w| {
        res = run(&mut |t| match t {
            Ok(t) if io_err.is_none() => io_err = put(&mut *w, t).err(),
            Ok(_) => {}
            Err(e) => {
                piece_err.get_or_insert(e);
            }
        });
        io_err.take().map_or(Ok(()), Err)
    })?;
    res.and(piece_err.map_or(Ok(()), Err))
}

/// One item per line, or a JSON array with `--json`; `--offset`/`--limit` page through it.
pub fn emit_list(items: &[String]) -> Result<(), String> {
    let o = out_opts();
    let page = || items.iter().skip(o.offset).take(o.limit);
    let shown = page().count();
    if shown < items.len() {
        crate::note!("{shown} of {} shown (--offset/--limit)", items.len());
    }
    emit_with(|w| {
        if o.json {
            w.write_all(b"[")?;
            for (k, s) in page().enumerate() {
                if k > 0 {
                    w.write_all(b",")?;
                }
                w.write_all(session::json_str(s).as_bytes())?;
            }
            w.write_all(b"]\n")
        } else {
            for s in page() {
                w.write_all(s.as_bytes())?;
                w.write_all(b"\n")?;
            }
            Ok(())
        }
    })
}

/// Structuring recurses per nesting level; deep methods need more than Windows' 1 MB main stack.
pub fn run_big_stack(f: impl FnOnce() -> Result<(), String> + Send) -> Result<(), String> {
    std::thread::scope(|s| {
        std::thread::Builder::new()
            .stack_size(256 << 20)
            .spawn_scoped(s, f)
            .unwrap()
            .join()
            .unwrap()
    })
}

/// Full session; `--no-cache` keeps it from reading or writing the code cache.
pub fn load(apk: &str, deobf: bool) -> Result<session::State, String> {
    let st = session::load(apk, deobf)?;
    if !session::CACHE_WRITE.load(std::sync::atomic::Ordering::Relaxed) {
        st.drop_cache();
    }
    Ok(st)
}

/// Calls `f` with each root-level classes*.dex; stops early when `f` returns Ok(true).
pub fn for_each_dex(
    path: &str,
    mut f: impl FnMut(&str, &dex::Dex) -> Result<bool, String>,
) -> Result<(), String> {
    let file = File::open(path).map_err(|e| format!("{path}: {e}"))?;
    let mut zip = zip::ZipArchive::new(file).map_err(|e| format!("{path}: {e}"))?;
    let mut buf = Vec::new();
    for i in 0..zip.len() {
        let mut entry = zip.by_index(i).map_err(|e| e.to_string())?;
        let name = entry.name().map_err(|e| e.to_string())?.into_owned();
        // only root-level classes*.dex are loaded by Android
        if !(name.starts_with("classes") && name.ends_with(".dex") && !name.contains('/')) {
            continue;
        }
        buf.clear();
        entry
            .read_to_end(&mut buf)
            .map_err(|e| format!("{name}: {e}"))?;
        let dex = dex::Dex::parse(&buf).map_err(|e| format!("{name}: {e}"))?;
        if f(&name, &dex).map_err(|e| format!("{name}: {e}"))? {
            break;
        }
    }
    Ok(())
}

/// The hand-written usage block, kept for the fallback paths clap does not own:
/// an unrecognized subcommand and the no-viewer no-args case. `--help`/`--version`
/// and flag/arity errors are handled by clap itself (stdout, exit 0 for help).
pub fn usage() -> ExitCode {
    eprintln!("apkscope {} - Android APK decompiler, API recon and editor
Fast, stateless queries (parallel, no index, no cache) - built for scripts and AI agents:
  apkscope classes  <apk> [--prefix com.example] [--app-only] [--desc]
  apkscope methods  <apk> [--class com.example.Main] [--filter name]
  apkscope strings  <apk> [--filter text]
  apkscope refs     <apk> string|type|method|field|extends|impl <query>
                          [--class C] [--fuzzy-class] [--regex] [--ignore-case] [--java]
  apkscope decompile <apk> <Class>... [--method name] [--smali] [--full]
  apkscope manifest <apk>
  apkscope diff     <old.apk> <new.apk> [--strings]   added / removed classes, methods, permissions; changed constants
Indexed + cached (first run builds it, later runs reuse the disk cache):
  apkscope decompile <apk>                 every class, to stdout
  apkscope search <apk> <scope> [query] [--regex] [--case] [--app-only] [--all] [--context N] [--method]
                  [--format txt|csv|json]   scopes: code string usages class res urls http secrets api config
  apkscope info <apk>                      package, SDKs, permissions, exported components
  apkscope resource <apk> <res/path.xml>
  apkscope export <apk> <out-dir>          Gradle project
Reverse engineering (Class = a.b.C, member = a.b.C#field or a.b.C#method()):
  apkscope callers   <apk> <Class> [method]      who calls it
  apkscope callgraph <apk> <Class> [method] [--depth N]   callers + callee tree
  apkscope access    <apk> <Class> <field>       who reads / writes a field
  apkscope frida     <apk> <Class> [method]      Frida hook script (--live: event body for live sessions)
  apkscope dump      <apk|package> <out-dir>     run the app under Frida, save the DEX it unpacked and the
                                                 scripts it decrypted (--wait S, --scripts-for S, --attach, --device ID)
  apkscope il2cpp    <apk|xapk>... [--uses TEXT] [--method NAME]   Unity games: C# methods + addresses,
                                                 which method uses a string, strings/calls in a method
  apkscope flutter   <apk> [--abi NAME] [--api] [--strings]   Flutter apps: Dart snapshot version, native libs,
                                                 recovered Dart library tree; --api lists hosts/routes/model
                                                 fields; --strings dumps libapp.so strings
  apkscope scan      <apk>                       security quick-scan
  apkscope decrypt   <apk>                       run string decryptors on their constant arguments
  apkscope rename    <apk> <Class|member> <new>  saved in <apk>.apkscope.json (empty name removes it)
  apkscope comment   <apk> <Class|member> <text>
  apkscope map <apk> export <out.jobf|out.mapping|out.txt>  |  map <apk> import <file>   JADX / Enigma / ProGuard names
Editing: apkscope smali <apk> <Class>      editable smali of one class (edit, then build --smali)
         apkscope res <apk> <out-dir>      the manifest and res/ as editable files (edit, then build --res)
         apkscope build <in.apk> <out.apk> [--put name=file]... [--delete name]... [--manifest x.xml]
                  [--res dir] [--string name[@config]=value]... [--smali edited.smali]...
                  [--key k.pk8 --cert c.crt | --no-sign]   a .jar is never signed
         apkscope verify <apk>
Agents:  apkscope mcp                      MCP server over stdio (see README)
Other:   apkscope disasm <apk> [Class]     apkscope gui [apk]
         apkscope upgrade [--stable | --canary] [--check] [--version X.Y.Z]
                                                 replace this binary with the latest release
                                                 (stable, default) or the latest commit's
                                                 build (canary); --check only looks
Global options: --json  --limit N  --offset N  --threads N  -o/--out file  --no-deobf  --no-cache", crate::upgrade::identity().version);
    ExitCode::from(2)
}

/// Started by double-click: drop the console window Windows opened for this console program.
pub fn hide_console() {
    #[cfg(windows)]
    {
        unsafe extern "system" {
            fn FreeConsole() -> i32;
        }
        // safety: no arguments; only detaches this process from its console
        unsafe { FreeConsole() };
    }
}

// ─────────────── small arg helpers (used by the MCP tool-call parser) ───────────────
//
// The user-facing CLI is clap-driven now (see the model below). The MCP server, however,
// parses its own tool-call argument vectors with these three small helpers, so they stay.

/// Remove `--name` from `args`; true if it was there.
pub fn flag(args: &mut Vec<String>, name: &str) -> bool {
    let n = args.len();
    args.retain(|a| a != name);
    args.len() != n
}

/// Remove `--name value` from `args` and return the value.
pub fn opt(args: &mut Vec<String>, names: &[&str]) -> Result<Option<String>, String> {
    let Some(k) = args.iter().position(|a| names.contains(&a.as_str())) else {
        return Ok(None);
    };
    if k + 1 >= args.len() {
        return Err(format!("{} needs a value", names[0]));
    }
    args.remove(k);
    Ok(Some(args.remove(k)))
}

pub fn num(v: Option<String>, name: &str) -> Result<Option<usize>, String> {
    v.map(|v| v.parse().map_err(|_| format!("{name} needs a number")))
        .transpose()
}

// ───────────────────────────── clap model ─────────────────────────────

#[derive(Parser)]
#[command(
    name = "apkscope",
    disable_version_flag = true,
    about = "Android APK decompiler, xref engine and MCP server for AI agents",
    long_about = None,
    after_help = crate::examples::TOP,
)]
pub struct Cli {
    #[command(subcommand)]
    pub cmd: Option<Cmd>,

    /// emit JSON arrays where a command lists items
    #[arg(global = true, long)]
    pub json: bool,

    /// page: show at most N items
    #[arg(global = true, long, value_name = "N")]
    pub limit: Option<usize>,

    /// page: skip the first N items
    #[arg(global = true, long, value_name = "N")]
    pub offset: Option<usize>,

    /// analysis thread count
    #[arg(global = true, long = "threads", alias = "thread", value_name = "N")]
    pub threads: Option<usize>,

    /// write output to <file> instead of stdout (search has its own --out)
    #[arg(global = true, short = 'o', long = "out", value_name = "file")]
    pub out: Option<String>,

    /// keep the deobfuscator off
    #[arg(global = true, long)]
    pub no_deobf: bool,

    /// do not read or write the code cache
    #[arg(global = true, long)]
    pub no_cache: bool,

    /// no progress or summary lines on stderr (errors still print); for scripts and agents
    #[arg(global = true, short = 'q', long)]
    pub quiet: bool,

    /// print the version (with --json: version, channel and commit)
    #[arg(short = 'V', long)]
    pub version: bool,

    /// print the version with the build's channel and commit
    #[arg(long)]
    pub revision: bool,
}

/// `--version` / `--revision`. `apkscope upgrade` reads `--version --json` to check a
/// staged binary's identity, so that shape must not change.
pub fn print_version(revision: bool) {
    let me = crate::upgrade::identity();
    if revision {
        match (me.channel, me.commit) {
            (Some(c), sha) if sha.len() >= 6 => {
                println!("apkscope {}-{}-{}", me.version, c.name(), &sha[..6])
            }
            _ => println!("apkscope {}-dev", me.version),
        }
    } else if out_opts().json {
        println!(
            "{}",
            serde_json::json!({
                "version": me.version,
                "channel": me.channel.map(|c| c.name()).unwrap_or("dev"),
                "commit": me.commit,
            })
        );
    } else {
        println!("apkscope {}", me.version);
    }
}

#[derive(Subcommand)]
pub enum Cmd {
    /// list classes
    #[command(name = "classes", alias = "listclass", after_help = crate::examples::CLASSES)]
    Classes(ClassesArgs),
    /// list methods
    #[command(name = "methods", alias = "listmethod", after_help = crate::examples::METHODS)]
    Methods(MethodsArgs),
    /// list strings
    #[command(name = "strings", alias = "liststring", after_help = crate::examples::STRINGS)]
    Strings(StringsArgs),
    /// cross-references
    #[command(name = "refs", alias = "findrefs", after_help = crate::examples::REFS)]
    Refs(RefsArgs),
    /// decompile classes
    #[command(name = "decompile", alias = "getclass", after_help = crate::examples::DECOMPILE)]
    Decompile(DecompileArgs),
    /// print the AndroidManifest.xml
    #[command(name = "manifest", alias = "getmanifest")]
    Manifest(ManifestArgs),
    /// added / removed classes, methods, permissions
    #[command(name = "diff", after_help = crate::examples::DIFF)]
    Diff(DiffArgs),
    /// static final constants (int, long, String...) of classes, by name, package or value
    #[command(name = "consts", after_help = crate::examples::CONSTS)]
    Consts(ConstsArgs),
    /// methods whose body returns one constant, e.g. every message class's `uri()` id
    #[command(name = "returns", after_help = crate::examples::RETURNS)]
    Returns(ReturnsArgs),
    /// where the APK's size goes: biggest entries, native libs per ABI, duplicate files
    #[command(name = "size", after_help = crate::examples::SIZE)]
    Size(SizeArgs),
    /// who calls a class or method
    #[command(name = "callers", after_help = crate::examples::RECON)]
    Callers(ReconArgs),
    /// callers + callee tree
    #[command(name = "callgraph", after_help = crate::examples::CALLGRAPH)]
    Callgraph(CallgraphArgs),
    /// who reads / writes a field
    #[command(name = "access", after_help = crate::examples::RECON)]
    Access(ReconArgs),
    /// Frida hook script
    #[command(name = "frida", after_help = crate::examples::FRIDA)]
    Frida(FridaArgs),
    /// run under Frida, save unpacked DEX and decrypted scripts
    #[command(name = "dump")]
    Dump(DumpArgs),
    /// Unity games: C# methods + addresses
    #[command(name = "il2cpp")]
    Il2cpp(Il2cppArgs),
    /// Flutter apps: Dart snapshot, native libs, recovered tree
    #[command(name = "flutter")]
    Flutter(FlutterArgs),
    /// security quick-scan
    #[command(name = "scan")]
    Scan(ScanArgs),
    /// run string decryptors on their constant arguments
    #[command(name = "decrypt")]
    Decrypt(DecryptArgs),
    /// rename a class or member (saved in <apk>.apkscope.json)
    #[command(name = "rename", after_help = crate::examples::NOTE)]
    Rename(NoteArgs),
    /// comment on a class or member (saved in <apk>.apkscope.json)
    #[command(name = "comment", after_help = crate::examples::NOTE)]
    Comment(NoteArgs),
    /// JADX / Enigma / ProGuard name mapping
    #[command(name = "map")]
    Map(MapArgs),
    /// package, SDKs, permissions, exported components
    #[command(name = "info", after_help = crate::examples::INFO)]
    Info(InfoArgs),
    /// print a resource XML
    #[command(name = "resource", after_help = crate::examples::RESOURCE)]
    Resource(ResourceArgs),
    /// MCP server over stdio
    #[command(name = "mcp")]
    Mcp,
    /// internal: MCP worker for one input
    #[command(name = "worker")]
    Worker(WorkerArgs),
    /// disassemble bytecode
    #[command(name = "disasm", after_help = crate::examples::DISASM)]
    Disasm(DisasmArgs),
    /// editable smali of one class
    #[command(name = "smali", after_help = crate::examples::SMALI)]
    Smali(SmaliArgs),
    /// export a Gradle project
    #[command(name = "export", after_help = crate::examples::EXPORT)]
    Export(ExportArgs),
    /// the manifest and res/ as editable files
    #[command(name = "res", after_help = crate::examples::RES)]
    Res(ResArgs),
    /// indexed + cached search
    #[command(name = "search", after_help = crate::examples::SEARCH)]
    Search(SearchArgs),
    /// apply edits, zipalign, sign v2 + v3
    #[command(name = "build", after_help = crate::examples::BUILD)]
    Build(BuildArgs),
    /// verify a signature
    #[command(name = "verify", after_help = crate::examples::VERIFY)]
    Verify(VerifyArgs),
    /// native viewer
    #[command(name = "gui")]
    Gui(GuiArgs),
    /// replace this binary with the latest stable or canary build
    #[command(name = "upgrade")]
    Upgrade(UpgradeArgs),
    /// a file associated with apkscope (double-click), or an unrecognized subcommand
    #[command(external_subcommand)]
    External(Vec<String>),
}

#[derive(Args)]
pub struct ClassesArgs {
    pub apk: String,
    #[arg(long, value_name = "P")]
    pub prefix: Option<String>,
    #[arg(long = "app-only")]
    pub app_only: bool,
    #[arg(long)]
    pub desc: bool,
}

#[derive(Args)]
pub struct MethodsArgs {
    pub apk: String,
    #[arg(long, value_name = "C")]
    pub class: Option<String>,
    #[arg(long = "filter", short = 'f', value_name = "F")]
    pub filter: Option<String>,
}

#[derive(Args)]
pub struct StringsArgs {
    pub apk: String,
    #[arg(long = "filter", short = 'f', value_name = "F")]
    pub filter: Option<String>,
}

#[derive(Args)]
pub struct RefsArgs {
    pub apk: String,
    /// string, type, method, field, extends, impl
    pub kind: String,
    /// query (words joined)
    #[arg(num_args = 0..)]
    pub query: Vec<String>,
    #[arg(long, value_name = "C")]
    pub class: Option<String>,
    #[arg(long = "fuzzy-class")]
    pub fuzzy_class: bool,
    #[arg(long)]
    pub regex: bool,
    #[arg(long = "ignore-case")]
    pub ignore_case: bool,
    #[arg(long)]
    pub java: bool,
}

#[derive(Args)]
pub struct DecompileArgs {
    pub apk: String,
    /// class names (omitted = every class)
    #[arg(num_args = 0..)]
    pub names: Vec<String>,
    #[arg(long, value_name = "name")]
    pub method: Option<String>,
    #[arg(long)]
    pub smali: bool,
    #[arg(long)]
    pub full: bool,
    /// write each class to its own file in this folder (a.b.C.java / .smali) instead of stdout
    #[arg(long = "out-dir", value_name = "DIR")]
    pub out_dir: Option<String>,
    /// read more class names from this file, one per line
    #[arg(long = "classes-file", value_name = "FILE")]
    pub classes_file: Option<String>,
}

#[derive(Args)]
pub struct ConstsArgs {
    pub apk: String,
    /// classes or packages: a.b.C, a.b.* or a.b. (several allowed, or comma-separated);
    /// omitted = every class
    #[arg(num_args = 0.., value_name = "CLASS|PKG")]
    pub classes: Vec<String>,
    /// only constants with this value: a number (736131, 0xB3B83, -1) or a string
    #[arg(long, value_name = "V")]
    pub value: Option<String>,
    /// only constants whose name matches this regex (case-insensitive)
    #[arg(long, value_name = "REGEX")]
    pub name: Option<String>,
}

#[derive(Args)]
pub struct ReturnsArgs {
    pub apk: String,
    /// method name, e.g. uri (omitted = every method that returns a constant)
    pub method: Option<String>,
    /// only classes that extend / implement this class or interface (directly or not)
    #[arg(long = "impl", value_name = "TYPE")]
    pub r#impl: Option<String>,
    /// only these classes or packages: a.b.C, a.b.* (several allowed)
    #[arg(long = "in", value_name = "PKG")]
    pub r#in: Vec<String>,
    /// only methods returning this value: a number (736131, 0xB3B83) or a string
    #[arg(long, value_name = "V")]
    pub value: Option<String>,
}

#[derive(Args)]
pub struct SizeArgs {
    pub apk: String,
    /// how many of the biggest entries to list
    #[arg(long, value_name = "N", default_value_t = 25)]
    pub top: usize,
}

#[derive(Args)]
pub struct ManifestArgs {
    pub apk: String,
}

#[derive(Args)]
pub struct DiffArgs {
    pub old: String,
    #[arg(value_name = "new.apk")]
    pub new: String,
    #[arg(long = "strings")]
    pub strings: bool,
    /// leave out classes of known libraries (SDK churn), with their methods and constants
    #[arg(long = "app-only")]
    pub app_only: bool,
}

#[derive(Args)]
pub struct ReconArgs {
    pub apk: String,
    pub class: String,
    /// method (callers/callgraph) or field (access)
    pub member: Option<String>,
}

#[derive(Args)]
pub struct CallgraphArgs {
    pub apk: String,
    pub class: String,
    pub member: Option<String>,
    #[arg(long, value_name = "N", default_value_t = 3)]
    pub depth: usize,
}

#[derive(Args)]
pub struct FridaArgs {
    pub apk: String,
    pub class: String,
    pub member: Option<String>,
    #[arg(long = "live")]
    pub live: bool,
}

#[derive(Args)]
pub struct DumpArgs {
    pub app: String,
    #[arg(value_name = "out-dir")]
    pub out: String,
    #[arg(long = "attach")]
    pub attach: bool,
    #[arg(long = "device", short = 'D', value_name = "ID")]
    pub device: Option<String>,
    #[arg(long = "wait", value_name = "S", default_value_t = 15)]
    pub wait: u64,
    #[arg(long = "scripts-for", value_name = "S", default_value_t = 15)]
    pub scripts_for: u64,
}

#[derive(Args)]
pub struct Il2cppArgs {
    /// input APK / XAPK (one or more)
    #[arg(num_args = 0..)]
    pub inputs: Vec<String>,
    #[arg(long, value_name = "TEXT")]
    pub uses: Option<String>,
    #[arg(long, value_name = "NAME")]
    pub method: Option<String>,
}

#[derive(Args)]
pub struct FlutterArgs {
    pub apk: String,
    #[arg(long, value_name = "NAME")]
    pub abi: Option<String>,
    #[arg(long = "api")]
    pub api: bool,
    #[arg(long = "strings")]
    pub strings: bool,
}

#[derive(Args)]
pub struct ScanArgs {
    pub apk: String,
    /// keep only findings containing this text (case-insensitive), under their section titles
    #[arg(long, value_name = "TEXT")]
    pub filter: Option<String>,
}

#[derive(Args)]
pub struct DecryptArgs {
    pub apk: String,
}

#[derive(Args)]
pub struct NoteArgs {
    pub apk: String,
    /// Class or member (a.b.C, a.b.C#field, a.b.C#method())
    pub target: String,
    /// new name (rename) or comment text (words joined)
    #[arg(num_args = 0..)]
    pub text: Vec<String>,
}

#[derive(Args)]
pub struct MapArgs {
    pub apk: String,
    /// export | import
    pub dir: String,
    pub file: String,
}

#[derive(Args)]
pub struct InfoArgs {
    pub apk: String,
}

#[derive(Args)]
pub struct ResourceArgs {
    pub apk: String,
    #[arg(value_name = "res/path.xml")]
    pub res: String,
}

#[derive(Args)]
pub struct WorkerArgs {
    pub path: String,
}

#[derive(Args)]
pub struct DisasmArgs {
    pub apk: String,
    pub class: Option<String>,
}

#[derive(Args)]
pub struct SmaliArgs {
    pub apk: String,
    pub class: String,
}

#[derive(Args)]
pub struct ExportArgs {
    pub apk: String,
    #[arg(value_name = "out-dir")]
    pub out: String,
}

#[derive(Args)]
pub struct ResArgs {
    pub apk: String,
    #[arg(value_name = "out-dir")]
    pub out: String,
}

#[derive(Args)]
pub struct SearchArgs {
    pub apk: String,
    /// code string usages class res urls http secrets api config
    pub scope: String,
    /// query (words joined)
    #[arg(num_args = 0..)]
    pub query: Vec<String>,
    #[arg(long)]
    pub regex: bool,
    #[arg(long = "case")]
    pub case: bool,
    #[arg(long = "app-only")]
    pub app_only: bool,
    /// include library code in urls / http / secrets, which default to app code only
    #[arg(long)]
    pub all: bool,
    /// only these classes or packages: a.b.C, a.b.* (several allowed, or comma-separated)
    #[arg(long = "in", value_name = "PKG")]
    pub r#in: Vec<String>,
    /// only classes that extend / implement this class or interface (directly or not)
    #[arg(long = "impl", value_name = "TYPE")]
    pub r#impl: Option<String>,
    #[arg(long = "context", value_name = "N", default_value_t = 0)]
    pub context: usize,
    #[arg(long = "method")]
    pub method: bool,
    #[arg(long = "format", value_name = "txt|csv|json", default_value = "txt")]
    pub format: String,
    /// search writes to this file (separate from the global -o)
    #[arg(long = "out", short = 'o', value_name = "file")]
    pub out: Option<String>,
}

#[derive(Args)]
pub struct BuildArgs {
    pub input: String,
    #[arg(value_name = "out.apk")]
    pub output: String,
    #[arg(long = "put", value_name = "name=file")]
    pub put: Vec<String>,
    #[arg(long = "delete", value_name = "name")]
    pub delete: Vec<String>,
    #[arg(long = "no-sign")]
    pub no_sign: bool,
    #[arg(long = "res", value_name = "dir")]
    pub res: Option<String>,
    #[arg(long = "string", value_name = "name[@config]=value")]
    pub string: Vec<String>,
    #[arg(long = "smali", value_name = "file")]
    pub smali: Vec<String>,
    #[arg(long = "manifest", value_name = "xml")]
    pub manifest: Option<String>,
    #[arg(long = "key", value_name = "file")]
    pub key: Option<String>,
    #[arg(long = "cert", value_name = "file")]
    pub cert: Option<String>,
    /// sign with a key from this JKS or PKCS#12 keystore (.jks, .keystore, .p12, .pfx)
    #[arg(long = "ks", value_name = "file")]
    pub ks: Option<String>,
    /// keystore password: pass:TEXT, env:VAR or file:PATH (plain TEXT works too)
    #[arg(long = "ks-pass", value_name = "spec")]
    pub ks_pass: Option<String>,
    /// key password, same forms as --ks-pass (default: the keystore password)
    #[arg(long = "ks-key-pass", value_name = "spec")]
    pub ks_key_pass: Option<String>,
    /// which key of the keystore (default: the only one)
    #[arg(long = "ks-alias", value_name = "alias")]
    pub ks_alias: Option<String>,
}

#[derive(Args)]
pub struct VerifyArgs {
    pub apk: String,
}

#[derive(Args)]
pub struct UpgradeArgs {
    /// --stable | --canary, --check, --version X.Y.Z (parsed by the upgrader)
    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
    pub args: Vec<String>,
}

#[derive(Args)]
pub struct GuiArgs {
    pub apk: Option<String>,
}

/// Apply the global flags to process state. Returns `deobf`.
pub fn apply_globals(cli: &Cli) -> bool {
    let _ = OUT.set(Out {
        file: cli.out.clone(),
        json: cli.json,
        limit: cli.limit.unwrap_or(usize::MAX),
        offset: cli.offset.unwrap_or(0),
    });
    QUIET.store(cli.quiet, std::sync::atomic::Ordering::Relaxed);
    if cli.no_cache {
        session::CACHE_WRITE.store(false, std::sync::atomic::Ordering::Relaxed);
    }
    if let Some(n) = cli.threads {
        session::THREADS.store(n, std::sync::atomic::Ordering::Relaxed);
    }
    !cli.no_deobf
}

#[cfg(test)]
#[path = "../tests/apkscope/cli.rs"]
mod tests;
