//! Live Frida: runs the `frida` CLI against an app with one generated script. Hooks are added
//! and removed by rewriting that script (frida reloads a changed `-l` file by itself); every
//! hook reports JSON events on stdout, which land in a ring buffer the MCP tools and the viewer
//! read from.

use std::collections::{BTreeMap, VecDeque};
use std::io::{BufRead, BufReader};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde_json::{Value, json};

/// events kept; older ones drop off
const KEEP: usize = 20_000;

/// Helpers every script starts with: `__s` stringifies any value safely, `__ev` reports an event.
const PRELUDE: &str = r#"const __s = v => { try { const t = v === null || v === undefined ? String(v) : v.$className ? `${v.$className}: ${v}` : String(v); return t.length > 500 ? t.slice(0, 500) + "..." : t; } catch (e) { return "<?>"; } };
function __ev(k, m, v) { console.log("\u0001" + JSON.stringify({ k, m, v, tid: Process.getCurrentThreadId(), ts: Date.now() })); }
"#;

#[derive(Default)]
pub struct Events {
    /// sequence number of the next event
    pub next: u64,
    pub list: VecDeque<Value>,
}

impl Events {
    fn push(&mut self, mut e: Value) {
        e["seq"] = json!(self.next);
        self.next += 1;
        if self.list.len() == KEEP {
            self.list.pop_front();
        }
        self.list.push_back(e);
    }
}

pub struct Live {
    child: Child,
    path: PathBuf,
    pub target: String,
    /// key -> (Java hook body, or raw script when `raw`)
    hooks: BTreeMap<String, (String, bool)>,
    pub events: Arc<Mutex<Events>>,
}

impl Drop for Live {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = std::fs::remove_file(&self.path);
    }
}

impl Live {
    /// Spawn (or with `attach`, attach to) `target`, an app id; `device` is a frida device id,
    /// "local" for a process on this machine (testing), or None for USB. Waits until the script
    /// loaded or frida gave up.
    pub fn start(target: &str, attach: bool, device: Option<&str>) -> Result<Live, String> {
        let path = std::env::temp_dir().join(format!("apkscope-live-{}.js", std::process::id()));
        std::fs::write(&path, script(&BTreeMap::new())).map_err(|e| e.to_string())?;
        let mut cmd = Command::new("frida");
        // frida is Python: unbuffered, or piped events arrive in late batches
        cmd.env("PYTHONUNBUFFERED", "1");
        match device {
            Some("local") => {}
            Some(d) => _ = cmd.args(["-D", d]),
            None => _ = cmd.arg("-U"),
        }
        // -N attaches to an app by identifier; a local process only has a name
        cmd.arg(match (attach, device) {
            (false, _) => "-f",
            (true, Some("local")) => "-n",
            (true, _) => "-N",
        });
        cmd.arg(target).args(["-q", "-t", "inf", "-l"]).arg(&path).stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped());
        let child = cmd.spawn().map_err(|e| format!("cannot run frida ({e}); install it with: pip install frida-tools"))?;
        let mut live = Live { child, path, target: target.into(), hooks: BTreeMap::new(), events: Default::default() };
        for (pipe, is_err) in [(live.child.stdout.take().map(|p| Box::new(p) as Box<dyn std::io::Read + Send>), false), (live.child.stderr.take().map(|p| Box::new(p) as Box<dyn std::io::Read + Send>), true)] {
            let Some(pipe) = pipe else { continue };
            let ev = live.events.clone();
            std::thread::spawn(move || {
                for line in BufReader::new(pipe).lines().map_while(Result::ok) {
                    ev.lock().unwrap().push(parse(&line, is_err));
                }
            });
        }
        let t = Instant::now();
        while t.elapsed() < Duration::from_secs(15) {
            if let Ok(Some(st)) = live.child.try_wait() {
                std::thread::sleep(Duration::from_millis(100));
                return Err(explain(format!("frida exited ({st}):\n{}", live.text(0, "", 50).0)));
            }
            if live.events.lock().unwrap().list.iter().any(|e| e["k"] == "loaded") {
                return Ok(live);
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        Err(format!("frida did not load the script within 15 s:\n{}", live.text(0, "", 50).0))
    }

    pub fn alive(&mut self) -> bool {
        matches!(self.child.try_wait(), Ok(None))
    }

    pub fn hook_keys(&self) -> Vec<String> {
        self.hooks.keys().cloned().collect()
    }

    /// Add or replace a hook: `java` is a body from `re::frida(.., live = true)`, run inside
    /// `Java.perform`; `raw` scripts run as they are.
    pub fn hook(&mut self, key: &str, js: &str, raw: bool) -> Result<(), String> {
        self.hooks.insert(key.into(), (js.into(), raw));
        self.write()
    }

    /// Remove hooks whose key is `key` or starts with `key#` ("*" removes all); how many went.
    pub fn unhook(&mut self, key: &str) -> Result<usize, String> {
        let n = self.hooks.len();
        self.hooks.retain(|k, _| !(key == "*" || k == key || k.starts_with(&format!("{key}#"))));
        self.write()?;
        Ok(n - self.hooks.len())
    }

    fn write(&self) -> Result<(), String> {
        std::fs::write(&self.path, script(&self.hooks)).map_err(|e| e.to_string())
    }

    /// Events from `since` on matching `filter` (substring of method or value), at most `limit`
    /// newest, as one line each; also the next `since` to pass.
    pub fn text(&self, since: u64, filter: &str, limit: usize) -> (String, u64) {
        let ev = self.events.lock().unwrap();
        let hits: Vec<&Value> = ev.list.iter().filter(|e| e["seq"].as_u64() >= Some(since) && matches(e, filter)).collect();
        let mut o = String::new();
        for e in &hits[hits.len().saturating_sub(limit)..] {
            o += &line(e);
            o.push('\n');
        }
        (o, ev.next)
    }

    /// Calls, returns and throws per method since `since`, busiest first.
    pub fn summary(&self, since: u64) -> String {
        let mut by: BTreeMap<String, [u64; 3]> = BTreeMap::new();
        for e in self.events.lock().unwrap().list.iter().filter(|e| e["seq"].as_u64() >= Some(since)) {
            let i = match e["k"].as_str() {
                Some("call") => 0,
                Some("ret") => 1,
                Some("throw") => 2,
                _ => continue,
            };
            by.entry(e["m"].as_str().unwrap_or_default().into()).or_default()[i] += 1;
        }
        let mut v: Vec<_> = by.into_iter().collect();
        v.sort_by(|a, b| b.1[0].cmp(&a.1[0]));
        v.iter().map(|(m, [c, r, t])| format!("{c:>7} calls {r:>7} returns {t:>5} throws  {m}\n")).collect()
    }
}

fn script(hooks: &BTreeMap<String, (String, bool)>) -> String {
    let mut s = PRELUDE.to_string();
    let mut java = String::new();
    for (k, (js, raw)) in hooks {
        let k = serde_json::to_string(k).unwrap();
        let block = format!("try {{\n{js}\n}} catch (e) {{ __ev(\"error\", {k}, String(e)); }}\n");
        if *raw { s += &block } else { java += &block }
    }
    if !java.is_empty() {
        s += &format!("if (Java.available) Java.perform(() => {{\n{java}}}); else __ev(\"error\", \"\", \"no Java runtime in this process\");\n");
    }
    s += &format!("__ev(\"loaded\", \"\", {});\n", hooks.len());
    s
}

fn matches(e: &Value, filter: &str) -> bool {
    filter.is_empty() || e["m"].as_str().is_some_and(|m| m.contains(filter)) || e["v"].to_string().contains(filter)
}

/// A frida output line as an event: hook events are JSON after \x01, anything else is frida's own text.
pub fn parse(line: &str, is_err: bool) -> Value {
    match line.split_once('\u{1}').and_then(|(_, j)| serde_json::from_str::<Value>(j).ok()) {
        Some(e) => e,
        None => json!({"k": if is_err { "stderr" } else { "log" }, "m": "", "v": line}),
    }
}

/// `#seq tid kind method value`
pub fn line(e: &Value) -> String {
    let v = value(e);
    format!("#{} t{} {:<6} {} {v}", e["seq"], e["tid"].as_u64().unwrap_or(0), e["k"].as_str().unwrap_or("?"), e["m"].as_str().unwrap_or(""))
}

/// An event's value as text: arguments as `(a, b)`.
pub fn value(e: &Value) -> String {
    match &e["v"] {
        Value::String(s) => s.clone(),
        Value::Array(a) => format!("({})", a.iter().map(|x| x.as_str().map_or_else(|| x.to_string(), str::to_string)).collect::<Vec<_>>().join(", ")),
        v => v.to_string(),
    }
}

/// Spells out frida's errors that mean "frida-server is not running on the device".
fn explain(log: String) -> String {
    if log.contains("need Gadget") || log.contains("unable to connect to remote frida-server") {
        format!("frida-server is not running on the device. Start it (Live panel, device, Start frida-server) or run:\n  adb shell \"su -c '/data/local/tmp/frida-server -D'\"\n\n{log}")
    } else {
        log
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn events() {
        let mut ev = Events::default();
        ev.push(parse("\u{1}{\"k\":\"call\",\"m\":\"a.B.c\",\"v\":[\"1\",\"x\"],\"tid\":7,\"ts\":0}", false));
        ev.push(parse("Spawned `x`.", true));
        assert_eq!(line(&ev.list[0]), "#0 t7 call   a.B.c (1, x)");
        assert_eq!(ev.list[1]["k"], "stderr");
        assert!(matches(&ev.list[0], "B.c") && !matches(&ev.list[0], "zzz"));
    }
}
