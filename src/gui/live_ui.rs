//! The LIVE panel: a Frida session on a device, drawn as a phosphor terminal. Each hooked method
//! is a pixel tile that flashes when it runs, a bar strip shows events per second, and the event
//! stream is indented by call depth per thread so nested calls read as a tree.

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use eframe::egui::{self, Color32, CornerRadius, FontId, RichText, Sense, Stroke, pos2, vec2};
use serde_json::Value;

use super::Act;
use crate::live::Live;
use crate::session::State;

const BG: Color32 = Color32::from_rgb(6, 10, 8);
const GRID: Color32 = Color32::from_rgb(16, 30, 22);
const GREEN: Color32 = Color32::from_rgb(60, 255, 120);
const DIM: Color32 = Color32::from_rgb(40, 120, 70);
const CYAN: Color32 = Color32::from_rgb(80, 220, 255);
const RED: Color32 = Color32::from_rgb(255, 70, 90);
const AMBER: Color32 = Color32::from_rgb(255, 190, 60);
/// stream lines kept in the panel
const KEEP: usize = 4000;
/// seconds of history in the bar strip
const SECS: usize = 60;

#[derive(Default)]
struct Tile {
    calls: u64,
    throws: u64,
    last: Option<Instant>,
    threw: bool,
}

/// One stream line: (depth, kind, method, value).
type Row = (usize, String, String, String);

#[derive(Default, Clone, Copy, PartialEq)]
enum Tab {
    #[default]
    Activity,
    Hooks,
    Script,
}

#[derive(Default)]
pub struct LiveUi {
    tab: Tab,
    pub open: bool,
    live: Option<Live>,
    starting: Option<mpsc::Receiver<Result<Live, String>>>,
    err: Option<String>,
    device: String,
    attach: bool,
    seen: u64,
    tiles: BTreeMap<String, Tile>,
    rows: VecDeque<Row>,
    depth: HashMap<u64, usize>,
    /// events per second, newest last, with the second the last bucket is for
    rate: VecDeque<u32>,
    rate_at: Option<Instant>,
    filter: String,
    paused: bool,
    script: String,
    script_name: String,
}

impl LiveUi {
    pub fn running(&self) -> bool {
        self.live.is_some()
    }

    /// Hook `class` (descriptor or Java name), one method or all, from the code view.
    pub fn hook(&mut self, st: &State, class: &str, method: Option<&str>) -> Result<String, String> {
        self.open = true;
        let live = self.live.as_mut().ok_or("start a live session first (LIVE panel, Spawn or Attach)")?;
        let js = crate::re::frida(&st.dexes, class, method, true)?;
        let java = crate::dex::java_name(&crate::re::desc(class));
        let key = method.map_or(java.clone(), |m| format!("{java}#{m}"));
        live.hook(&key, &js, false)?;
        Ok(format!("hooked {key} live"))
    }

    fn start(&mut self, target: String) {
        let (tx, rx) = mpsc::channel();
        let (attach, device) = (self.attach, Some(self.device.trim().to_string()).filter(|d| !d.is_empty()));
        std::thread::spawn(move || _ = tx.send(Live::start(&target, attach, device.as_deref())));
        self.starting = Some(rx);
        self.err = None;
    }

    /// Pull new events into tiles, rate and stream.
    fn poll(&mut self) {
        if let Some(rx) = &self.starting {
            match rx.try_recv() {
                Ok(Ok(l)) => {
                    *self = LiveUi { open: true, live: Some(l), device: std::mem::take(&mut self.device), attach: self.attach, script: std::mem::take(&mut self.script), script_name: std::mem::take(&mut self.script_name), ..Default::default() };
                }
                Ok(Err(e)) => {
                    self.err = Some(e);
                    self.starting = None;
                }
                Err(mpsc::TryRecvError::Disconnected) => self.starting = None,
                Err(mpsc::TryRecvError::Empty) => {}
            }
        }
        let now = Instant::now();
        let at = *self.rate_at.get_or_insert(now);
        let gone = (now - at).as_secs() as usize;
        for _ in 0..gone.min(SECS) {
            self.rate.push_back(0);
        }
        if gone > 0 {
            self.rate_at = Some(at + Duration::from_secs(gone as u64));
        }
        if self.rate.is_empty() {
            self.rate.push_back(0);
        }
        while self.rate.len() > SECS {
            self.rate.pop_front();
        }
        let Some(live) = &self.live else { return };
        let new: Vec<Value> = {
            let ev = live.events.lock().unwrap();
            ev.list.iter().filter(|e| e["seq"].as_u64() >= Some(self.seen)).cloned().collect()
        };
        self.ingest(new, now);
    }

    fn ingest(&mut self, new: Vec<Value>, now: Instant) {
        for e in new {
            self.seen = e["seq"].as_u64().unwrap_or(0) + 1;
            if let Some(r) = self.rate.back_mut() {
                *r += 1;
            }
            let (k, m) = (e["k"].as_str().unwrap_or("?").to_string(), e["m"].as_str().unwrap_or("").to_string());
            let tid = e["tid"].as_u64().unwrap_or(0);
            let d = self.depth.entry(tid).or_default();
            let shown = match k.as_str() {
                "call" => {
                    let t = self.tiles.entry(m.clone()).or_default();
                    t.calls += 1;
                    t.last = Some(now);
                    t.threw = false;
                    *d += 1;
                    *d - 1
                }
                "ret" | "throw" => {
                    if k == "throw" {
                        let t = self.tiles.entry(m.clone()).or_default();
                        t.throws += 1;
                        t.threw = true;
                        t.last = Some(now);
                    }
                    *d = d.saturating_sub(1);
                    *d
                }
                _ => 0,
            };
            let v = crate::live::value(&e);
            self.rows.push_back((shown.min(24), k, m, v));
            if self.rows.len() > KEEP {
                self.rows.pop_front();
            }
        }
    }

    /// Draw the panel; returns what a click asked the viewer to open.
    pub fn show(&mut self, ui: &mut egui::Ui, st: &'static State) -> Option<Act> {
        if !self.paused {
            self.poll();
        }
        ui.ctx().request_repaint_after(Duration::from_millis(if self.live.is_some() { 50 } else { 250 }));
        let mut out = None;
        ui.visuals_mut().override_text_color = Some(GREEN);
        ui.style_mut().override_font_id = Some(FontId::monospace(12.0));
        let alive = self.live.as_mut().map(Live::alive);
        let (status, color) = match (alive, &self.starting) {
            (Some(true), _) => ("● RUNNING", GREEN),
            (Some(false), _) => ("✖ FRIDA EXITED", RED),
            (None, Some(_)) => ("◌ CONNECTING…", AMBER),
            _ => ("○ OFF", DIM),
        };
        ui.horizontal(|ui| {
            ui.label(RichText::new("▓▒░ LIVE").strong().size(15.0));
            ui.label(RichText::new(status).color(color));
        });
        ui.label(RichText::new(&st.package).color(DIM));
        ui.add_space(4.0);
        if self.live.is_none() {
            let ok = self.starting.is_none() && !st.package.is_empty();
            ui.horizontal(|ui| {
                if ui.add_enabled(ok, egui::Button::new(RichText::new("▶ Launch app").strong())).on_hover_text("Start the app on the device under Frida").clicked() {
                    self.attach = false;
                    self.start(st.package.clone());
                }
                if ui.add_enabled(ok, egui::Button::new("⇢ Attach")).on_hover_text("Join the app that is already running").clicked() {
                    self.attach = true;
                    self.start(st.package.clone());
                }
            });
            egui::CollapsingHeader::new("device").default_open(false).show(ui, |ui| {
                ui.add(egui::TextEdit::singleline(&mut self.device).hint_text("frida device id (empty = USB)"));
                if ui.button("Start frida-server").on_hover_text("adb shell su -c /data/local/tmp/frida-server -D (rooted device or emulator)").clicked() {
                    // -D daemonizes; adb returns once it has
                    self.err = match std::process::Command::new("adb").args(["shell", "su -c '/data/local/tmp/frida-server -D'"]).stdin(std::process::Stdio::null()).spawn() {
                        Ok(_) => None,
                        Err(e) => Some(format!("cannot run adb: {e}")),
                    };
                }
                ui.label(RichText::new("Needs `pip install frida-tools` here and frida-server on the device. MuMu: adb connect 127.0.0.1:16384").small().color(DIM));
            });
        } else {
            ui.horizontal(|ui| {
                if ui.button("■ Stop").clicked() {
                    self.live = None;
                }
                ui.toggle_value(&mut self.paused, "❚❚ Pause");
                if ui.button("Clear").clicked() {
                    self.rows.clear();
                    self.tiles.values_mut().for_each(|t| *t = Tile::default());
                }
            });
        }
        if let Some(e) = &self.err {
            ui.colored_label(RED, e.lines().take(6).collect::<Vec<_>>().join("\n"));
        }
        ui.add_space(4.0);
        ui.horizontal(|ui| {
            for (t, name) in [(Tab::Activity, "Activity"), (Tab::Hooks, "Hooks"), (Tab::Script, "Script")] {
                ui.selectable_value(&mut self.tab, t, name);
            }
        });
        ui.separator();
        match self.tab {
            Tab::Activity => {
                if let Some(a) = self.pixels(ui, 170.0) {
                    out = Some(a);
                }
                ui.add(egui::TextEdit::singleline(&mut self.filter).hint_text("filter the stream").desired_width(f32::INFINITY));
                if let Some(a) = self.stream(ui) {
                    out = Some(a);
                }
            }
            Tab::Hooks => {
                let keys = self.live.as_ref().map(Live::hook_keys).unwrap_or_default();
                if keys.is_empty() {
                    ui.label(RichText::new("No hooks yet.\n\nRight-click a method or class in the code and pick Hook live: its calls, arguments and results show up under Activity.").color(DIM));
                }
                egui::ScrollArea::vertical().id_salt("live_hooks").show(ui, |ui| {
                    for k in keys {
                        ui.horizontal(|ui| {
                            if ui.small_button("✖").on_hover_text("Unhook").clicked() {
                                if let Some(l) = &mut self.live {
                                    let _ = l.unhook(&k);
                                }
                            }
                            let prefix = k.replace('#', ".");
                            let calls: u64 = self.tiles.iter().filter(|(m, _)| m.starts_with(&prefix)).map(|(_, t)| t.calls).sum();
                            ui.label(format!("{k}  ({calls})"));
                        });
                    }
                });
            }
            Tab::Script => {
                ui.label(RichText::new("Your own Frida JS. __ev(kind, name, value) puts events in Activity.").color(DIM));
                ui.horizontal(|ui| {
                    ui.add(egui::TextEdit::singleline(&mut self.script_name).hint_text("name").desired_width(120.0));
                    if ui.add_enabled(self.live.is_some() && !self.script.trim().is_empty(), egui::Button::new("Load")).clicked() {
                        let name = if self.script_name.trim().is_empty() { "script".to_string() } else { self.script_name.trim().to_string() };
                        if let Some(l) = &mut self.live {
                            if let Err(e) = l.hook(&name, &self.script, true) {
                                self.err = Some(e);
                            }
                        }
                    }
                });
                egui::ScrollArea::vertical().id_salt("live_js").show(ui, |ui| {
                    ui.add(egui::TextEdit::multiline(&mut self.script).code_editor().desired_rows(16).desired_width(f32::INFINITY).hint_text("Java.perform(() => { ... })"));
                });
            }
        }
        out
    }

    /// The event stream, indented by call depth; a click opens the method.
    fn stream(&mut self, ui: &mut egui::Ui) -> Option<Act> {
        let mut out = None;
        let rows: Vec<&Row> = self.rows.iter().filter(|r| self.filter.is_empty() || r.2.contains(&self.filter) || r.3.contains(&self.filter)).collect();
        if rows.is_empty() {
            ui.label(RichText::new("Calls of hooked methods appear here as they happen.").color(DIM));
        }
        egui::ScrollArea::vertical().id_salt("live_stream").stick_to_bottom(true).auto_shrink(false).show_rows(ui, 15.0, rows.len(), |ui, range| {
            for (d, k, m, v) in &rows[range] {
                let (glyph, c) = match k.as_str() {
                    "call" => ("→", GREEN),
                    "ret" => ("←", CYAN),
                    "throw" => ("✖", RED),
                    "error" | "stderr" => ("!", AMBER),
                    _ => ("·", DIM),
                };
                let short = m.rsplit('.').take(2).collect::<Vec<_>>().into_iter().rev().collect::<Vec<_>>().join(".");
                let text = format!("{}{glyph} {short} {v}", "│ ".repeat(*d));
                let r = ui.add(egui::Label::new(RichText::new(text).color(c)).truncate().sense(Sense::click()));
                if r.clicked() {
                    out = open_method(m);
                }
                r.on_hover_text(format!("{m}\n{v}\n(click: open in code)"));
            }
        });
        out
    }

    /// The pixel board: one tile per hooked method that flashes on a call (red on a throw)
    /// and fades, then 60 s of events per second as pixel bars.
    fn pixels(&mut self, ui: &mut egui::Ui, h: f32) -> Option<Act> {
        let mut out = None;
        let w = ui.available_width();
        let (rect, _) = ui.allocate_exact_size(vec2(w, h), Sense::hover());
        let p = ui.painter_at(rect);
        p.rect_filled(rect, CornerRadius::ZERO, BG);
        // scanlines
        let mut y = rect.top();
        while y < rect.bottom() {
            p.hline(rect.x_range(), y, Stroke::new(1.0_f32, GRID));
            y += 3.0;
        }
        let strip = 54.0;
        let board = egui::Rect::from_min_max(rect.min + vec2(6.0, 6.0), pos2(rect.right() - 6.0, rect.bottom() - strip - 6.0));
        let now = Instant::now();
        let cell = 18.0;
        let per = ((board.width() / (cell + 4.0)) as usize).max(1);
        let max_calls = self.tiles.values().map(|t| t.calls).max().unwrap_or(1).max(1) as f32;
        if self.tiles.is_empty() {
            p.text(board.center(), egui::Align2::CENTER_CENTER, "[ NO SIGNAL ]", FontId::monospace(14.0), DIM);
        }
        for (i, (m, t)) in self.tiles.iter().enumerate() {
            let at = board.min + vec2((i % per) as f32 * (cell + 4.0), (i / per) as f32 * (cell + 4.0));
            let r = egui::Rect::from_min_size(at, vec2(cell, cell));
            if r.bottom() > board.bottom() {
                break;
            }
            let heat = t.last.map_or(0.0, |l| (1.0 - (now - l).as_secs_f32() / 1.5).max(0.0));
            let base = if t.threw { RED } else { GREEN };
            let warm = 0.15 + 0.35 * (t.calls as f32).ln_1p() / max_calls.ln_1p().max(1.0);
            p.rect_filled(r, CornerRadius::ZERO, base.gamma_multiply((warm + heat).min(1.0)));
            // the inner pixel blinks while hot
            if heat > 0.0 {
                p.rect_filled(r.shrink(6.0), CornerRadius::ZERO, Color32::WHITE.gamma_multiply(heat));
            }
            let resp = ui.interact(r, ui.id().with(("tile", i)), Sense::click());
            if resp.clicked() {
                out = open_method(m);
            }
            resp.on_hover_text(format!("{m}\n{} calls, {} throws\n(click: open in code)", t.calls, t.throws));
        }
        // events-per-second bars, in 4-px pixel blocks
        let base = rect.bottom() - 6.0;
        let top = base - strip + 10.0;
        p.text(pos2(rect.left() + 6.0, top - 8.0), egui::Align2::LEFT_TOP, format!("EV/S {}", self.rate.back().copied().unwrap_or(0)), FontId::monospace(10.0), DIM);
        let peak = self.rate.iter().copied().max().unwrap_or(1).max(1) as f32;
        let bw = ((rect.width() - 12.0) / SECS as f32).floor().max(2.0);
        for (i, &n) in self.rate.iter().enumerate() {
            let x = rect.left() + 6.0 + (SECS - self.rate.len() + i) as f32 * bw;
            let blocks = ((n as f32 / peak) * ((base - top) / 4.0)).ceil() as usize;
            for b in 0..blocks {
                let y = base - (b as f32 + 1.0) * 4.0;
                p.rect_filled(egui::Rect::from_min_size(pos2(x, y), vec2(bw - 1.0, 3.0)), CornerRadius::ZERO, if b > 8 { AMBER } else { GREEN });
            }
        }
        out
    }
}

/// `pkg.Cls.method` -> open the top-level class at that method.
fn open_method(m: &str) -> Option<Act> {
    let (class, name) = m.rsplit_once('.')?;
    let top = class.split('$').next().unwrap_or(class).to_string();
    let name = if name == "<init>" { class.rsplit(['.', '$']).next().unwrap_or(name).to_string() } else { name.to_string() };
    Some(Act::OpenClass(top, Some(super::Target { decl: None, then: Some(format!(" {name}(")) })))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stream_depth_and_tiles() {
        let mut ui = LiveUi::default();
        let ev: Vec<Value> = [r#"{"k":"call","m":"a.B.f","v":[],"tid":1,"seq":0}"#, r#"{"k":"call","m":"a.B.g","v":["1"],"tid":1,"seq":1}"#, r#"{"k":"ret","m":"a.B.g","v":"2","tid":1,"seq":2}"#, r#"{"k":"throw","m":"a.B.f","v":"E","tid":1,"seq":3}"#]
            .iter()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect();
        ui.ingest(ev, Instant::now());
        assert_eq!(ui.rows.iter().map(|r| r.0).collect::<Vec<_>>(), [0, 1, 1, 0]);
        assert_eq!(ui.seen, 4);
        assert!(ui.tiles["a.B.f"].threw && ui.tiles["a.B.g"].calls == 1);
        assert!(matches!(open_method("a.b.C$D.run"), Some(Act::OpenClass(c, _)) if c == "a.b.C"));
    }
}
