//! The frame: menus, panels, tabs and documents drawn every update.

use super::*;

impl eframe::App for App {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.poll();
        self.style(ctx);
        if let (Some(st), false) = (self.st, self.titled) {
            let name = std::path::Path::new(&st.path)
                .file_name()
                .map_or(st.path.clone(), |n| n.to_string_lossy().into_owned());
            ctx.send_viewport_cmd(egui::ViewportCommand::Title(format!("{name} - apkscope")));
            self.titled = true;
        }
        let p = self.set.theme.palette();
        // files dropped on the window
        if let Some(path) = ctx.input(|i| i.raw.dropped_files.first().and_then(|f| f.path.clone()))
        {
            self.start_load(path.display().to_string());
        }
        if ctx.input(|i| i.modifiers.command && i.key_pressed(egui::Key::F)) {
            self.focus_search = true;
        }
        if ctx.input(|i| i.modifiers.command && i.key_pressed(egui::Key::W))
            && !self.docs.is_empty()
        {
            self.close(self.active);
        }
        let (back, fwd) = ctx.input(|i| {
            (
                i.modifiers.alt && i.key_pressed(egui::Key::ArrowLeft)
                    || i.pointer.button_pressed(egui::PointerButton::Extra1),
                i.modifiers.alt && i.key_pressed(egui::Key::ArrowRight)
                    || i.pointer.button_pressed(egui::PointerButton::Extra2),
            )
        });
        if back {
            self.nav(false);
        } else if fwd {
            self.nav(true);
        }
        // Escape cancels a running search, else clears the marked word
        if self.prog.is_some() && ctx.input(|i| i.key_pressed(egui::Key::Escape)) {
            self.cancel_search();
        } else if ctx.input(|i| i.key_pressed(egui::Key::Escape))
            && let Some(d) = self.docs.get_mut(self.active)
            && d.sel.take().is_some()
        {
            d.job = None;
        }
        // Ctrl+Tab / Ctrl+Shift+Tab switch tabs, Ctrl+O opens an APK
        let (next_tab, prev_tab, open_apk) = ctx.input(|i| {
            (
                i.modifiers.command && !i.modifiers.shift && i.key_pressed(egui::Key::Tab),
                i.modifiers.command && i.modifiers.shift && i.key_pressed(egui::Key::Tab),
                i.modifiers.command && i.key_pressed(egui::Key::O),
            )
        });
        if !self.docs.is_empty() && (next_tab || prev_tab) {
            let n = self.docs.len();
            self.active = if next_tab {
                (self.active + 1) % n
            } else {
                (self.active + n - 1) % n
            };
        }
        egui::TopBottomPanel::top("bar").frame(egui::Frame::new().fill(p.bg).inner_margin(Margin::symmetric(10, 8))).show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.label(RichText::new("apkscope").strong().size(16.0).color(p.accent));
                ui.add_space(6.0);
                if (ui.button("Open…").on_hover_text("Open an APK, split bundle or DEX (Ctrl+O)").clicked() || open_apk)
                    && let Some(f) = rfd::FileDialog::new().add_filter("APK, split bundle or DEX", &session::INPUTS).pick_file() {
                        self.start_load(f.display().to_string());
                    }
                // one-off jobs live in a menu so the bar stays readable
                ui.add_enabled_ui(self.st.is_some(), |ui| {
                    ui.menu_button("Tools", |ui| {
                        if ui.button("Export Gradle project…").on_hover_text("Write a Gradle project (runs in the background)").clicked() {
                            ui.close_menu();
                            if let Some(dir) = rfd::FileDialog::new().pick_folder()
                                && let Ok(exe) = std::env::current_exe() {
                                    let mut cmd = std::process::Command::new(exe);
                                    cmd.arg("export").arg(&self.path).arg(&dir);
                                    if !self.set.deobf {
                                        cmd.arg("--no-deobf");
                                    }
                                    let _ = cmd.spawn();
                                    self.toast(format!("Exporting to {} in the background", dir.display()));
                                }
                        }
                        if ui.button("Security scan").on_hover_text("Manifest flags, exported components, risky APIs, weak crypto, TLS overrides, keys and URLs").clicked() {
                            self.report("Security scan".into(), |st| crate::re::scan(st).lines().map(|l| (l.to_string(), None)).collect());
                            ui.close_menu();
                        }
                        if ui.button("SDK fingerprints").on_hover_text("Known SDKs, frameworks and trackers (curated catalog + Exodus list) with version pins, evidence and an obfuscation-aware confidence").clicked() {
                            self.report("SDK fingerprints".into(), |st| {
                                crate::fingerprint::report_lines(st, true, crate::fingerprint::Catalog::Both)
                                    .into_iter()
                                    .map(|l| (l, None))
                                    .collect()
                            });
                            ui.close_menu();
                        }
                        if ui.button("Decrypt strings").on_hover_text("Run string-decryptor methods on their constant arguments (also shown inline in the code as /* = \"...\" */)").clicked() {
                            self.report("Decrypted strings".into(), |st| crate::re::decrypt_report(&st.dexes));
                            ui.close_menu();
                        }
                        let path = std::ffi::OsString::from(self.path.clone());
                        if ui.button("Compare with another APK…").on_hover_text("Added / removed classes, methods, permissions and strings between this APK and another version").clicked() {
                            ui.close_menu();
                            if let Some(other) = rfd::FileDialog::new().add_filter("Android app", &session::INPUTS).pick_file() {
                                self.cli_report("Diff", vec!["diff".into(), path.clone(), other.into(), "--strings".into()]);
                            }
                        }
                        if ui.button("Disassemble this class").on_hover_text("Raw Dalvik bytecode of the open class").clicked() {
                            ui.close_menu();
                            match self.docs.get(self.active).map(|d| d.open.clone()) {
                                Some(Open::Class(c)) => self.cli_report("Bytecode", vec!["disasm".into(), path.clone(), crate::dex::java_name(&c).into()]),
                                _ => self.toast("Open a class first"),
                            }
                        }
                        if ui.button("Constants of this class").on_hover_text("Static final values stored in the DEX (ids, codes, keys)").clicked() {
                            ui.close_menu();
                            match self.docs.get(self.active).map(|d| d.open.clone()) {
                                Some(Open::Class(c)) => self.cli_report("Constants", vec!["consts".into(), path.clone(), crate::lookup::raw_name(&c).into()]),
                                _ => self.toast("Open a class first"),
                            }
                        }
                        if ui.button("Constant returns in this class").on_hover_text("Methods whose body is return <constant>: ids, opcodes, type codes").clicked() {
                            ui.close_menu();
                            match self.docs.get(self.active).map(|d| d.open.clone()) {
                                Some(Open::Class(c)) => self.cli_report("Returns", vec!["returns".into(), path.clone(), "--in".into(), crate::lookup::raw_name(&c).into()]),
                                _ => self.toast("Open a class first"),
                            }
                        }
                        if ui.button("Size breakdown").on_hover_text("Where the APK's bytes go: dex, native libs per ABI, res, biggest files, duplicates").clicked() {
                            ui.close_menu();
                            self.cli_report("Size", vec!["size".into(), path.clone()]);
                        }
                        if ui.button("Install on device").on_hover_text("adb install with the splits and ABI the device needs (arm64-only apps on x86_64 emulators get --abi arm64-v8a); shows the ABI the package manager chose").clicked() {
                            ui.close_menu();
                            self.cli_report("Install", vec!["install".into(), path.clone()]);
                        }
                        ui.separator();
                        if ui.button("Unity IL2CPP").on_hover_text("Unity games: C# methods with their native addresses").clicked() {
                            ui.close_menu();
                            self.cli_report("IL2CPP", vec!["il2cpp".into(), path.clone()]);
                        }
                        if ui.button("Flutter").on_hover_text("Flutter apps: Dart version, libraries, hosts, routes and model fields").clicked() {
                            ui.close_menu();
                            self.cli_report("Flutter", vec!["flutter".into(), path.clone(), "--api".into()]);
                        }
                        if ui.button("Dump unpacked code (Frida)…").on_hover_text("Run the app on the device and save the DEX it unpacks and the scripts it decrypts (needs frida-server)").clicked() {
                            ui.close_menu();
                            if let Some(dir) = rfd::FileDialog::new().pick_folder() {
                                self.cli_report("Dump", vec!["dump".into(), path.clone(), dir.into()]);
                            }
                        }
                        ui.separator();
                        if ui.button("Import names…").on_hover_text("Take renames from a JADX (.jobf), Enigma (.mapping) or ProGuard/R8 (mapping.txt) file").clicked() {
                            ui.close_menu();
                            if let Some(f) = rfd::FileDialog::new().add_filter("Mapping", &["jobf", "mapping", "txt"]).pick_file() {
                                match std::fs::read_to_string(&f) {
                                    Ok(text) => {
                                        let mut n = crate::deobf::notes();
                                        let k = crate::re::import_mapping(&text, &mut n);
                                        self.store_notes(n, Some(format!("{k} names imported")));
                                    }
                                    Err(e) => self.toast(format!("{}: {e}", f.display())),
                                }
                            }
                        }
                        if ui.button("Export names…").on_hover_text("Write your renames as JADX (.jobf), Enigma (.mapping) or ProGuard (mapping.txt), by file name").clicked() {
                            ui.close_menu();
                            if let (Some(st), Some(f)) = (self.st, rfd::FileDialog::new().set_file_name("mapping.txt").save_file()) {
                                let name = f.to_string_lossy().into_owned();
                                let text = crate::re::export_mapping(&st.dexes, &crate::deobf::notes(), crate::re::MappingFormat::from_file(&name));
                                match std::fs::write(&f, text) {
                                    Ok(()) => self.toast(format!("Wrote {name}")),
                                    Err(e) => self.toast(format!("{name}: {e}")),
                                }
                            }
                        }
                    });
                });
                ui.separator();
                let scope = self.scope.label();
                egui::ComboBox::from_id_salt("scope").width(130.0).selected_text(scope).show_ui(ui, |ui| {
                    for s in Scope::ALL {
                        ui.selectable_value(&mut self.scope, s, s.label()).on_hover_text(s.note());
                    }
                })
                .response
                .on_hover_text("Search scope (Up / Down in the search box)")
                .widget_info(|| egui::WidgetInfo::labeled(egui::WidgetType::ComboBox, true, format!("Search scope: {scope}")));
                let hint = if self.scope.query_optional() { "optional filter (Enter lists all)" } else { "Search…  (Ctrl+F)" };
                let r = edit(ui, &mut self.query, hint, (ui.available_width() - 600.0).clamp(140.0, 520.0));
                if std::mem::take(&mut self.focus_search) {
                    r.request_focus();
                }
                // Up / Down in the search box change the scope
                if r.has_focus() {
                    let (up, down) = ui.input(|i| (i.key_pressed(egui::Key::ArrowUp), i.key_pressed(egui::Key::ArrowDown)));
                    if up || down {
                        let k = Scope::ALL.iter().position(|&s| s == self.scope).unwrap_or(0);
                        let n = Scope::ALL.len();
                        let next = Scope::ALL[if down { (k + 1) % n } else { (k + n - 1) % n }];
                        // entering an API scope: app-only is the default there now
                        if next.query_optional() && !self.scope.query_optional() {
                            self.app_only = true;
                        }
                        self.scope = next;
                    }
                }
                let (case, re) = (self.case, self.use_regex);
                ui.toggle_value(&mut self.case, "Aa").on_hover_text("Match case").widget_info(|| egui::WidgetInfo::selected(egui::WidgetType::SelectableLabel, true, case, "Match case"));
                ui.toggle_value(&mut self.use_regex, ".*").on_hover_text("Regular expression").widget_info(|| egui::WidgetInfo::selected(egui::WidgetType::SelectableLabel, true, re, "Regular expression"));
                ui.toggle_value(&mut self.app_only, "App only").on_hover_text("Skip classes from known libraries and SDKs (faster, less noise)");
                let w = edit(ui, &mut self.within, "in: a.b.*", 120.0).on_hover_text("Only these classes or packages (a.b.*, comma-separated); impl:a.b.Type keeps classes that extend or implement it");
                let enter_w = w.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
                let enter = r.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
                let go = ui.add_enabled(self.st.is_some(), egui::Button::new(RichText::new("Search").strong()).fill(p.accent.gamma_multiply(0.55)));
                if go.clicked() || enter || enter_w {
                    self.run_search();
                }
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if ui.button("⚙").on_hover_text("Settings").clicked() {
                        self.show_settings = !self.show_settings;
                    }
                    // Frida costs nothing until this is on
                    let on = self.live.open;
                    let label = RichText::new(if self.live.running() { "● Live  on" } else { "○ Live" }).strong().color(if on { Color32::BLACK } else { p.dim });
                    let b = egui::Button::new(label).fill(if on { Color32::from_rgb(60, 255, 120) } else { p.panel }).corner_radius(CornerRadius::same(10));
                    if ui.add_enabled(self.st.is_some(), b).on_hover_text("Live mode: run the app under Frida, hook methods with a click, see what runs").clicked() {
                        self.live.open = !on;
                    }
                });
            });
            if let Some(e) = &self.search_err {
                ui.colored_label(Color32::from_rgb(230, 80, 80), e.lines().last().unwrap_or(e));
            }
            if self.scope.query_optional() {
                ui.label(RichText::new(self.scope.note()).small().italics().color(p.dim));
            }
        });
        egui::TopBottomPanel::bottom("status")
            .frame(
                egui::Frame::new()
                    .fill(p.bg)
                    .inner_margin(Margin::symmetric(10, 4)),
            )
            .show(ctx, |ui| {
                ui.horizontal(|ui| match (self.st, &self.err) {
                    (_, Some(e)) => {
                        ui.colored_label(Color32::RED, format!("Failed to open: {e}"));
                    }
                    (Some(st), _) => {
                        ui.label(
                            RichText::new(format!(
                                "{}  ·  {} classes  ·  {} methods  ·  {} dex  ·  {} resources",
                                st.package,
                                st.classes.len(),
                                st.methods(),
                                st.dexes.len(),
                                st.texts().len() + st.files().len()
                            ))
                            .color(p.dim),
                        );
                        ui.separator();
                        match st.index.get() {
                            Some(_) => ui.label(RichText::new("indexed").color(p.dim)),
                            None => {
                                ui.spinner();
                                ui.label(
                                    RichText::new(format!(
                                        "indexing {} / {}",
                                        st.indexed.load(Ordering::Relaxed),
                                        st.classes.len()
                                    ))
                                    .color(p.dim),
                                )
                            }
                        };
                        if st.cached() {
                            ui.label(RichText::new("·  code cached").color(p.dim));
                        }
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            if let Some(m) = session::memory_used() {
                                ui.label(RichText::new(mb(m)).color(p.dim));
                            }
                        });
                    }
                    (None, _) if !self.path.is_empty() => {
                        ui.spinner();
                        ui.label(format!("Loading {}…", self.path));
                    }
                    _ => {
                        ui.label("Open an APK: the button above, or drop it on the window.");
                    }
                });
            });
        // the sidebar only means something once an APK is open
        if self.st.is_some() {
            egui::SidePanel::left("side")
                .default_width(330.0)
                .resizable(true)
                .frame(
                    egui::Frame::new()
                        .fill(p.panel)
                        .inner_margin(Margin::same(8)),
                )
                .show(ctx, |ui| self.side_panel(ui));
        }
        if let (Some(st), true) = (self.st, self.live.open) {
            let mut act = None;
            egui::SidePanel::right("live")
                .resizable(true)
                .default_width(440.0)
                .min_width(320.0)
                .frame(
                    egui::Frame::new()
                        .fill(Color32::from_rgb(6, 10, 8))
                        .inner_margin(Margin::same(8)),
                )
                .show(ctx, |ui| act = self.live.show(ui, st));
            if let Some(a) = act {
                self.act(a, ctx);
            }
        }
        if self.prog.is_some() || !self.hits_title.is_empty() {
            egui::TopBottomPanel::bottom("hits")
                .resizable(true)
                .default_height(240.0)
                .frame(
                    egui::Frame::new()
                        .fill(p.panel)
                        .inner_margin(Margin::same(8)),
                )
                .show(ctx, |ui| self.results_panel(ui));
        }
        egui::CentralPanel::default().frame(egui::Frame::new().fill(p.bg).inner_margin(Margin::same(8))).show(ctx, |ui| {
            if self.st.is_none() {
                self.start_screen(ui, &p);
                return;
            }
            if self.docs.is_empty() {
                ui.centered_and_justified(|ui| ui.label(RichText::new("Pick a class or resource on the left.").size(16.0).color(p.dim)));
                return;
            }
            // tab strip
            let mut close = None;
            let mut pick = None;
            // (which tabs to close, relative to tab k): 0 others, 1 left, 2 right, 3 all
            let mut close_many: Option<(usize, u8)> = None;
            let mut go_nav = None;
            egui::ScrollArea::horizontal().id_salt("tabs").show(ui, |ui| {
                ui.horizontal(|ui| {
                    if ui.add_enabled(!self.back.is_empty(), egui::Button::new("◀").frame(false)).on_hover_text("Back (Alt+Left, mouse back)").clicked() {
                        go_nav = Some(false);
                    }
                    if ui.add_enabled(!self.fwd.is_empty(), egui::Button::new("▶").frame(false)).on_hover_text("Forward (Alt+Right)").clicked() {
                        go_nav = Some(true);
                    }
                    ui.separator();
                    let n = self.docs.len();
                    for (k, d) in self.docs.iter().enumerate() {
                        let active = k == self.active;
                        let fill = if active { p.panel } else { Color32::TRANSPARENT };
                        egui::Frame::new().fill(fill).corner_radius(CornerRadius::same(6)).inner_margin(Margin::symmetric(8, 3)).show(ui, |ui| {
                            ui.horizontal(|ui| {
                                let t = RichText::new(d.open.short()).color(if active { p.text } else { p.dim });
                                let r = ui.add(egui::Label::new(t).sense(egui::Sense::click())).on_hover_text(d.open.name());
                                if r.clicked() {
                                    pick = Some(k);
                                }
                                if r.middle_clicked() || ui.add(egui::Button::new(RichText::new("x").small().color(p.dim)).frame(false)).on_hover_text("Close (Ctrl+W, middle-click)").clicked() {
                                    close = Some(k);
                                }
                                r.context_menu(|ui| {
                                    for (label, what, on) in [("Close", 9, true), ("Close others", 0, n > 1), ("Close tabs to the left", 1, k > 0), ("Close tabs to the right", 2, k + 1 < n), ("Close all", 3, true)] {
                                        if ui.add_enabled(on, egui::Button::new(label)).clicked() {
                                            if what == 9 { close = Some(k) } else { close_many = Some((k, what)) }
                                            ui.close_menu();
                                        }
                                    }
                                    ui.separator();
                                    if ui.button("Copy name").clicked() {
                                        ui.ctx().copy_text(d.open.name().to_string());
                                        ui.close_menu();
                                    }
                                });
                            });
                        });
                    }
                });
            });
            if let Some(k) = pick {
                self.active = k;
            }
            if let Some(f) = go_nav {
                self.nav(f);
                return;
            }
            if let Some((k, what)) = close_many {
                let keep = |i: usize| match what {
                    0 => i == k,
                    1 => i >= k,
                    2 => i <= k,
                    _ => false,
                };
                let mut i = 0;
                self.docs.retain(|_| { let r = keep(i); i += 1; r });
                self.active = match what {
                    0 | 1 => 0,
                    2 => k,
                    _ => 0,
                }
                .min(self.docs.len().saturating_sub(1));
                return;
            }
            if let Some(k) = close {
                self.close(k);
                return;
            }
            let (pal, size) = (p, self.set.code_font);
            let mut switch = None;
            let mut usages = None;
            let mut toast_msg = None;
            let mut change: Option<(String, Option<Vec<u8>>)> = None;
            let mut stage_smali: Option<String> = None;
            let mut act: Option<Act> = None;
            let st_now = self.st;
            let Some(doc) = self.docs.get_mut(self.active) else { return };
            ui.horizontal(|ui| {
                ui.label(RichText::new(doc.open.name()).strong());
                if let Open::Class(c) = &doc.open {
                    ui.separator();
                    for (v, name) in [(View::Java, "Java"), (View::Smali, "Smali")] {
                        if ui.selectable_label(doc.view == v, name).clicked() && doc.view != v {
                            switch = Some(v);
                        }
                    }
                    if ui.button("Usages").on_hover_text("Find where this class is used").clicked() {
                        usages = Some(c.rsplit('.').next().unwrap_or(c).to_string());
                    }
                }
                // edit a class as round-trippable Smali and stage it for the next Build & sign
                if matches!(&doc.open, Open::Class(_)) {
                    ui.separator();
                    match &doc.editing {
                        None => {
                            if ui.button("Edit smali").on_hover_text("Edit as round-trippable Smali; Apply stages it for the next Build & sign").clicked() {
                                let cls = doc.open.name().to_string();
                                match st_now.map(|st| smali::export_class(&st.file(), &cls)) {
                                    Some(Ok(t)) => {
                                        doc.editing = Some(t);
                                        doc.view = View::Smali;
                                    }
                                    Some(Err(e)) => toast_msg = Some(format!("Can't load smali: {e}")),
                                    None => {}
                                }
                            }
                        }
                        Some(buf) => {
                            if ui.button(RichText::new("Apply smali").strong()).on_hover_text("Stage this class for the next Build & sign (assembled when you build)").clicked() {
                                stage_smali = Some(buf.clone());
                                doc.editing = None;
                            }
                            if ui.button("Cancel").clicked() {
                                doc.editing = None;
                            }
                        }
                    }
                }
                let mut extract = None;
                if let Open::Native(path) | Open::File(path) = &doc.open {
                    ui.separator();
                    if ui.button("Extract…").on_hover_text("Save this file from the APK").clicked() {
                        extract = Some(path.clone());
                    }
                    if ui.button("Replace…").on_hover_text("Use another file in its place when you build").clicked()
                        && let Some(f) = rfd::FileDialog::new().pick_file() {
                            match std::fs::read(&f) {
                                Ok(b) => change = Some((path.clone(), Some(b))),
                                Err(e) => toast_msg = Some(format!("Can't read {}: {e}", f.display())),
                            }
                        }
                    if ui.button("Delete").on_hover_text("Leave this file out when you build").clicked() {
                        change = Some((path.clone(), None));
                    }
                }
                // the manifest can be edited as text and goes back in as binary XML
                if doc.open.name() == "AndroidManifest.xml" {
                    ui.separator();
                    match &doc.editing {
                        None => {
                            if ui.button("Edit manifest").on_hover_text("Edit as XML; Apply puts it into the next Build & sign").clicked() {
                                doc.editing = st_now.and_then(|st| st.resource("AndroidManifest.xml"));
                            }
                        }
                        Some(buf) => {
                            if ui.button(RichText::new("Apply").strong()).on_hover_text("Encode to binary XML and add it to the pending changes").clicked() {
                                match st_now.map(|st| st.encode_manifest(buf)) {
                                    Some(Ok(bin)) => {
                                        change = Some(("AndroidManifest.xml".into(), Some(bin)));
                                        doc.editing = None;
                                    }
                                    Some(Err(e)) => toast_msg = Some(format!("Manifest not applied: {e}")),
                                    None => {}
                                }
                            }
                            if ui.button("Cancel").clicked() {
                                doc.editing = None;
                            }
                        }
                    }
                }
                if let (Some(path), Some(st)) = (extract, st_now) {
                    let name = path.rsplit('/').next().unwrap_or(&path).to_string();
                    if let Some(f) = rfd::FileDialog::new().set_file_name(&name).save_file() {
                        let r = st.read_entry(&path).ok_or("can't read it".to_string()).and_then(|b| std::fs::write(&f, b).map_err(|e| e.to_string()));
                        toast_msg = Some(match r {
                            Ok(()) => format!("Saved {}", f.display()),
                            Err(e) => format!("Extract failed: {e}"),
                        });
                    }
                }
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if let Some(t) = &doc.text {
                        if ui.button("Copy").clicked() {
                            ui.ctx().copy_text(t.to_string());
                        }
                        let r = edit(ui, &mut doc.find, "Find in file (Enter)", 200.0);
                        if r.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)) && !doc.find.is_empty() {
                            if let Some(l) = find_next(t, &doc.find, doc.mark.unwrap_or(0)) {
                                doc.mark = Some(l);
                                doc.scroll_pending = true;
                            }
                            r.request_focus();
                        }
                    }
                });
            });
            ui.separator();
            if let Some(buf) = &mut doc.editing {
                egui::ScrollArea::both().id_salt("manifest-edit").auto_shrink(false).show(ui, |ui| {
                    ui.add(egui::TextEdit::multiline(buf).code_editor().font(FontId::monospace(size)).desired_width(f32::INFINITY).desired_rows(40));
                });
            } else if let Some(text) = doc.text.clone() {
            let key = (pal.bg, (size * 10.0) as u32, doc.mark, doc.sel.clone());
            if doc.job.as_ref().is_none_or(|j| j.0 != key) {
                doc.job = Some((key, highlight(&text, &pal, size, doc.mark, doc.sel.as_deref())));
            }
            let job = doc.job.as_ref().unwrap().1.clone();
            let mut area = egui::ScrollArea::both().id_salt(doc.open.name()).auto_shrink(false);
            if std::mem::take(&mut doc.scroll_pending)
                && let Some(ln) = doc.mark {
                    let row = ui.fonts(|f| f.row_height(&FontId::monospace(size)));
                    area = area.vertical_scroll_offset(((ln as f32 - 6.0).max(0.0)) * row);
                }
            let row = ui.fonts(|f| f.row_height(&FontId::monospace(size)));
            let glyph = ui.fonts(|f| f.glyph_width(&FontId::monospace(size), 'M'));
            let is_report = matches!(doc.open, Open::Report(_));
            area.show(ui, |ui| {
                let r = ui.add(egui::Label::new(job).extend().selectable(true));
                let at = r.interact_pointer_pos().or(r.hover_pos()).map(|p| (((p.y - r.rect.top()) / row).max(0.0) as usize, ((p.x - r.rect.left()) / glyph).max(0.0) as usize));
                let link_here = |l: usize| doc.links.as_ref().and_then(|v| v.get(l).cloned().flatten());
                if is_report && r.hovered() && r.hover_pos().is_some_and(|p| link_here(((p.y - r.rect.top()) / row).max(0.0) as usize).is_some()) {
                    ui.ctx().set_cursor_icon(egui::CursorIcon::PointingHand);
                }
                if r.secondary_clicked() {
                    doc.menu_at = at;
                }
                if r.clicked()
                    && let Some((l, c)) = at {
                        let ctrl = ui.input(|i| i.modifiers.command);
                        if is_report {
                            // a click on a linked report line jumps to that code
                            if let Some(link) = link_here(l) {
                                act = Some(Act::GoTo(link));
                            }
                        } else if let (true, Open::Class(top), Some(st)) = (ctrl, &doc.open, st_now) {
                            act = definition(st, top, &text, l, c);
                        }
                        // a click on a name marks it everywhere in the file; again to clear
                        let w = word_at(&text, l, c).map(|w| w.0).filter(|w| !KEYWORDS.contains(&w.as_str()));
                        doc.sel = if doc.sel == w { None } else { w };
                        doc.job = None;
                    }
                r.context_menu(|ui| {
                    if let Some(a) = line_menu(ui, doc, &text, st_now) {
                        act = Some(a);
                        ui.close_menu();
                    }
                });
            });
            // keyboard, with no text box focused: Up/Down move the marked line, F12 goes to
            // the definition (or follows a report link), Shift+F10 opens the line's actions
            if ui.ctx().memory(|m| m.focused().is_none()) && !doc.kb_menu {
                let (up, down, f12, menu) = ui.input(|i| (i.key_pressed(egui::Key::ArrowUp), i.key_pressed(egui::Key::ArrowDown), i.key_pressed(egui::Key::F12), i.modifiers.shift && i.key_pressed(egui::Key::F10)));
                if up || down {
                    let (cur, n) = (doc.mark.unwrap_or(0), text.lines().count().max(1));
                    doc.mark = Some(if up { cur.saturating_sub(1).max(1) } else { (cur + 1).min(n) });
                    doc.scroll_pending = true;
                    doc.job = None;
                }
                if let Some(l) = doc.mark.map(|m| m - 1).filter(|_| f12 || menu) {
                    let line = text.lines().nth(l).unwrap_or("");
                    // the name before the first `(`, else the first word
                    let col = line.find('(').and_then(|p| p.checked_sub(1)).unwrap_or(line.len() - line.trim_start().len());
                    if f12 && is_report {
                        act = doc.links.as_ref().and_then(|v| v.get(l).cloned().flatten()).map(Act::GoTo);
                    } else if let (true, Open::Class(top), Some(st)) = (f12, &doc.open, st_now) {
                        act = definition(st, top, &text, l, col);
                    }
                    if menu {
                        doc.menu_at = Some((l, col));
                        doc.kb_menu = true;
                    }
                }
            }
            if doc.kb_menu {
                let mut open = true;
                egui::Window::new("Line actions").collapsible(false).resizable(false).open(&mut open).anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0]).show(ui.ctx(), |ui| {
                    if let Some(a) = line_menu(ui, doc, &text, st_now) {
                        act = Some(a);
                        doc.kb_menu = false;
                    }
                });
                if !open || ui.input(|i| i.key_pressed(egui::Key::Escape)) {
                    doc.kb_menu = false;
                }
            }
            }
            let Some(_) = doc.text.clone() else {
                ui.spinner();
                if let Some(v) = switch {
                    let o = doc.open.clone();
                    self.open(o, Some(v), None);
                }
                return;
            };
            if let Some(v) = switch {
                let o = doc.open.clone();
                self.open(o, Some(v), None);
            }
            if let Some(name) = usages {
                self.usages_of(&name);
            }
            if let Some(a) = act {
                self.act(a, ui.ctx());
            }
            if let Some(t) = toast_msg {
                self.toast(t);
            }
            if let Some((name, new)) = change {
                let what = if new.is_some() { "replaced" } else { "deleted" };
                self.edits.insert(name.clone(), new);
                let what = if name == "AndroidManifest.xml" && what == "replaced" { "updated" } else { what };
                self.toast(format!("{name} will be {what} when you build (Files tab)"));
            }
            if let Some(src) = stage_smali {
                self.smali_edits.push(src);
                self.toast(format!("Smali staged ({} class(es)) — use Build & sign to write it", self.smali_edits.len()));
            }
        });
        self.export_window(ctx);
        self.note_window(ctx);
        self.edit_windows(ctx);
        self.settings_window(ctx);
        if let Some((t, at)) = &self.toast {
            if at.elapsed().as_secs() < 4 {
                egui::Area::new("toast".into())
                    .anchor(egui::Align2::RIGHT_BOTTOM, [-16.0, -36.0])
                    .show(ctx, |ui| {
                        egui::Frame::new()
                            .fill(p.panel)
                            .stroke(Stroke::new(1.0_f32, p.accent))
                            .corner_radius(CornerRadius::same(8))
                            .inner_margin(Margin::symmetric(12, 8))
                            .show(ui, |ui| {
                                ui.label(t);
                            });
                    });
                ctx.request_repaint_after(std::time::Duration::from_millis(500));
            } else {
                self.toast = None;
            }
        }
        let indexing = self.st.is_some_and(|s| s.index.get().is_none());
        let busy = (self.st.is_none() && !self.path.is_empty() && self.err.is_none())
            || self.prog.is_some()
            || indexing
            || self.docs.iter().any(|d| d.text.is_none());
        if busy {
            ctx.request_repaint_after(std::time::Duration::from_millis(150));
        }
    }
}
