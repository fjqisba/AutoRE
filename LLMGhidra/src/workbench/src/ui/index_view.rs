// SPDX-License-Identifier: Apache-2.0
use super::*;
use llmghidra_analysis::index::{store::Store, FunctionFact, StringFact, SymbolFact, XrefFact};
use std::collections::BTreeMap;
const PAGE: usize = 128;
#[derive(Default)]
pub(super) struct BrowserPage {
    functions: Vec<FunctionFact>,
    strings: Vec<StringFact>,
    xrefs: Vec<XrefFact>,
    symbols: Vec<SymbolFact>,
    pub labels: BTreeMap<u64, String>,
    pub comments: BTreeMap<u64, String>,
    aliases: BTreeMap<u64, Vec<String>>,
}
pub(super) struct Browser {
    pub page: BrowserPage,
    pub epoch: u64,
    pub busy: bool,
    pub dirty: bool,
    pub error: String,
    revision: u64,
    last: Instant,
    function_query: String,
    function_cursors: Vec<Option<u64>>,
    string_query: String,
    string_cursors: Vec<Option<(u64, String)>>,
    symbol_query: String,
    symbol_offset: usize,
    xref_address: u64,
    xref_end: u64,
    incoming: bool,
    xref_cursors: Vec<Option<(u64, u64, String)>>,
}
impl Default for Browser {
    fn default() -> Self {
        Self {
            page: BrowserPage::default(),
            epoch: 0,
            busy: false,
            dirty: true,
            error: String::new(),
            revision: u64::MAX,
            last: Instant::now() - Duration::from_secs(1),
            function_query: String::new(),
            function_cursors: vec![None],
            string_query: String::new(),
            string_cursors: vec![None],
            symbol_query: String::new(),
            symbol_offset: 0,
            xref_address: 0,
            xref_end: 1,
            incoming: true,
            xref_cursors: vec![None],
        }
    }
}
impl Browser {
    pub fn invalidate(&mut self) {
        self.epoch += 1;
        self.dirty = true;
    }
}
impl Workbench {
    pub(super) fn poll_index(&mut self, ctx: &egui::Context) {
        let Some(session) = self.index_session.clone() else {
            return;
        };
        let previous = self.index_progress.running;
        self.index_progress = session.progress();
        if previous && !self.index_progress.running {
            self.log(format!(
                "{} | {} functions, {} strings, {} references | {} ms",
                self.index_progress.phase,
                self.index_progress.counts.functions,
                self.index_progress.counts.strings,
                self.index_progress.counts.xrefs,
                self.index_progress.elapsed_ms
            ));
            for warning in self.index_progress.warnings.clone() {
                self.log(warning);
            }
        }
        if !self.initial_navigated {
            if let Some(address) = self.index_progress.preferred {
                self.initial_navigated = true;
                self.navigate(address, ctx, true);
            }
        }
        if self.browser.busy || self.browser.last.elapsed() < Duration::from_millis(250) {
            ctx.request_repaint_after(Duration::from_millis(100));
            return;
        }
        if !self.browser.dirty && self.browser.revision == self.index_progress.revision {
            return;
        }
        self.browser.last = Instant::now();
        self.browser.revision = self.index_progress.revision;
        self.browser.dirty = false;
        let epoch = self.browser.epoch;
        let path = session.path.clone();
        let fq = self.browser.function_query.clone();
        let fc = self.browser.function_cursors.last().copied().flatten();
        let sq = self.browser.string_query.clone();
        let sc = self.browser.string_cursors.last().cloned().flatten();
        let tab = self.tab;
        let xva = self.browser.xref_address;
        let xend = self.browser.xref_end;
        let incoming = self.browser.incoming;
        let xc = self.browser.xref_cursors.last().cloned().flatten();
        let syq = self.browser.symbol_query.clone();
        let syo = self.browser.symbol_offset;
        let addresses: Vec<_> = self
            .listing
            .iter()
            .filter_map(|i| i.target)
            .chain(std::iter::once(self.address))
            .collect();
        let listing_start = self.listing.first().map(|i| i.address);
        let listing_end = self.listing.last().map(|i| i.address.saturating_add(4));
        let before = self.pending;
        self.submit(ctx, move || {
            Event::Browser(
                epoch,
                (|| {
                    let store = Store::read(&path)?;
                    store.begin_snapshot()?;
                    let mut page = BrowserPage {
                        functions: store.functions(&fq, fc, PAGE)?,
                        ..Default::default()
                    };
                    for f in &page.functions {
                        page.aliases.insert(f.address, store.aliases(f.address)?);
                    }
                    for va in addresses {
                        if let Some(label) = store.label(va) {
                            page.labels.insert(va, label);
                        }
                    }
                    if let (Some(start), Some(end)) = (listing_start, listing_end) {
                        for x in store.xrefs(start, end, false, None, 512)? {
                            if let Some(label) = store.label(x.to) {
                                page.comments
                                    .entry(x.from)
                                    .or_insert_with(|| format!("; {}: {}", x.kind, label));
                            }
                        }
                    }
                    match tab {
                        Tab::Strings => page.strings = store.strings(&sq, sc, PAGE)?,
                        Tab::Xrefs => page.xrefs = store.xrefs(xva, xend, incoming, xc, PAGE)?,
                        Tab::Imports | Tab::Exports => {
                            page.symbols = store.symbols(
                                if tab == Tab::Imports {
                                    "import"
                                } else {
                                    "export"
                                },
                                &syq,
                                syo,
                                PAGE,
                            )?
                        }
                        _ => (),
                    }
                    for x in &page.xrefs {
                        for va in [x.from, x.to] {
                            if let Some(label) = store.label(va) {
                                page.labels.insert(va, label);
                            }
                        }
                        if let std::collections::btree_map::Entry::Vacant(entry) =
                            page.labels.entry(x.from)
                        {
                            if let Some(owner) = store.owner(x.from) {
                                entry.insert(owner);
                            }
                        }
                    }
                    Ok(page)
                })(),
            )
        });
        self.browser.busy = self.pending > before;
        if !self.browser.busy {
            self.browser.dirty = true;
        }
        if self.index_progress.running {
            ctx.request_repaint_after(Duration::from_millis(100));
        }
    }
    pub(super) fn show_xrefs(&mut self, address: u64, end: u64, ctx: &egui::Context) {
        self.browser.xref_address = address;
        self.browser.xref_end = end.max(address.saturating_add(1));
        self.browser.xref_cursors = vec![None];
        self.browser.invalidate();
        self.tab = Tab::Xrefs;
        ctx.request_repaint();
    }
    fn coverage(&mut self, ui: &mut egui::Ui) {
        let p = &self.index_progress;
        ui.horizontal_wrapped(|ui| {
            if p.running {
                ui.spinner();
            }
            ui.label(&p.phase);
            ui.label(format!(
                "{} candidate entries · {} unresolved indirect sites",
                p.counts.candidates, p.counts.unresolved
            ));
            if p.total > 0 {
                ui.label(format!(
                    "{:.1} / {:.1} MiB",
                    p.scanned as f64 / 1048576.0,
                    p.total as f64 / 1048576.0
                ));
            }
            if !p.running && !p.complete && ui.button("Resume indexing").clicked() {
                if let Some(session) = &self.index_session {
                    session.start();
                }
            }
        });
        if !p.warnings.is_empty() {
            ui.collapsing(format!("{} coverage diagnostics", p.warnings.len()), |ui| {
                for w in &p.warnings {
                    ui.label(w);
                }
            });
        }
        if !self.browser.error.is_empty() {
            ui.colored_label(MUTED, &self.browser.error);
        }
        ui.separator();
    }
    pub(super) fn index_functions(&mut self, ctx: &egui::Context) {
        egui::SidePanel::left("functions")
            .default_width(315.0)
            .min_width(230.0)
            .resizable(true)
            .show(ctx, |ui| {
                ui.heading(format!(
                    "Functions ({})",
                    self.index_progress.counts.functions
                ));
                if ui
                    .add(
                        egui::TextEdit::singleline(&mut self.browser.function_query)
                            .hint_text("Name / alias / address")
                            .desired_width(f32::INFINITY),
                    )
                    .changed()
                {
                    self.browser.function_cursors = vec![None];
                    self.browser.invalidate();
                }
                ui.horizontal(|ui| {
                    if ui
                        .add_enabled(
                            self.browser.function_cursors.len() > 1,
                            egui::Button::new("◀"),
                        )
                        .clicked()
                    {
                        self.browser.function_cursors.pop();
                        self.browser.invalidate();
                    }
                    ui.label(format!("Page {}", self.browser.function_cursors.len()));
                    if ui
                        .add_enabled(
                            self.browser.page.functions.len() == PAGE,
                            egui::Button::new("▶"),
                        )
                        .clicked()
                    {
                        let cursor = self.browser.page.functions.last().map(|f| f.address);
                        self.browser.function_cursors.push(cursor);
                        self.browser.invalidate();
                    }
                });
                ui.separator();
                let mut navigate = None;
                let mut refs = None;
                egui::ScrollArea::vertical()
                    .id_salt("indexed-functions")
                    .show_rows(ui, 23.0, self.browser.page.functions.len(), |ui, range| {
                        for i in range {
                            let f = &self.browser.page.functions[i];
                            let name = if f.confidence <= 1 {
                                format!("? {}", f.name)
                            } else {
                                f.name.clone()
                            };
                            let response = ui.add_sized(
                                [ui.available_width(), 23.0],
                                egui::Button::new(
                                    RichText::new(format!("{:08X}  {name}", f.address)).monospace(),
                                )
                                .selected(self.address == f.address)
                                .truncate()
                                .frame(false),
                            );
                            if response.clicked() {
                                navigate = Some(f.address);
                            }
                            response.context_menu(|ui| {
                                if ui.button("Incoming references  X").clicked() {
                                    refs = Some(f.address);
                                    ui.close_menu();
                                }
                            });
                            response.on_hover_text(format!(
                                "Size: {}\nSource: {}\nEvidence level: {}\nAliases: {}",
                                if f.size == 0 {
                                    "?".into()
                                } else {
                                    format!("0x{:X}", f.size)
                                },
                                f.source,
                                f.confidence,
                                self.browser
                                    .page
                                    .aliases
                                    .get(&f.address)
                                    .map(|a| a.join("\n"))
                                    .unwrap_or_default()
                            ));
                        }
                    });
                if self.browser.page.functions.is_empty() {
                    ui.label(if self.index_progress.running {
                        "Discovering functions…"
                    } else {
                        "No functions match this page. See indexing status."
                    });
                }
                if let Some(va) = navigate {
                    self.initial_navigated = true;
                    self.navigate(va, ctx, true);
                    self.browser.invalidate();
                }
                if let Some(va) = refs {
                    self.show_xrefs(va, va.saturating_add(1), ctx);
                }
            });
    }
    pub(super) fn index_strings(&mut self, ui: &mut egui::Ui, ctx: &egui::Context) {
        self.coverage(ui);
        ui.label(format!(
            "{} strings · Double-click address for Hex · Xrefs includes interior addresses",
            self.index_progress.counts.strings
        ));
        if ui
            .add(
                egui::TextEdit::singleline(&mut self.browser.string_query)
                    .hint_text("Search text")
                    .desired_width(f32::INFINITY),
            )
            .changed()
        {
            self.browser.string_cursors = vec![None];
            self.browser.invalidate();
        }
        ui.horizontal(|ui| {
            if ui
                .add_enabled(
                    self.browser.string_cursors.len() > 1,
                    egui::Button::new("Previous"),
                )
                .clicked()
            {
                self.browser.string_cursors.pop();
                self.browser.invalidate();
            }
            ui.label(format!("Page {}", self.browser.string_cursors.len()));
            if ui
                .add_enabled(
                    self.browser.page.strings.len() == PAGE,
                    egui::Button::new("Next"),
                )
                .clicked()
            {
                self.browser.string_cursors.push(
                    self.browser
                        .page
                        .strings
                        .last()
                        .map(|s| (s.address, s.encoding.clone())),
                );
                self.browser.invalidate();
            }
        });
        let mut jump = None;
        let mut refs = None;
        egui::ScrollArea::both().id_salt("strings").show_rows(
            ui,
            24.0,
            self.browser.page.strings.len(),
            |ui, range| {
                for i in range {
                    let s = &self.browser.page.strings[i];
                    ui.horizontal(|ui| {
                        if ui.link(format!("{:016X}", s.address)).double_clicked() {
                            jump = Some(s.address);
                        }
                        if ui.small_button("Xrefs").clicked() {
                            refs = Some((s.address, s.end));
                        }
                        ui.label(RichText::new(&s.encoding).color(MUTED));
                        ui.label(
                            RichText::new(format!(
                                "{}{}",
                                s.text.escape_debug(),
                                if s.truncated {
                                    " … [preview/extent limited]"
                                } else {
                                    ""
                                }
                            ))
                            .monospace()
                            .color(GREEN),
                        )
                        .on_hover_text(format!(
                            "{}\n{} bytes",
                            s.source,
                            s.end - s.address
                        ));
                    });
                }
            },
        );
        if let Some(va) = jump {
            self.navigate_hex(va, ctx);
        }
        if let Some((va, end)) = refs {
            self.show_xrefs(va, end, ctx);
        }
    }
    pub(super) fn index_xrefs(&mut self, ui: &mut egui::Ui, ctx: &egui::Context) {
        self.coverage(ui);
        ui.horizontal(|ui| {
            ui.label(
                RichText::new(format!(
                    "0x{:X} .. 0x{:X}",
                    self.browser.xref_address, self.browser.xref_end
                ))
                .monospace(),
            );
            if ui
                .selectable_label(self.browser.incoming, "Incoming")
                .clicked()
            {
                self.browser.incoming = true;
                self.browser.xref_cursors = vec![None];
                self.browser.invalidate();
            }
            if ui
                .selectable_label(!self.browser.incoming, "Outgoing")
                .clicked()
            {
                self.browser.incoming = false;
                self.browser.xref_cursors = vec![None];
                self.browser.invalidate();
            }
            if ui.button("Current address").clicked() {
                self.show_xrefs(self.address, self.address.saturating_add(1), ctx);
            }
        });
        ui.label(RichText::new("Incoming coverage depends on all source ranges. Indirect targets can remain unresolved; local data-flow edges retain candidate evidence.").small().color(MUTED));
        ui.horizontal(|ui| {
            if ui
                .add_enabled(
                    self.browser.xref_cursors.len() > 1,
                    egui::Button::new("Previous"),
                )
                .clicked()
            {
                self.browser.xref_cursors.pop();
                self.browser.invalidate();
            }
            if ui
                .add_enabled(
                    self.browser.page.xrefs.len() == PAGE,
                    egui::Button::new("Next"),
                )
                .clicked()
            {
                self.browser.xref_cursors.push(
                    self.browser
                        .page
                        .xrefs
                        .last()
                        .map(|x| (x.from, x.to, x.kind.clone())),
                );
                self.browser.invalidate();
            }
        });
        let mut jump = None;
        let mut follow = None;
        egui::ScrollArea::both().id_salt("xrefs").show_rows(
            ui,
            25.0,
            self.browser.page.xrefs.len(),
            |ui, range| {
                for i in range {
                    let x = &self.browser.page.xrefs[i];
                    ui.horizontal(|ui| {
                        if ui
                            .link(format!("{:016X}", x.from))
                            .on_hover_text(
                                self.browser
                                    .page
                                    .labels
                                    .get(&x.from)
                                    .map(String::as_str)
                                    .unwrap_or("Function ownership unknown"),
                            )
                            .clicked()
                        {
                            jump = Some(x.from);
                        }
                        ui.label(&x.kind);
                        if x.kind == "unresolved-indirect" {
                            ui.label("unresolved");
                        } else {
                            if ui.link(format!("{:016X}", x.to)).clicked() {
                                jump = Some(x.to);
                            }
                            if ui.small_button("Follow refs").clicked() {
                                follow = Some(x.to);
                            }
                        }
                        if let Some(label) = self.browser.page.labels.get(&x.to) {
                            ui.label(RichText::new(label).color(GREEN));
                        }
                        ui.label(format!("evidence {}", x.confidence))
                            .on_hover_text(&x.evidence);
                    });
                }
            },
        );
        if self.browser.page.xrefs.is_empty() {
            ui.label(if self.index_progress.running {
                "No references in this page yet — scanning continues."
            } else {
                "No indexed references in this page; review coverage and unresolved targets above."
            });
        }
        if let Some(va) = jump {
            if self.engine.as_ref().is_some_and(|e| e.image.executable(va)) {
                self.navigate(va, ctx, true);
            } else {
                self.navigate_hex(va, ctx);
            }
            self.browser.invalidate();
        }
        if let Some(va) = follow {
            self.show_xrefs(va, va.saturating_add(1), ctx);
        }
    }
    pub(super) fn index_symbols(&mut self, ui: &mut egui::Ui, ctx: &egui::Context) {
        self.coverage(ui);
        ui.label(if self.tab==Tab::Imports{"Imports: addresses are relocation slots; follow references to see loads and dispatches."}else{"Exports: defined symbols; function aliases are preserved."});
        if ui
            .text_edit_singleline(&mut self.browser.symbol_query)
            .changed()
        {
            self.browser.symbol_offset = 0;
            self.browser.invalidate();
        }
        ui.horizontal(|ui| {
            if ui
                .add_enabled(
                    self.browser.symbol_offset > 0,
                    egui::Button::new("Previous"),
                )
                .clicked()
            {
                self.browser.symbol_offset = self.browser.symbol_offset.saturating_sub(PAGE);
                self.browser.invalidate();
            }
            if ui
                .add_enabled(
                    self.browser.page.symbols.len() == PAGE,
                    egui::Button::new("Next"),
                )
                .clicked()
            {
                self.browser.symbol_offset += PAGE;
                self.browser.invalidate();
            }
        });
        let mut jump = None;
        let mut refs = None;
        egui::ScrollArea::both().id_salt("symbols").show_rows(
            ui,
            24.0,
            self.browser.page.symbols.len(),
            |ui, range| {
                for i in range {
                    let s = &self.browser.page.symbols[i];
                    ui.horizontal(|ui| {
                        if ui.link(format!("{:016X}", s.address)).clicked() {
                            jump = Some(s.address);
                        }
                        if ui.small_button("Xrefs").clicked() {
                            refs = Some(s.address);
                        }
                        ui.label(RichText::new(&s.name).monospace())
                            .on_hover_text(&s.source);
                    });
                }
            },
        );
        if let Some(va) = jump {
            if self.tab == Tab::Imports {
                self.navigate_hex(va, ctx);
            } else {
                self.navigate(va, ctx, true);
            }
        }
        if let Some(va) = refs {
            self.show_xrefs(va, va.saturating_add(1), ctx);
        }
    }
}
