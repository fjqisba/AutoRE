// SPDX-License-Identifier: Apache-2.0
mod index_view;
use eframe::egui::{self, Color32, FontId, RichText, TextStyle};
use index_view::{Browser, BrowserPage};
use llmghidra_analysis::index::{IndexSession, Progress};
use llmghidra_analysis::{
    protocol::{self, Request},
    Analysis, Cancellation, ElfImage, Engine, Function, Instruction, Limits, WorkerPool,
};
use std::{
    path::PathBuf,
    sync::{
        mpsc::{channel, Receiver, Sender},
        Arc,
    },
    time::{Duration, Instant},
};

const BLUE: Color32 = Color32::from_rgb(0, 54, 154);
const GREEN: Color32 = Color32::from_rgb(0, 110, 73);
const MUTED: Color32 = Color32::from_rgb(108, 117, 130);
#[derive(Clone, Copy, PartialEq)]
enum Tab {
    Disassembly,
    Segments,
    Hex,
    Analysis,
    #[allow(dead_code)] // 旧本地请求面板保留，当前基础分析流程不依赖它。
    Agent,
    Strings,
    Xrefs,
    Imports,
    Exports,
}
enum Event {
    Open(llmghidra_analysis::Result<Arc<Engine>>, f64),
    Listing(u64, llmghidra_analysis::Result<Vec<Instruction>>),
    Analysis(u64, llmghidra_analysis::Result<Analysis>),
    Hex(u64, llmghidra_analysis::Result<Vec<u8>>),
    Agent(llmghidra_analysis::Result<serde_json::Value>),
    File(Option<PathBuf>),
    Saved(llmghidra_analysis::Result<()>),
    Browser(u64, llmghidra_analysis::Result<BrowserPage>),
    CacheFile(Option<PathBuf>),
    Restored(llmghidra_analysis::Result<Arc<IndexSession>>),
    IndexMerged(llmghidra_analysis::Result<()>),
}
pub struct Workbench {
    pool: WorkerPool,
    tx: Sender<(u64, Event)>,
    rx: Receiver<(u64, Event)>,
    generation: u64,
    cancel: Cancellation,
    engine: Option<Arc<Engine>>,
    functions: Vec<Function>,
    filtered: Vec<usize>,
    filter: String,
    listing: Vec<Instruction>,
    analysis: Option<Analysis>,
    hex: Vec<u8>,
    hex_address: u64,
    address: u64,
    address_text: String,
    history: Vec<u64>,
    history_index: usize,
    view_request: u64,
    analysis_request: u64,
    tab: Tab,
    logs: Vec<String>,
    status: String,
    pending: usize,
    indexing: bool,
    opening: bool,
    load_ms: f64,
    request_text: String,
    response_text: String,
    screenshot: Option<PathBuf>,
    screenshot_requested: bool,
    start: Instant,
    index_session: Option<Arc<IndexSession>>,
    index_progress: Progress,
    browser: Browser,
    initial_navigated: bool,
    start_view: Option<String>,
}
impl Workbench {
    pub fn new(
        cc: &eframe::CreationContext<'_>,
        path: Option<PathBuf>,
        screenshot: Option<PathBuf>,
        start_view: Option<String>,
    ) -> Self {
        let ctx = &cc.egui_ctx;
        let mut visuals = egui::Visuals::light();
        visuals.panel_fill = Color32::from_rgb(245, 246, 248);
        visuals.window_fill = Color32::WHITE;
        visuals.override_text_color = Some(Color32::from_rgb(32, 38, 48));
        visuals.selection.bg_fill = Color32::from_rgb(214, 230, 255);
        visuals.selection.stroke = egui::Stroke::new(1.0, BLUE);
        visuals.widgets.noninteractive.bg_stroke =
            egui::Stroke::new(1.0, Color32::from_rgb(203, 208, 216));
        ctx.set_visuals(visuals);
        let mut style = (*ctx.style()).clone();
        style.spacing.item_spacing = egui::vec2(6.0, 5.0);
        style
            .text_styles
            .insert(TextStyle::Body, FontId::proportional(13.0));
        style
            .text_styles
            .insert(TextStyle::Button, FontId::proportional(13.0));
        style
            .text_styles
            .insert(TextStyle::Monospace, FontId::monospace(13.0));
        ctx.set_style(style);
        // 有中文符号名时提供本机字体回退；没有字体不影响启动。
        if let Ok(data) = std::fs::read("C:/Windows/Fonts/msyh.ttc") {
            let mut fonts = egui::FontDefinitions::default();
            fonts
                .font_data
                .insert("cjk".into(), egui::FontData::from_owned(data).into());
            for family in [egui::FontFamily::Proportional, egui::FontFamily::Monospace] {
                fonts.families.entry(family).or_default().push("cjk".into());
            }
            ctx.set_fonts(fonts);
        }
        let (tx, rx) = channel();
        let mut app=Self {pool:WorkerPool::default(),tx,rx,generation:0,cancel:Cancellation::default(),engine:None,
            functions:vec![],filtered:vec![],filter:String::new(),listing:vec![],analysis:None,hex:vec![],hex_address:0,
            address:0,address_text:String::new(),history:vec![],history_index:0,view_request:0,analysis_request:0,tab:Tab::Disassembly,
            logs:vec!["LLMGhidra | Native ELF / AArch64 | automatic baseline indexing".into(),"Ready. Functions, strings and references appear automatically after opening.".into()],status:"No file loaded".into(),pending:0,indexing:false,opening:false,load_ms:0.0,
            request_text:"{\"id\":1,\"method\":\"analyze\",\"address\":\"0x1000\",\"limits\":{\"instructions\":4096,\"milliseconds\":750}}".into(),response_text:String::new(),
            screenshot,screenshot_requested:false,start:Instant::now(),index_session:None,index_progress:Progress::default(),browser:Browser::default(),initial_navigated:false,start_view};
        if let Some(path) = path {
            app.open(path, ctx);
        }
        app
    }
    fn log(&mut self, message: impl Into<String>) {
        self.logs.push(message.into());
        if self.logs.len() > 200 {
            self.logs.remove(0);
        }
    }
    fn submit(&mut self, ctx: &egui::Context, job: impl FnOnce() -> Event + Send + 'static) {
        let tx = self.tx.clone();
        let generation = self.generation;
        let ctx = ctx.clone();
        match self.pool.submit(move || {
            let event = job();
            let _ = tx.send((generation, event));
            ctx.request_repaint();
        }) {
            Ok(()) => self.pending += 1,
            Err(e) => {
                self.status = e.clone();
                self.log(e);
            }
        }
    }
    fn open(&mut self, path: PathBuf, ctx: &egui::Context) {
        if let Some(session) = self.index_session.take() {
            session.cancel();
        }
        self.browser = Browser::default();
        self.index_progress = Progress::default();
        self.initial_navigated = false;
        self.cancel.cancel();
        self.cancel = Cancellation::default();
        self.generation += 1;
        self.pending = 0;
        self.indexing = false;
        self.opening = true;
        self.engine = None;
        self.functions.clear();
        self.filtered.clear();
        self.listing.clear();
        self.analysis = None;
        self.hex.clear();
        self.history.clear();
        self.history_index = 0;
        self.status = format!("Opening {} ...", path.display());
        self.log(self.status.clone());
        self.submit(ctx, move || {
            let start = Instant::now();
            let result = ElfImage::open(path).map(|i| Arc::new(Engine::new(i)));
            Event::Open(result, start.elapsed().as_secs_f64() * 1000.0)
        });
    }
    fn pick_file(&mut self, ctx: &egui::Context) {
        self.submit(ctx, || {
            Event::File(
                rfd::FileDialog::new()
                    .add_filter("ELF / shared library", &["elf", "so", "bin"])
                    .add_filter("All files", &["*"])
                    .pick_file(),
            )
        });
    }
    fn refresh_filter(&mut self) {
        let query = self.filter.to_ascii_lowercase();
        self.filtered = self
            .functions
            .iter()
            .enumerate()
            .filter(|(_, f)| {
                query.is_empty()
                    || f.name.to_ascii_lowercase().contains(&query)
                    || format!("{:x}", f.address).contains(&query)
            })
            .map(|(i, _)| i)
            .collect();
    }
    fn merge_functions(&mut self, functions: Vec<Function>) {
        self.functions.extend(functions);
        self.functions.sort_by_key(|f| f.address);
        self.functions
            .dedup_by(|a, b| a.address == b.address && a.name == b.name);
        self.refresh_filter();
    }
    fn navigate(&mut self, address: u64, ctx: &egui::Context, record: bool) {
        self.initial_navigated = true;
        self.browser.invalidate();
        let Some(engine) = self.engine.clone() else {
            return;
        };
        if engine.image.segment_at(address).is_none() {
            self.status = format!("Unmapped address: 0x{address:X}");
            self.log(self.status.clone());
            return;
        }
        if record {
            if !self.history.is_empty() {
                self.history.truncate(self.history_index + 1);
            }
            if self.history.last() != Some(&address) {
                self.history.push(address);
            }
            self.history_index = self.history.len().saturating_sub(1);
        }
        self.address = address;
        self.address_text = format!("{address:016X}");
        self.view_request += 1;
        let request = self.view_request;
        self.listing.clear();
        self.hex.clear();
        self.analysis = None;
        self.analysis_request += 1;
        self.request_text=format!("{{\"id\":1,\"method\":\"analyze\",\"address\":\"0x{address:x}\",\"limits\":{{\"instructions\":4096,\"milliseconds\":750}}}}");
        if engine.image.executable(address) && engine.image.machine == 183 {
            self.tab = Tab::Disassembly;
            let token = self.cancel.clone();
            self.submit(ctx, move || {
                Event::Listing(request, engine.disassemble(address, 256, &token))
            });
        } else {
            self.tab = Tab::Hex;
            self.request_hex(ctx);
        }
    }
    fn jump(&mut self, ctx: &egui::Context) {
        match protocol::parse_address(&serde_json::Value::String(
            self.address_text.trim().to_string(),
        )) {
            Ok(a) => self.navigate(a, ctx, true),
            Err(e) => {
                self.status = e;
            }
        }
    }
    fn request_hex(&mut self, ctx: &egui::Context) {
        if let Some(engine) = self.engine.clone() {
            self.hex.clear();
            let address = self.address;
            self.hex_address = address;
            let req = self.view_request;
            let size = engine
                .image
                .segment_at(address)
                .map_or(0, |s| (s.end() - address).min(1024) as usize);
            self.submit(ctx, move || {
                Event::Hex(req, engine.image.read_virtual(address, size))
            });
        }
    }
    fn navigate_hex(&mut self, address: u64, ctx: &egui::Context) {
        // 与反汇编跳转共用代次和历史，防止换页后显示旧地址的异步结果。
        if self
            .engine
            .as_ref()
            .is_none_or(|e| e.image.segment_at(address).is_none())
        {
            self.status = format!("Unmapped address: 0x{address:X}");
            return;
        }
        self.navigate(address, ctx, true);
        if self.tab != Tab::Hex {
            self.tab = Tab::Hex;
            self.request_hex(ctx);
        }
    }
    fn analyze(&mut self, ctx: &egui::Context) {
        if let Some(engine) = self.engine.clone() {
            let address = self.address;
            self.analysis_request += 1;
            let request = self.analysis_request;
            let token = self.cancel.clone();
            self.status = format!("Analyzing 0x{address:X} within request budget ...");
            self.submit(ctx, move || {
                Event::Analysis(request, engine.analyze(address, Limits::default(), &token))
            });
        }
    }
    fn agent(&mut self, ctx: &egui::Context) {
        let Some(engine) = self.engine.clone() else {
            return;
        };
        match serde_json::from_str::<Request>(&self.request_text) {
            Ok(request) => {
                let token = self.cancel.clone();
                self.submit(ctx, move || {
                    Event::Agent(protocol::execute(&engine, &request, &token))
                });
            }
            Err(e) => self.response_text = e.to_string(),
        }
    }
    fn poll(&mut self, ctx: &egui::Context) {
        let deadline = Instant::now() + Duration::from_millis(4);
        while Instant::now() < deadline {
            let Ok((generation, event)) = self.rx.try_recv() else {
                break;
            };
            if generation != self.generation {
                continue;
            }
            self.pending = self.pending.saturating_sub(1);
            match event {
                Event::Open(result, ms) => {
                    self.opening = false;
                    match result {
                        Ok(engine) => {
                            self.load_ms = ms;
                            let meta = engine.image.metadata();
                            self.functions = engine.image.seed_functions();
                            self.refresh_filter();
                            self.status = format!(
                                "ELF{} | {} bytes | headers in {ms:.2} ms",
                                meta.bits, meta.file_size
                            );
                            self.log(format!(
                                "Opened {} | {:.2} ms | {} bytes read | {} program headers",
                                meta.path.display(),
                                ms,
                                meta.bytes_read,
                                meta.segments.len()
                            ));
                            self.log("Automatic function, string and reference indexing started; deep analysis remains on demand.");
                            ctx.send_viewport_cmd(egui::ViewportCommand::Title(format!(
                                "{} — LLMGhidra",
                                meta.path.file_name().unwrap_or_default().to_string_lossy()
                            )));
                            match IndexSession::new(engine.image.clone()) {
                                Ok(session) => {
                                    session.start();
                                    self.index_session = Some(session);
                                }
                                Err(error) => self.log(format!("Cannot start index: {error}")),
                            }
                            self.engine = Some(engine);
                            self.tab = Tab::Segments;
                        }
                        Err(e) => {
                            self.status = e.clone();
                            self.log(format!("Open failed: {e}"));
                        }
                    }
                }
                Event::Listing(request, result) => {
                    if request != self.view_request {
                        continue;
                    }
                    match result {
                        Ok(rows) => {
                            self.listing = rows;
                            self.status = format!(
                                "0x{:X} | {} instructions in current page",
                                self.address,
                                self.listing.len()
                            );
                        }
                        Err(e) => {
                            self.status = e.clone();
                            self.log(e);
                        }
                    }
                }
                Event::Analysis(request, result) => {
                    if request != self.analysis_request {
                        continue;
                    }
                    match result {
                        Ok(analysis) => {
                            if let Some(session) = self.index_session.clone() {
                                let local = analysis.clone();
                                let cancel = self.cancel.clone();
                                self.submit(ctx, move || {
                                    Event::IndexMerged(session.merge_analysis(&local, &cancel))
                                });
                            }
                            self.log(format!(
                                "Analysis 0x{:X}: {} instructions, {} blocks, {:.2} ms{}",
                                analysis.entry,
                                analysis.instructions.len(),
                                analysis.blocks.len(),
                                analysis.elapsed_ms,
                                if analysis.partial { " [partial]" } else { "" }
                            ));
                            self.merge_functions(analysis.functions.clone());
                            self.status = format!(
                                "Local analysis: {} blocks / {} instructions",
                                analysis.blocks.len(),
                                analysis.instructions.len()
                            );
                            self.analysis = Some(analysis);
                            self.tab = Tab::Analysis;
                        }
                        Err(e) => {
                            self.status = e.clone();
                            self.log(e);
                        }
                    }
                }
                Event::Hex(request, result) => {
                    if request != self.view_request {
                        continue;
                    }
                    match result {
                        Ok(bytes) => self.hex = bytes,
                        Err(e) => {
                            self.status = e.clone();
                            self.log(e);
                        }
                    }
                }
                Event::Agent(result) => {
                    self.response_text = match result {
                        Ok(value) => serde_json::to_string_pretty(&value).unwrap_or_default(),
                        Err(error) => format!("{{\"error\":{}}}", serde_json::json!(error)),
                    };
                }
                Event::File(Some(path)) => self.open(path, ctx),
                Event::File(None) => (),
                Event::Saved(result) => self.log(match result {
                    Ok(()) => "Analysis exported".into(),
                    Err(e) => e,
                }),
                Event::Browser(epoch, result) => {
                    self.browser.busy = false;
                    if epoch != self.browser.epoch {
                        self.browser.dirty = true;
                        continue;
                    }
                    match result {
                        Ok(page) => {
                            self.browser.page = page;
                            self.browser.error.clear();
                        }
                        Err(e) => {
                            self.browser.error = e;
                            self.browser.dirty = self.index_progress.running;
                        }
                    }
                }
                Event::CacheFile(Some(path)) => {
                    self.cancel_tasks();
                    self.index_session = None;
                    self.engine = None;
                    self.browser = Browser::default();
                    self.initial_navigated = false;
                    self.listing.clear();
                    self.history.clear();
                    self.history_index = 0;
                    self.index_progress = Progress::default();
                    self.status = "Verifying cached source fingerprint…".into();
                    let cancel = self.cancel.clone();
                    self.submit(ctx, move || {
                        Event::Restored(IndexSession::restore(path, &cancel))
                    });
                }
                Event::CacheFile(None) => (),
                Event::Restored(result) => match result {
                    Ok(session) => {
                        self.engine = Some(Arc::new(Engine::from_image(session.image.clone())));
                        self.index_progress = session.progress();
                        self.index_session = Some(session);
                        self.status = "Verified index restored".into();
                        self.browser.invalidate();
                    }
                    Err(error) => {
                        self.status = error.clone();
                        self.log(error);
                    }
                },
                Event::IndexMerged(result) => {
                    if let Err(error) = result {
                        self.log(format!("Local analysis index update: {error}"));
                    }
                    self.browser.invalidate();
                }
            }
        }
    }
    fn cancel_tasks(&mut self) {
        if let Some(session) = &self.index_session {
            session.cancel();
        }
        self.browser.busy = false;
        self.browser.dirty = true;
        self.cancel.cancel();
        self.cancel = Cancellation::default();
        self.generation += 1;
        self.pending = 0;
        self.indexing = false;
        self.opening = false;
        self.log("Pending analysis requests cancelled. Existing results retained.");
    }
    fn export(&mut self, ctx: &egui::Context) {
        if let Some(analysis) = self.analysis.as_ref() {
            let json = serde_json::to_string_pretty(analysis).unwrap_or_default();
            self.submit(ctx, move || {
                if let Some(path) = rfd::FileDialog::new()
                    .set_file_name("analysis.json")
                    .save_file()
                {
                    Event::Saved(std::fs::write(path, json).map_err(|e| e.to_string()))
                } else {
                    Event::Saved(Ok(()))
                }
            });
        }
    }
    fn header(&mut self, ctx: &egui::Context) {
        egui::TopBottomPanel::top("menu-toolbar").show(ctx,|ui|{
            egui::menu::bar(ui,|ui|{
                ui.menu_button("File",|ui|{
                    if ui.button("Open ELF...     Ctrl+O").clicked(){self.pick_file(ctx);ui.close_menu();}
                    if ui.button("Open verified analysis cache...").clicked(){self.submit(ctx,||Event::CacheFile(rfd::FileDialog::new().add_filter("Analysis cache",&["sqlite"]).pick_file()));ui.close_menu();}
                    if ui.button("Copy analysis cache path").clicked(){if let Some(session)=&self.index_session{ctx.copy_text(session.path.display().to_string());}ui.close_menu();}
                    if ui.add_enabled(self.analysis.is_some(),egui::Button::new("Export analysis JSON...")).clicked(){self.export(ctx);ui.close_menu();}
                    if ui.button("Exit").clicked(){ctx.send_viewport_cmd(egui::ViewportCommand::Close);}
                });
                ui.menu_button("View",|ui|{for (tab,name) in [(Tab::Disassembly,"Disassembly"),(Tab::Segments,"Segments"),(Tab::Hex,"Hex dump"),(Tab::Analysis,"Function analysis"),(Tab::Strings,"Strings"),(Tab::Xrefs,"Xrefs"),(Tab::Imports,"Imports"),(Tab::Exports,"Exports")] {if ui.button(name).clicked(){self.tab=tab;self.browser.invalidate();if tab==Tab::Hex{self.request_hex(ctx);}ui.close_menu();}}});
                ui.menu_button("Jump",|ui|{if ui.button("Entry point").clicked(){if let Some(engine)=self.engine.as_ref(){self.navigate(engine.image.initial_address(),ctx,true);}ui.close_menu();}});
                ui.menu_button("Analyze",|ui|{
                    if ui.button("Current address     F5").clicked(){self.analyze(ctx);ui.close_menu();}
                    if ui.button("Resume automatic indexing").clicked(){if let Some(session)=&self.index_session{session.start();}ui.close_menu();}
                    if ui.button("Cancel pending tasks").clicked(){self.cancel_tasks();ui.close_menu();}
                });
                ui.menu_button("Help",|ui|{ui.label("AArch64 ELF • Native Rust / egui");ui.label("F5: analyze  |  X: references  |  G: address  |  Alt+Left/Right: history");ui.label("Addresses are ELF virtual addresses (before ASLR).");ui.label("Functions, strings and references are indexed automatically. Deep analysis runs on demand.");});
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center),|ui|{ui.label(RichText::new("LLMGhidra").strong().color(BLUE));ui.label(RichText::new("AI WORKBENCH").small().color(MUTED));});
            });
            ui.separator();
            ui.horizontal(|ui|{
                if ui.button("Open").clicked(){self.pick_file(ctx);}ui.separator();
                if ui.add_enabled(self.history_index>0,egui::Button::new("◀")).clicked(){self.history_index-=1;self.navigate(self.history[self.history_index],ctx,false);}
                if ui.add_enabled(self.history_index+1<self.history.len(),egui::Button::new("▶")).clicked(){self.history_index+=1;self.navigate(self.history[self.history_index],ctx,false);}
                ui.label("Address");let jump=ui.add(egui::TextEdit::singleline(&mut self.address_text).font(TextStyle::Monospace).desired_width(165.0).id(egui::Id::new("address-field")));
                if jump.lost_focus() && ui.input(|i|i.key_pressed(egui::Key::Enter)) {self.jump(ctx);}
                if ui.button("Go").clicked(){self.jump(ctx);}ui.separator();
                if ui.add_enabled(self.engine.is_some(),egui::Button::new("Analyze  F5")).clicked(){self.analyze(ctx);}
                if ui.add_enabled(self.engine.is_some(),egui::Button::new("Xrefs  X")).clicked(){self.show_xrefs(self.address,self.address.saturating_add(1),ctx);}
                if ui.add_enabled(self.index_session.is_some()&&!self.index_progress.running,egui::Button::new("Resume index")).clicked(){if let Some(session)=&self.index_session{session.start();}}
                if ui.add_enabled(self.pending>0||self.index_progress.running,egui::Button::new("Pause / Cancel")).clicked(){self.cancel_tasks();}
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center),|ui|{ui.label(RichText::new(format!("{} workers  •  {} pending",self.pool.threads,self.pending)).color(MUTED));if self.pending>0{ui.spinner();}});
            });
            ui.add_space(3.0);self.segment_strip(ui,ctx);
        });
    }
    fn segment_strip(&mut self, ui: &mut egui::Ui, ctx: &egui::Context) {
        let (rect, response) =
            ui.allocate_exact_size(egui::vec2(ui.available_width(), 18.0), egui::Sense::click());
        ui.painter()
            .rect_filled(rect, 0.0, Color32::from_rgb(223, 227, 232));
        let Some(engine) = self.engine.as_ref() else {
            return;
        };
        let loads: Vec<_> = engine
            .image
            .segments
            .iter()
            .filter(|s| s.loadable() && s.memory_size > 0)
            .collect();
        let total = loads.iter().map(|s| s.memory_size as f64).sum::<f64>();
        if total == 0.0 {
            return;
        }
        let mut x = rect.left();
        let mut selected = None;
        for segment in loads {
            let width = (segment.memory_size as f64 / total * rect.width() as f64) as f32;
            let r = egui::Rect::from_min_size(
                egui::pos2(x, rect.top()),
                egui::vec2(width.max(1.0), rect.height()),
            );
            let color = if segment.executable() {
                Color32::from_rgb(91, 126, 184)
            } else if segment.flags & 2 != 0 {
                Color32::from_rgb(154, 189, 141)
            } else {
                Color32::from_rgb(181, 172, 197)
            };
            ui.painter().rect_filled(r.shrink(1.0), 0.0, color);
            if self.address >= segment.address && self.address < segment.end() {
                let at = x
                    + ((self.address - segment.address) as f64 / segment.memory_size as f64
                        * width as f64) as f32;
                ui.painter().line_segment(
                    [egui::pos2(at, r.top()), egui::pos2(at, r.bottom())],
                    egui::Stroke::new(2.0, Color32::from_rgb(220, 70, 50)),
                );
            }
            if response.clicked()
                && response
                    .interact_pointer_pos()
                    .is_some_and(|p| r.contains(p))
            {
                selected = Some(segment.address);
            }
            x += width;
        }
        response.on_hover_text("PT_LOAD map: blue = executable, green = writable, purple = read-only. Click a segment to jump.");
        if let Some(address) = selected {
            self.navigate(address, ctx, true);
        }
    }
    fn functions(&mut self, ctx: &egui::Context) {
        self.index_functions(ctx);
    }
    #[allow(dead_code)]
    fn legacy_functions(&mut self, ctx: &egui::Context) {
        egui::SidePanel::left("functions").default_width(280.0).min_width(210.0).resizable(true).show(ctx,|ui|{
            ui.horizontal(|ui|{ui.label(RichText::new("Functions").strong());ui.with_layout(egui::Layout::right_to_left(egui::Align::Center),|ui|{ui.label(RichText::new(self.functions.len().to_string()).color(MUTED));});});
            if ui.add(egui::TextEdit::singleline(&mut self.filter).hint_text("Filter name or address...").desired_width(f32::INFINITY)).changed(){self.refresh_filter();}
            ui.horizontal(|ui|{ui.label(RichText::new("Name").small().color(MUTED));ui.with_layout(egui::Layout::right_to_left(egui::Align::Center),|ui|{ui.label(RichText::new("Address").small().color(MUTED));});});ui.separator();
            let mut clicked=None;
            egui::ScrollArea::vertical().id_salt("function-list").auto_shrink([false,false]).show_rows(ui,22.0,self.filtered.len(),|ui,range|{
                for row in range {let function=&self.functions[self.filtered[row]];
                    let selected=function.address==self.address;
                    let response=ui.horizontal(|ui| {
                        let width=(ui.available_width()-90.0).max(90.0);
                        let response=ui.add_sized([width,22.0],egui::Button::new(RichText::new(&function.name).color(if selected{BLUE}else{Color32::from_rgb(42,53,66)})).selected(selected));
                        if ui.add(egui::Label::new(RichText::new(format!("{:08X}",function.address)).monospace().color(MUTED)).sense(egui::Sense::click())).clicked(){clicked=Some(function.address);}
                        response
                    }).inner;
                    if response.clicked(){clicked=Some(function.address);}
                    response.on_hover_text(format!("0x{:016X}\nSize: {}\nSource: {}",function.address,function.size,function.source));
                }
            });
            if self.functions.is_empty(){ui.label(RichText::new("No function seeds yet.").color(MUTED));ui.label("Index ELF symbols, jump to an executable address, or let local analysis discover call targets.");}
            if let Some(address)=clicked{self.navigate(address,ctx,true);}
        });
    }
    fn bottom(&mut self, ctx: &egui::Context) {
        egui::TopBottomPanel::bottom("status").show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.label(
                    RichText::new(format!(
                        "F {} · S {} · X {}",
                        self.index_progress.counts.functions,
                        self.index_progress.counts.strings,
                        self.index_progress.counts.xrefs
                    ))
                    .small()
                    .color(BLUE),
                );
                ui.label(RichText::new(&self.status).small());
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if let Some(engine) = &self.engine {
                        ui.label(
                            RichText::new(format!(
                                "I/O {} KiB  |  open {:.2} ms  |  ELF VA",
                                engine.image.bytes_read() / 1024,
                                self.load_ms
                            ))
                            .small()
                            .color(MUTED),
                        );
                    }
                });
            });
        });
        egui::TopBottomPanel::bottom("output")
            .default_height(125.0)
            .height_range(60.0..=300.0)
            .resizable(true)
            .show(ctx, |ui| {
                ui.horizontal(|ui| {
                    ui.label(RichText::new("Output").strong());
                    ui.separator();
                    ui.label(
                        RichText::new(&self.index_progress.phase)
                            .small()
                            .color(MUTED),
                    );
                });
                ui.separator();
                egui::ScrollArea::vertical()
                    .stick_to_bottom(true)
                    .show(ui, |ui| {
                        for line in &self.logs {
                            ui.label(RichText::new(line).monospace().size(12.0));
                        }
                    });
            });
    }
    fn center(&mut self, ctx: &egui::Context) {
        egui::CentralPanel::default()
            .frame(egui::Frame::central_panel(&ctx.style()).fill(Color32::WHITE))
            .show(ctx, |ui| {
                ui.horizontal(|ui| {
                    for (tab, name) in [
                        (Tab::Disassembly, "IDA View-A"),
                        (Tab::Segments, "Segments"),
                        (Tab::Hex, "Hex View-1"),
                        (Tab::Analysis, "Function analysis"),
                        (Tab::Strings, "Strings"),
                        (Tab::Xrefs, "Xrefs"),
                        (Tab::Imports, "Imports"),
                        (Tab::Exports, "Exports"),
                    ] {
                        if ui.selectable_label(self.tab == tab, name).clicked() {
                            self.tab = tab;
                            self.browser.invalidate();
                            if tab == Tab::Hex {
                                self.request_hex(ctx);
                            }
                        }
                    }
                });
                ui.separator();
                if self.engine.is_none() {
                    self.welcome(ui, ctx);
                    return;
                }
                match self.tab {
                    Tab::Disassembly => self.disassembly(ui, ctx),
                    Tab::Segments => self.segments(ui, ctx),
                    Tab::Hex => self.hex_view(ui, ctx),
                    Tab::Analysis => self.analysis_view(ui, ctx),
                    Tab::Agent => self.agent_view(ui, ctx),
                    Tab::Strings => self.index_strings(ui, ctx),
                    Tab::Xrefs => self.index_xrefs(ui, ctx),
                    Tab::Imports | Tab::Exports => self.index_symbols(ui, ctx),
                }
            });
    }
    fn welcome(&mut self, ui: &mut egui::Ui, ctx: &egui::Context) {
        ui.add_space(65.0);
        ui.horizontal(|ui| {
            ui.add_space(45.0);
            ui.vertical(|ui| {
                ui.label(RichText::new("LLMGhidra").size(36.0).strong().color(BLUE));
                ui.add_space(8.0);
                ui.label(RichText::new("Open. Discover. Follow references.").size(22.0));
                ui.add_space(20.0);
                ui.label("Native ELF workspace for Android / AArch64 and AI agents.");
                ui.label(
                    "Functions, strings and references index automatically. Deep analysis runs on demand.",
                );
                ui.add_space(25.0);
                if ui
                    .add_sized([160.0, 35.0], egui::Button::new("Open ELF / SO"))
                    .clicked()
                {
                    self.pick_file(ctx);
                }
                ui.add_space(18.0);
                ui.label(
                    RichText::new("Drop a file anywhere  •  Ctrl+O to open  •  F5 to analyze")
                        .color(MUTED),
                );
                if self.opening {
                    ui.horizontal(|ui| {
                        ui.spinner();
                        ui.label("Reading ELF headers...");
                    });
                }
            });
        });
    }
    fn disassembly(&mut self, ui: &mut egui::Ui, ctx: &egui::Context) {
        ui.horizontal(|ui| {
            let name = self
                .browser
                .page
                .labels
                .get(&self.address)
                .cloned()
                .unwrap_or_else(|| format!("loc_{:X}", self.address));
            ui.label(RichText::new(format!("; {name}")).monospace().color(GREEN));
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if ui.button("Next page ▶").clicked() {
                    if let Some(next) = self.address.checked_add(256 * 4) {
                        self.navigate(next, ctx, true);
                    }
                }
                if ui.button("◀ Previous page").clicked() {
                    self.navigate(self.address.saturating_sub(256 * 4), ctx, true);
                }
            });
        });
        ui.horizontal(|ui| {
            ui.add_sized(
                [150.0, 18.0],
                egui::Label::new(RichText::new("Address").small().color(MUTED)),
            );
            ui.add_sized(
                [120.0, 18.0],
                egui::Label::new(RichText::new("Bytes").small().color(MUTED)),
            );
            ui.label(RichText::new("Instruction").small().color(MUTED));
        });
        let mut jump = None;
        let mut analyze_here = false;
        let mut xrefs_here = None;
        egui::ScrollArea::both()
            .id_salt(("asm", self.address))
            .auto_shrink([false, false])
            .show_rows(ui, 22.0, self.listing.len(), |ui, range| {
                for index in range {
                    let insn = &self.listing[index];
                    let color = match insn.flow.as_str() {
                        "call" => Color32::from_rgb(148, 53, 164),
                        "branch" | "conditional" | "return" | "indirect" => BLUE,
                        "invalid" => Color32::from_rgb(180, 55, 50),
                        _ => Color32::from_rgb(38, 42, 48),
                    };
                    ui.horizontal(|ui| {
                        ui.add_sized(
                            [150.0, 20.0],
                            egui::Label::new(
                                RichText::new(format!("{:016X}", insn.address))
                                    .monospace()
                                    .color(BLUE),
                            ),
                        );
                        ui.add_sized(
                            [120.0, 20.0],
                            egui::Label::new(RichText::new(&insn.bytes).monospace().color(MUTED)),
                        );
                        ui.add_sized(
                            [85.0, 20.0],
                            egui::Label::new(
                                RichText::new(&insn.mnemonic).monospace().color(color),
                            ),
                        );
                        let response = ui.add(
                            egui::Label::new(
                                RichText::new(&insn.operands).monospace().color(color),
                            )
                            .sense(egui::Sense::click()),
                        );
                        if response.double_clicked() {
                            jump = Some(insn.target.unwrap_or(insn.address));
                        }
                        response.context_menu(|ui| {
                            if ui.button("References to this instruction").clicked() {
                                xrefs_here = Some(insn.address);
                                ui.close_menu();
                            }
                            if let Some(target) = insn.target {
                                if ui.button("References to target").clicked() {
                                    xrefs_here = Some(target);
                                    ui.close_menu();
                                }
                            }
                            if ui.button("Analyze here").clicked() {
                                jump = Some(insn.address);
                                analyze_here = true;
                                ui.close_menu();
                            }
                            if let Some(target) = insn.target {
                                if ui.button(format!("Jump to 0x{target:X}")).clicked() {
                                    jump = Some(target);
                                    ui.close_menu();
                                }
                            }
                            if ui.button("Copy instruction").clicked() {
                                ui.ctx().copy_text(format!(
                                    "0x{:X}: {} {}",
                                    insn.address, insn.mnemonic, insn.operands
                                ));
                                ui.close_menu();
                            }
                        });
                        if let Some(text) = self.browser.page.comments.get(&insn.address) {
                            ui.label(RichText::new(text).monospace().color(GREEN));
                        }
                    });
                }
            });
        if self.listing.is_empty() {
            ui.label(
                RichText::new(
                    "No decoded instructions in this page. Select an executable AArch64 segment.",
                )
                .color(MUTED),
            );
        }
        if let Some(address) = jump {
            self.navigate(address, ctx, true);
            if analyze_here {
                self.analyze(ctx);
            }
        }
        if let Some(address) = xrefs_here {
            self.show_xrefs(address, address.saturating_add(1), ctx);
        }
    }
    fn segments(&mut self, ui: &mut egui::Ui, ctx: &egui::Context) {
        let Some(engine) = self.engine.clone() else {
            return;
        };
        let meta = engine.image.metadata();
        ui.label(
            RichText::new(format!(
                "ELF{} / {} / machine {} / entry 0x{:X}",
                meta.bits,
                if meta.little_endian {
                    "little endian"
                } else {
                    "big endian"
                },
                meta.machine,
                meta.entry
            ))
            .strong(),
        );
        ui.label(RichText::new("PT_LOAD defines the virtual address map. File size and memory size are independent; their difference is zero-filled BSS.").color(MUTED));
        ui.add_space(8.0);
        let mut selected = None;
        egui::ScrollArea::both().show(ui, |ui| {
            egui::Grid::new("segments-table")
                .striped(true)
                .min_col_width(72.0)
                .spacing([16.0, 10.0])
                .show(ui, |ui| {
                    for title in [
                        "#",
                        "Type",
                        "VA start",
                        "VA end",
                        "File offset",
                        "File bytes",
                        "Memory bytes",
                        "Perms",
                    ] {
                        ui.label(RichText::new(title).strong());
                    }
                    ui.end_row();
                    for s in &meta.segments {
                        ui.label(s.index.to_string());
                        ui.label(s.kind_name());
                        if ui.link(format!("{:016X}", s.address)).clicked() {
                            selected = Some(s.address);
                        }
                        ui.monospace(format!("{:016X}", s.end()));
                        ui.monospace(format!("{:X}", s.offset));
                        ui.monospace(format!("{:X}", s.file_size));
                        ui.monospace(format!("{:X}", s.memory_size));
                        ui.label(RichText::new(s.permissions()).color(if s.executable() {
                            BLUE
                        } else {
                            GREEN
                        }));
                        ui.end_row();
                    }
                });
        });
        if let Some(address) = selected {
            self.navigate(address, ctx, true);
        }
    }
    fn hex_view(&mut self, ui: &mut egui::Ui, ctx: &egui::Context) {
        ui.horizontal(|ui| {
            ui.label(
                RichText::new(format!("Virtual memory at 0x{:016X}", self.hex_address)).strong(),
            );
            if ui.button("Previous 1 KiB").clicked() {
                self.navigate_hex(self.address.saturating_sub(1024), ctx);
            }
            if ui.button("Next 1 KiB").clicked() {
                if let Some(a) = self.address.checked_add(1024) {
                    self.navigate_hex(a, ctx);
                }
            }
        });
        ui.separator();
        egui::ScrollArea::both().show(ui, |ui| {
            for (i, chunk) in self.hex.chunks(16).enumerate() {
                let bytes = chunk
                    .iter()
                    .map(|b| format!("{b:02X}"))
                    .collect::<Vec<_>>()
                    .join(" ");
                let ascii = chunk
                    .iter()
                    .map(|b| {
                        if b.is_ascii_graphic() {
                            *b as char
                        } else {
                            '.'
                        }
                    })
                    .collect::<String>();
                ui.label(
                    RichText::new(format!(
                        "{:016X}  {:47}  {}",
                        self.hex_address + i as u64 * 16,
                        bytes,
                        ascii
                    ))
                    .monospace()
                    .color(BLUE),
                );
            }
        });
    }
    fn analysis_view(&mut self, ui: &mut egui::Ui, ctx: &egui::Context) {
        if self.analysis.is_none() {
            ui.heading("Function analysis");
            ui.label("Request a bounded control-flow traversal at the current address.");
            ui.label(
                "Calls become function candidates; indirect branches remain explicitly unresolved.",
            );
            if ui.button("Analyze current address  F5").clicked() {
                self.analyze(ctx);
            }
            return;
        }
        let mut export = false;
        let mut jump = None;
        let analysis = self.analysis.as_ref().unwrap();
        ui.horizontal(|ui| {
            ui.label(
                RichText::new(format!("sub_{:X}", analysis.entry))
                    .size(18.0)
                    .strong()
                    .color(BLUE),
            );
            ui.label(format!(
                "{} instructions  /  {} blocks  /  {:.2} ms",
                analysis.instructions.len(),
                analysis.blocks.len(),
                analysis.elapsed_ms
            ));
            export = ui.button("Export JSON").clicked();
        });
        ui.label(
            RichText::new(if analysis.partial {
                "PARTIAL — some paths remain unexplored"
            } else {
                "Requested direct-flow traversal finished; indirect calls are not resolved"
            })
            .color(if analysis.partial {
                Color32::from_rgb(178, 102, 15)
            } else {
                GREEN
            }),
        );
        for reason in &analysis.reasons {
            ui.label(RichText::new(reason).color(MUTED));
        }
        ui.separator();
        egui::ScrollArea::vertical().show_rows(ui, 180.0, analysis.blocks.len(), |ui, rows| {
            for row in rows {
                let block = &analysis.blocks[row];
                let start = analysis
                    .instructions
                    .partition_point(|i| i.address < block.address);
                egui::Frame::group(ui.style())
                    .fill(Color32::from_rgb(248, 250, 254))
                    .show(ui, |ui| {
                        ui.set_min_height(160.0);
                        ui.horizontal(|ui| {
                            if ui
                                .link(
                                    RichText::new(format!("loc_{:X}", block.address))
                                        .monospace()
                                        .strong(),
                                )
                                .clicked()
                            {
                                jump = Some(block.address);
                            }
                            ui.label(
                                RichText::new(format!("{} instructions", block.instruction_count))
                                    .small()
                                    .color(MUTED),
                            );
                        });
                        for insn in analysis.instructions[start..]
                            .iter()
                            .take(block.instruction_count.min(4))
                        {
                            ui.label(
                                RichText::new(format!(
                                    "{:016X}  {:8} {}",
                                    insn.address, insn.mnemonic, insn.operands
                                ))
                                .monospace(),
                            );
                        }
                        if block.instruction_count > 4 {
                            ui.label(format!(
                                "... {} more instructions (available in JSON)",
                                block.instruction_count - 4
                            ));
                        }
                        for edge in analysis
                            .edges
                            .iter()
                            .filter(|e| e.from >= block.address && e.from < block.end)
                            .take(2)
                        {
                            ui.horizontal(|ui| {
                                ui.label(RichText::new(format!("{} →", edge.kind)).color(GREEN));
                                if let Some(target) = edge.to {
                                    if ui.link(format!("0x{target:X}")).clicked() {
                                        jump = Some(target);
                                    }
                                } else {
                                    ui.label("unresolved / exit");
                                }
                            });
                        }
                    });
                ui.add_space(8.0);
            }
        });
        if export {
            self.export(ctx);
        }
        if let Some(address) = jump {
            self.navigate(address, ctx, true);
        }
    }
    fn agent_view(&mut self, ui: &mut egui::Ui, ctx: &egui::Context) {
        ui.label(RichText::new("Agent request").strong());
        ui.label(RichText::new("metadata · segments · functions · read · disassemble · analyze  |  Same API available via --serve file.so").color(MUTED));
        ui.add(
            egui::TextEdit::multiline(&mut self.request_text)
                .font(TextStyle::Monospace)
                .desired_rows(4)
                .desired_width(f32::INFINITY),
        );
        ui.horizontal(|ui| {
            if ui.button("Execute request").clicked() {
                self.agent(ctx);
            }
            if ui.button("Copy response").clicked() {
                ctx.copy_text(self.response_text.clone());
            }
        });
        ui.separator();
        egui::ScrollArea::both().show(ui, |ui| {
            ui.add(
                egui::TextEdit::multiline(&mut self.response_text)
                    .font(TextStyle::Monospace)
                    .desired_width(f32::INFINITY)
                    .interactive(false),
            );
        });
    }
}
impl eframe::App for Workbench {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.poll(ctx);
        self.poll_index(ctx);
        if self.initial_navigated && !self.index_progress.running {
            if let Some(view) = self.start_view.take() {
                self.tab = match view.as_str() {
                    "strings" => Tab::Strings,
                    "imports" => Tab::Imports,
                    "exports" => Tab::Exports,
                    "xrefs" => Tab::Xrefs,
                    _ => Tab::Disassembly,
                };
                self.browser.invalidate();
            }
        }
        let dropped = ctx.input(|i| i.raw.dropped_files.iter().find_map(|f| f.path.clone()));
        if let Some(path) = dropped {
            self.open(path, ctx);
        }
        if ctx.input_mut(|i| i.consume_key(egui::Modifiers::CTRL, egui::Key::O)) {
            self.pick_file(ctx);
        }
        if ctx.input_mut(|i| i.consume_key(egui::Modifiers::NONE, egui::Key::F5)) {
            self.analyze(ctx);
        }
        if !ctx.wants_keyboard_input()
            && ctx.input_mut(|i| i.consume_key(egui::Modifiers::NONE, egui::Key::X))
        {
            self.show_xrefs(self.address, self.address.saturating_add(1), ctx);
        }
        if ctx.input_mut(|i| i.consume_key(egui::Modifiers::ALT, egui::Key::ArrowLeft))
            && self.history_index > 0
        {
            self.history_index -= 1;
            self.navigate(self.history[self.history_index], ctx, false);
        }
        if ctx.input_mut(|i| i.consume_key(egui::Modifiers::ALT, egui::Key::ArrowRight))
            && self.history_index + 1 < self.history.len()
        {
            self.history_index += 1;
            self.navigate(self.history[self.history_index], ctx, false);
        }
        if !ctx.wants_keyboard_input()
            && ctx.input_mut(|i| i.consume_key(egui::Modifiers::NONE, egui::Key::G))
        {
            ctx.memory_mut(|m| m.request_focus(egui::Id::new("address-field")));
        }
        self.header(ctx);
        self.bottom(ctx);
        self.functions(ctx);
        self.center(ctx);
        if let Some(path) = self.screenshot.as_ref() {
            if !self.screenshot_requested
                && self.pending == 0
                && !self.index_progress.running
                && !self.browser.busy
                && !self.browser.dirty
                && self.start.elapsed() > Duration::from_secs(2)
            {
                self.screenshot_requested = true;
                ctx.send_viewport_cmd(egui::ViewportCommand::Screenshot(egui::UserData::default()));
            }
            for event in ctx.input(|i| i.events.clone()) {
                if let egui::Event::Screenshot { image, .. } = event {
                    let bytes: Vec<u8> = image.pixels.iter().flat_map(|p| p.to_array()).collect();
                    let result = image::save_buffer(
                        path,
                        &bytes,
                        image.width() as u32,
                        image.height() as u32,
                        image::ColorType::Rgba8,
                    );
                    if let Err(e) = result {
                        eprintln!("screenshot failed: {e}");
                    }
                    ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                }
            }
            ctx.request_repaint_after(Duration::from_millis(100));
            if self.start.elapsed() > Duration::from_secs(30) {
                ctx.send_viewport_cmd(egui::ViewportCommand::Close);
            }
        }
    }
}
