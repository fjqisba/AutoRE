// SPDX-License-Identifier: Apache-2.0
//! 本地自动基础分析：有界结果通道、持久化事实、独立交互线程。
mod metadata;
mod scan;
pub mod store;
use crate::{Cancellation, ElfImage, Result};
use serde::{Deserialize, Serialize};
use std::{
    path::PathBuf,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    time::Instant,
};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FunctionFact {
    pub address: u64,
    pub size: u64,
    pub name: String,
    pub source: String,
    pub confidence: u8,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct XrefFact {
    pub from: u64,
    pub to: u64,
    pub kind: String,
    pub confidence: u8,
    pub evidence: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StringFact {
    pub address: u64,
    pub end: u64,
    pub encoding: String,
    pub text: String,
    pub truncated: bool,
    pub source: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SymbolFact {
    pub address: u64,
    pub name: String,
    pub kind: String,
    pub source: String,
}
#[derive(Default)]
pub(crate) struct FactBatch {
    pub functions: Vec<FunctionFact>,
    pub xrefs: Vec<XrefFact>,
    pub strings: Vec<StringFact>,
    pub symbols: Vec<SymbolFact>,
    pub checkpoint: Option<(String, u64)>,
    pub warnings: Vec<String>,
}
#[derive(Clone, Debug, Default, Serialize)]
pub struct Counts {
    pub functions: u64,
    pub xrefs: u64,
    pub strings: u64,
    pub imports: u64,
    pub exports: u64,
    pub candidates: u64,
    pub unresolved: u64,
}
#[derive(Clone, Debug, Default, Serialize)]
pub struct Progress {
    pub phase: String,
    pub counts: Counts,
    pub scanned: u64,
    pub total: u64,
    pub revision: u64,
    pub running: bool,
    pub complete: bool,
    pub warnings: Vec<String>,
    pub elapsed_ms: u64,
    pub preferred: Option<u64>,
    pub cache_path: PathBuf,
}
pub struct IndexSession {
    pub image: Arc<ElfImage>,
    pub path: PathBuf,
    progress: Mutex<Progress>,
    cancel: Mutex<Cancellation>,
    running: AtomicBool,
}
impl IndexSession {
    pub fn new(image: Arc<ElfImage>) -> Result<Arc<Self>> {
        let base = std::env::var_os("LOCALAPPDATA")
            .map(PathBuf::from)
            .unwrap_or_else(std::env::temp_dir)
            .join("LLMGhidra/analysis-cache");
        std::fs::create_dir_all(&base).map_err(|e| e.to_string())?;
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|e| e.to_string())?
            .as_nanos();
        let path = base.join(format!("index-{}-{stamp}.sqlite", std::process::id()));
        let progress = Progress {
            phase: "Opening analysis cache".into(),
            cache_path: path.clone(),
            ..Default::default()
        };
        Ok(Arc::new(Self {
            image,
            path,
            progress: Mutex::new(progress),
            cancel: Mutex::new(Cancellation::default()),
            running: AtomicBool::new(false),
        }))
    }
    pub fn progress(&self) -> Progress {
        self.progress
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }
    /// 显式重开缓存时先校验完整内容身份；不因同路径/同尺寸复用过期事实。
    pub fn restore(path: PathBuf, cancel: &Cancellation) -> Result<Arc<Self>> {
        let store = store::Store::read(&path)?;
        if store.metadata_value("schema")? != "2" {
            return Err("Analysis cache version is incompatible; reopen the ELF to rebuild".into());
        }
        let image = Arc::new(ElfImage::open(store.metadata_value("source")?)?);
        let expected = store
            .metadata_value("sha256")
            .map_err(|_| "Cache has no completed source fingerprint; reopen ELF instead")?;
        if fingerprint(&image, cancel)? != expected {
            return Err(
                "Source contents changed; cache rejected. Reopen the ELF to reindex.".into(),
            );
        }
        let warnings: Vec<String> =
            serde_json::from_str(&store.metadata_value("warnings")?).map_err(|e| e.to_string())?;
        let progress = Progress {
            phase: "Verified cached baseline (indirect targets may remain unresolved)".into(),
            counts: store.counts()?,
            preferred: store.preferred(),
            cache_path: path.clone(),
            complete: warnings.is_empty(),
            warnings,
            revision: 1,
            ..Default::default()
        };
        Ok(Arc::new(Self {
            image,
            path,
            progress: Mutex::new(progress),
            cancel: Mutex::new(Cancellation::default()),
            running: AtomicBool::new(false),
        }))
    }
    /// 局部 CFG 结果写回同一索引。SQLite 事务串行化短批次，不占用 GUI 线程。
    pub fn merge_analysis(&self, analysis: &crate::Analysis, cancel: &Cancellation) -> Result<()> {
        cancel.check()?;
        let mut batch = FactBatch::default();
        for f in &analysis.functions {
            batch.functions.push(FunctionFact {
                address: f.address,
                size: f.size,
                name: f.name.clone(),
                source: f.source.clone(),
                confidence: 1,
            });
        }
        for e in &analysis.edges {
            if let Some(to) = e.to {
                batch.xrefs.push(XrefFact {
                    from: e.from,
                    to,
                    kind: match e.kind.as_str() {
                        "branch" => "jump",
                        "taken" => "conditional",
                        k => k,
                    }
                    .into(),
                    confidence: 2,
                    evidence: format!(
                        "local CFG rooted at {:#x}; partial={}",
                        analysis.entry, analysis.partial
                    ),
                });
            }
        }
        let mut store = store::Store::create(&self.path)?;
        cancel.check()?;
        store.commit(&batch)?;
        let counts = store.counts()?;
        self.update(|p| {
            p.counts = counts;
            p.revision += 1;
        });
        Ok(())
    }
    fn update(&self, f: impl FnOnce(&mut Progress)) {
        let mut p = self.progress.lock().unwrap_or_else(|e| e.into_inner());
        f(&mut p);
    }
    pub fn cancel(&self) {
        self.cancel
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .cancel();
    }
    pub fn start(self: &Arc<Self>) -> bool {
        if self.running.swap(true, Ordering::AcqRel) {
            return false;
        }
        let cancel = Cancellation::default();
        *self.cancel.lock().unwrap_or_else(|e| e.into_inner()) = cancel.clone();
        self.update(|p| {
            p.running = true;
            p.complete = false;
            p.phase = "Reading symbols and unwind metadata".into();
            p.scanned = 0;
            p.total = 0;
            p.warnings.clear();
        });
        let session = self.clone();
        let launched = std::thread::Builder::new()
            .name("index-coordinator".into())
            .spawn(move || {
                let start = Instant::now();
                let result = session.run(&cancel);
                session.update(|p| {
                    p.running = false;
                    p.elapsed_ms = start.elapsed().as_millis() as u64;
                    match result {
                        Ok(()) => {
                            p.complete = p.warnings.is_empty();
                            p.phase = if p.complete {
                                "Baseline ready (indirect targets may remain unresolved)"
                            } else {
                                "Baseline partial — see diagnostics"
                            }
                            .into();
                        }
                        Err(e) => {
                            p.phase = if e == "request cancelled" {
                                "Paused — committed results retained; Resume continues".into()
                            } else {
                                format!("Index failed: {e}")
                            };
                            if e != "request cancelled" {
                                p.warnings.push(e);
                            }
                        }
                    }
                    p.revision += 1;
                });
                session.running.store(false, Ordering::Release);
            });
        if let Err(e) = launched {
            self.running.store(false, Ordering::Release);
            self.update(|p| {
                p.running = false;
                p.phase = e.to_string();
            });
            return false;
        }
        true
    }
    fn run(&self, cancel: &Cancellation) -> Result<()> {
        if self.image.machine != 183 || self.image.bits != 64 || !self.image.little {
            return Err("Automatic indexing requires ELF64 little-endian AArch64".into());
        }
        let mut store = store::Store::create(&self.path)?;
        store.metadata("source", &self.image.path.to_string_lossy())?;
        store.metadata("schema", "2")?;
        let mut publish = |batch: FactBatch| -> Result<()> {
            cancel.check()?;
            store.commit(&batch)?;
            let counts = store.counts()?;
            let preferred = store
                .preferred()
                .filter(|va| store.label(*va).as_deref() == Some("JNI_OnLoad"));
            self.update(|p| {
                for w in &batch.warnings {
                    if p.warnings.len() < 64 && !p.warnings.contains(w) {
                        p.warnings.push(w.clone());
                    }
                }
                p.counts = counts;
                p.preferred = preferred;
                p.revision += 1;
            });
            Ok(())
        };
        let info = metadata::discover(&self.image, cancel, &mut publish)?;
        let preferred = store.preferred();
        self.update(|p| {
            p.preferred = preferred;
            p.warnings = info.warnings.clone();
            p.phase = "Scanning code references and strings".into();
        });
        self.update(|p| p.total = info.code.iter().chain(&info.data).map(|r| r.size).sum());
        let (work_tx, work_rx) = crossbeam_channel::bounded(32);
        let (tx, rx) = crossbeam_channel::bounded::<Result<FactBatch>>(8);
        let workers = std::thread::available_parallelism()
            .map_or(2, usize::from)
            .saturating_sub(1)
            .clamp(1, 6);
        std::thread::scope(|scope| -> Result<()> {
            let info_ref = &info;
            let errors = tx.clone();
            scope.spawn(move || {
                let result = (|| -> Result<()> {
                    let checkpoints = store::Store::read(&self.path)?;
                    for mut task in scan::tasks(info_ref) {
                        cancel.check()?;
                        if checkpoints.task_done(&task.id()) {
                            self.update(|p| p.scanned += task.length());
                            continue;
                        }
                        loop {
                            cancel.check()?;
                            match work_tx.send_timeout(task, std::time::Duration::from_millis(50)) {
                                Ok(()) => break,
                                Err(crossbeam_channel::SendTimeoutError::Timeout(back)) => {
                                    task = back
                                }
                                Err(crossbeam_channel::SendTimeoutError::Disconnected(_)) => {
                                    return Ok(())
                                }
                            }
                        }
                    }
                    Ok(())
                })();
                if let Err(e) = result {
                    let _ = errors.send(Err(e));
                }
            });
            for _ in 0..workers {
                let tx = tx.clone();
                let work = work_rx.clone();
                let info = &info;
                scope.spawn(move || {
                    for task in work {
                        if cancel.check().is_err() {
                            break;
                        }
                        let result = scan::execute(&self.image, info, &task, cancel);
                        if tx.send(result).is_err() {
                            break;
                        }
                    }
                });
            }
            drop(work_rx);
            drop(tx);
            let mut failure = None;
            for result in rx {
                if failure.is_some() {
                    continue;
                }
                match result.and_then(|b| {
                    cancel.check()?;
                    let bytes = b.checkpoint.as_ref().map_or(0, |(_, n)| *n);
                    store.commit(&b)?;
                    self.update(|p| {
                        for w in &b.warnings {
                            if p.warnings.len() < 64 && !p.warnings.contains(w) {
                                p.warnings.push(w.clone());
                            }
                        }
                        p.scanned += bytes;
                        p.revision += 1;
                    });
                    Ok(())
                }) {
                    Ok(()) => (),
                    Err(e) => {
                        failure = Some(e);
                        cancel.cancel();
                    }
                }
                let counts = store.counts()?;
                self.update(|p| p.counts = counts);
            }
            if let Some(e) = failure {
                return Err(e);
            }
            cancel.check()
        })?;
        self.update(|p| p.phase = "Recording source fingerprint".into());
        // 完整哈希在首批结果与扫描之后执行，绝不阻塞首屏。缓存不按路径盲目复用。
        store.metadata("sha256", &fingerprint(&self.image, cancel)?)?;
        store.metadata("status", "baseline_scanned")?;
        store.metadata(
            "warnings",
            &serde_json::to_string(&self.progress().warnings).map_err(|e| e.to_string())?,
        )?;
        Ok(())
    }
}
fn fingerprint(image: &ElfImage, cancel: &Cancellation) -> Result<String> {
    use sha2::{Digest, Sha256};
    let mut hash = Sha256::new();
    let mut off = 0;
    while off < image.length {
        cancel.check()?;
        let bytes = image.read_file(off, (image.length - off).min(1024 * 1024) as usize)?;
        hash.update(&bytes);
        off += bytes.len() as u64;
    }
    Ok(format!("{:x}", hash.finalize()))
}
