// SPDX-License-Identifier: Apache-2.0
use crate::Result;
use crossbeam_channel::{bounded, Sender};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};

#[derive(Clone, Default)]
pub struct Cancellation(Arc<AtomicBool>);
impl Cancellation {
    pub fn cancel(&self) {
        self.0.store(true, Ordering::Relaxed);
    }
    pub fn check(&self) -> Result<()> {
        if self.0.load(Ordering::Relaxed) {
            Err("request cancelled".into())
        } else {
            Ok(())
        }
    }
}
type Job = Box<dyn FnOnce() + Send + 'static>;
/// 有界队列避免 AI 并发请求无限积压；UI 提交永不阻塞。
pub struct WorkerPool {
    sender: Sender<Job>,
    pub threads: usize,
}
impl Default for WorkerPool {
    fn default() -> Self {
        Self::new(
            std::thread::available_parallelism()
                .map_or(2, usize::from)
                .clamp(2, 8),
        )
    }
}
impl WorkerPool {
    pub fn new(threads: usize) -> Self {
        let threads = threads.clamp(1, 16);
        let (sender, receiver) = bounded::<Job>(threads * 4);
        for i in 0..threads {
            let receiver = receiver.clone();
            std::thread::Builder::new()
                .name(format!("analysis-{i}"))
                .spawn(move || {
                    while let Ok(job) = receiver.recv() {
                        job();
                    }
                })
                .expect("cannot create analysis worker");
        }
        Self { sender, threads }
    }
    pub fn submit(&self, job: impl FnOnce() + Send + 'static) -> Result<()> {
        self.sender
            .try_send(Box::new(job))
            .map_err(|_| "analysis queue full; retry after pending requests finish".into())
    }
}
