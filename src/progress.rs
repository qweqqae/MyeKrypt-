use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

#[derive(Clone, Default)]
pub struct Progress {
    inner: Arc<Counters>,
}

#[derive(Default)]
struct Counters {
    done: AtomicU64,
    total: AtomicU64,
}

impl Progress {
    pub fn new() -> Self {
        Progress::default()
    }

    pub fn set_total(&self, total: u64) {
        self.inner.total.store(total, Ordering::Relaxed);
    }

    pub fn add(&self, bytes: u64) {
        self.inner.done.fetch_add(bytes, Ordering::Relaxed);
    }

    pub fn done(&self) -> u64 {
        self.inner.done.load(Ordering::Relaxed)
    }

    pub fn total(&self) -> u64 {
        self.inner.total.load(Ordering::Relaxed)
    }

    pub fn ratio(&self) -> Option<f64> {
        let total = self.total();
        if total == 0 {
            return None;
        }
        Some((self.done() as f64 / total as f64).clamp(0.0, 1.0))
    }
}
