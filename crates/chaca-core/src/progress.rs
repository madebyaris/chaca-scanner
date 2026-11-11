//! Progress reporting for scan runs.
//!
//! The engine emits progress through a [`ProgressSink`]. Front ends implement
//! that trait to forward events to whatever UI they own: the Tauri app sends
//! them to the web view, the native app updates its own state.

use std::sync::{Arc, Mutex};

/// A single progress event from a running scan.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ScanProgress {
    pub phase: String,
    pub current: u32,
    pub total: u32,
    pub message: String,
    #[serde(default)]
    pub detail: String,
    #[serde(default)]
    pub findings_so_far: u32,
}

/// Receives progress events emitted by the scan engine.
pub trait ProgressSink: Send + Sync {
    fn emit(&self, progress: &ScanProgress);
}

/// A sink that discards every event.
#[derive(Debug, Clone, Copy, Default)]
pub struct NullProgressSink;

impl ProgressSink for NullProgressSink {
    fn emit(&self, _progress: &ScanProgress) {}
}

/// A sink that forwards events to a closure.
pub struct FnProgressSink<F>(pub F);

impl<F> ProgressSink for FnProgressSink<F>
where
    F: Fn(&ScanProgress) + Send + Sync,
{
    fn emit(&self, progress: &ScanProgress) {
        (self.0)(progress);
    }
}

/// A sink that keeps every event it receives, for tests and for replay.
#[derive(Debug, Default)]
pub struct RecordedProgressSink {
    events: Mutex<Vec<ScanProgress>>,
}

impl RecordedProgressSink {
    pub fn new() -> Self {
        Self::default()
    }

    /// Every event received so far, in order.
    pub fn events(&self) -> Vec<ScanProgress> {
        self.events.lock().expect("progress lock").clone()
    }

    /// The most recent event, if any.
    pub fn last(&self) -> Option<ScanProgress> {
        self.events.lock().expect("progress lock").last().cloned()
    }

    /// The phases seen so far, in order.
    pub fn phases(&self) -> Vec<String> {
        self.events
            .lock()
            .expect("progress lock")
            .iter()
            .map(|event| event.phase.clone())
            .collect()
    }

    /// How many events carried the given phase.
    pub fn count_for_phase(&self, phase: &str) -> usize {
        self.events
            .lock()
            .expect("progress lock")
            .iter()
            .filter(|event| event.phase == phase)
            .count()
    }
}

impl ProgressSink for RecordedProgressSink {
    fn emit(&self, progress: &ScanProgress) {
        self.events.lock().expect("progress lock").push(progress.clone());
    }
}

/// Wraps a sink in an `Arc` so it can be shared across tasks.
pub fn shared_sink(sink: Arc<dyn ProgressSink>) -> Arc<dyn ProgressSink> {
    sink
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recorded_sink_keeps_events_in_order() {
        let sink = RecordedProgressSink::new();
        sink.emit(&ScanProgress {
            phase: "crawling".into(),
            current: 0,
            total: 100,
            message: "Discovering endpoints...".into(),
            detail: String::new(),
            findings_so_far: 0,
        });
        sink.emit(&ScanProgress {
            phase: "passive".into(),
            current: 22,
            total: 100,
            message: "Running passive analysis...".into(),
            detail: String::new(),
            findings_so_far: 3,
        });

        assert_eq!(sink.events().len(), 2);
        assert_eq!(sink.phases(), vec!["crawling", "passive"]);
        assert_eq!(sink.count_for_phase("passive"), 1);
        assert_eq!(sink.last().unwrap().findings_so_far, 3);
    }

    #[test]
    fn fn_sink_forwards_to_closure() {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let seen_for_closure = seen.clone();
        let sink = FnProgressSink(move |progress: &ScanProgress| {
            seen_for_closure
                .lock()
                .unwrap()
                .push(progress.phase.clone());
        });

        sink.emit(&ScanProgress {
            phase: "active".into(),
            current: 70,
            total: 100,
            message: "Running active vulnerability tests...".into(),
            detail: String::new(),
            findings_so_far: 0,
        });

        assert_eq!(seen.lock().unwrap().as_slice(), ["active"]);
    }
}
