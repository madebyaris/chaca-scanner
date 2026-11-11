//! Engine work runs on a dedicated OS thread; only channel messages cross into GPUI.
use chaca_core::{ProgressSink, ScanConfig, ScanProgress, ScanRequest, ScanResult, ScanType};
use std::{
    sync::{mpsc, Arc},
    thread,
    time::{Duration, Instant},
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ScanMode {
    Passive,
    Active,
    Full,
}
impl ScanMode {
    pub const ALL: [Self; 3] = [Self::Passive, Self::Active, Self::Full];
    pub fn label(self) -> &'static str {
        match self {
            Self::Passive => "Passive",
            Self::Active => "Active",
            Self::Full => "Full",
        }
    }
    pub fn description(self) -> &'static str {
        match self {
            Self::Passive => "Header, cookie, response and exposure analysis",
            Self::Active => "Sends test payloads. Scan only targets you are authorized to test.",
            Self::Full => {
                "Passive analysis and active payload tests. Requires target authorization."
            }
        }
    }
    pub fn engine_type(self) -> ScanType {
        match self {
            Self::Passive => ScanType::Passive,
            Self::Active => ScanType::Active,
            Self::Full => ScanType::Full,
        }
    }
}

#[derive(Debug)]
pub enum ScanState {
    Idle,
    Scanning { started: Instant, cancelling: bool },
    Done,
    Cancelled,
    Error(String),
}
impl ScanState {
    pub fn busy(&self) -> bool {
        matches!(self, Self::Scanning { .. })
    }
    pub fn cancelling(&self) -> bool {
        matches!(
            self,
            Self::Scanning {
                cancelling: true,
                ..
            }
        )
    }
    pub fn label(&self) -> &'static str {
        match self {
            Self::Idle => "Ready",
            Self::Scanning {
                cancelling: false, ..
            } => "Scanning",
            Self::Scanning {
                cancelling: true, ..
            } => "Cancelling",
            Self::Done => "Complete",
            Self::Cancelled => "Cancelled",
            Self::Error(_) => "Error",
        }
    }
}

pub enum WorkerEvent {
    Progress(ScanProgress),
    Finished(Result<ScanResult, String>),
}
struct ChannelSink(mpsc::Sender<WorkerEvent>);
impl ProgressSink for ChannelSink {
    fn emit(&self, progress: &ScanProgress) {
        let _ = self.0.send(WorkerEvent::Progress(progress.clone()));
    }
}

pub fn launch_scan(request: ScanRequest) -> Result<mpsc::Receiver<WorkerEvent>, String> {
    let (sender, receiver) = mpsc::channel();
    chaca_core::reset_scan_cancelled();
    thread::Builder::new().name("chaca-scan".into()).spawn(move || {
        // Catch a worker panic so the UI can always leave its scanning state.
        let started = Instant::now();
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let runtime = tokio::runtime::Builder::new_multi_thread().worker_threads(2)
                .enable_all().build().map_err(|err| format!("Cannot start scanner runtime: {err}"))?;
            let sink: Arc<dyn ProgressSink> = Arc::new(ChannelSink(sender.clone()));
            let outcome = runtime.block_on(async {
                tokio::select! {
                    result = chaca_core::scanner::engine::run_scan(request, Some(sink)) => result.map_err(|e| e.to_string()),
                    _ = async { loop {
                        tokio::time::sleep(Duration::from_millis(50)).await;
                        if chaca_core::cancel_scan_requested() { break; }
                    } } => Err("Scan cancelled".to_string()),
                }
            });
            // Tear down outstanding engine tasks before allowing another scan.
            drop(runtime);
            outcome
        })).unwrap_or_else(|_| Err("The scanner worker stopped unexpectedly. You can start a new scan.".into()));
        let result = result.map(|mut result| {
            // The shared engine leaves timing to its desktop host.
            result.scan_duration_ms = started.elapsed().as_millis().min(u64::MAX as u128) as u64;
            result
        });
        let _ = sender.send(WorkerEvent::Finished(result));
    }).map_err(|err| format!("Cannot launch scanner: {err}"))?;
    Ok(receiver)
}

pub fn request(url: String, mode: ScanMode) -> ScanRequest {
    ScanRequest {
        url,
        scan_type: mode.engine_type(),
        config: ScanConfig::default(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn progress_sink_crosses_threads_and_preserves_details() {
        let (tx, rx) = mpsc::channel();
        thread::spawn(move || {
            ChannelSink(tx).emit(&ScanProgress {
                phase: "passive".into(),
                current: 3,
                total: 7,
                message: "Headers".into(),
                detail: "GET /".into(),
                findings_so_far: 2,
            })
        })
        .join()
        .unwrap();
        let WorkerEvent::Progress(p) = rx.recv().unwrap() else {
            panic!("wrong event")
        };
        assert_eq!((p.current, p.total, p.findings_so_far), (3, 7, 2));
        assert_eq!(p.detail, "GET /");
    }
}
