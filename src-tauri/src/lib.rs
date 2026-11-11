use std::sync::Arc;
use tauri::Emitter;
use tracing::info;

pub use chaca_core::{
    cancel_scan_requested, request_scan_cancel, reset_scan_cancelled, ApiExposure, AuthState, CmsType,
    Confidence, CookieInfo, DataExposure, DiscoveryMode, EvidenceItem, HeaderPair, InventorySummaryItem,
    ScanConfig, ScanMetrics, ScanProgress, ScanRequest, ScanResult, ScanType, Severity, TargetInfo,
    Vulnerability,
};

struct TauriProgressSink {
    app: tauri::AppHandle,
}

impl chaca_core::ProgressSink for TauriProgressSink {
    fn emit(&self, progress: &ScanProgress) {
        let _ = self.app.emit("scan-progress", progress);
    }
}

#[tauri::command]
async fn start_scan(app: tauri::AppHandle, request: ScanRequest) -> Result<ScanResult, String> {
    info!(
        "Starting scan for URL: {} with type: {:?}",
        request.url, request.scan_type
    );
    chaca_core::reset_scan_cancelled();

    let start_time = std::time::Instant::now();

    let sink: Arc<dyn chaca_core::ProgressSink> = Arc::new(TauriProgressSink { app });
    let result = chaca_core::scanner::engine::run_scan(request, Some(sink))
        .await
        .map_err(|e| e.to_string())?;

    let duration = start_time.elapsed().as_millis() as u64;
    let mut final_result = result;
    final_result.scan_duration_ms = duration;

    info!(
        "Scan completed in {}ms with {} vulnerabilities",
        duration,
        final_result.vulnerabilities.len()
    );

    Ok(final_result)
}

#[tauri::command]
fn cancel_scan() -> Result<(), String> {
    chaca_core::request_scan_cancel();
    Ok(())
}

#[tauri::command]
fn get_app_info() -> serde_json::Value {
    serde_json::json!({
        "name": "Chaca",
        "version": env!("CARGO_PKG_VERSION"),
        "description": "Web Security Scanner for vibe coders"
    })
}

#[tauri::command]
async fn scan_folder(path: String) -> Result<ScanResult, String> {
    info!("Starting folder scan: {}", path);
    chaca_core::scanner::folder_scanner::scan_folder(&path)
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tracing_subscriber::fmt()
        .with_env_filter("securescan=info")
        .init();

    info!("Starting Chaca application");

    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_http::init())
        .plugin(tauri_plugin_store::Builder::default().build())
        .invoke_handler(tauri::generate_handler![
            start_scan,
            cancel_scan,
            scan_folder,
            get_app_info,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
