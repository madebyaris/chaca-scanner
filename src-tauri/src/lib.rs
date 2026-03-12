use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicBool, Ordering};
use tracing::info;

pub mod license;
pub mod scanner;

static SCAN_CANCELLED: AtomicBool = AtomicBool::new(false);
const DEFAULT_CHROME_USER_AGENT: &str =
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36";

pub fn reset_scan_cancelled() {
    SCAN_CANCELLED.store(false, Ordering::SeqCst);
}

pub fn cancel_scan_requested() -> bool {
    SCAN_CANCELLED.load(Ordering::SeqCst)
}

pub fn request_scan_cancel() {
    SCAN_CANCELLED.store(true, Ordering::SeqCst);
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanRequest {
    pub url: String,
    pub scan_type: ScanType,
    #[serde(default = "ScanConfig::default")]
    pub config: ScanConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ScanConfig {
    // Network
    pub http_timeout_secs: u64,
    pub accept_invalid_certs: bool,
    pub custom_user_agent: String,
    pub custom_headers: Vec<HeaderPair>,
    pub rate_limit_rps: u32,

    // Crawling
    pub discovery_mode: DiscoveryMode,
    pub max_crawl_depth: u32,
    pub max_endpoints: u32,
    pub follow_robots_txt: bool,
    pub scope_allowlist: Vec<String>,
    pub scope_denylist: Vec<String>,
    pub custom_api_paths: Vec<String>,
    pub artifact_input: String,

    // Passive scan toggles
    pub passive_server_header: bool,
    pub passive_x_powered_by: bool,
    pub passive_json_api: bool,
    pub passive_hsts: bool,
    pub passive_content_type_options: bool,
    pub passive_frame_options: bool,
    pub passive_csp: bool,
    pub passive_cors: bool,
    pub passive_referrer_policy: bool,
    pub passive_permissions_policy: bool,
    pub passive_cache_control: bool,
    pub passive_cookie_flags: bool,
    pub passive_csrf: bool,
    pub passive_clickjack: bool,
    pub passive_info_disclosure: bool,
    pub passive_jwt_analysis: bool,
    pub passive_ratelimit_check: bool,
    pub passive_deser_check: bool,
    pub cms_detection: bool,
    pub generic_exposure_checks: bool,
    pub check_exposed_services: bool,
    pub check_admin_panels: bool,

    // Active scan toggles
    pub active_bola: bool,
    pub active_ssrf: bool,
    pub active_injection: bool,
    pub active_auth_bypass: bool,
    pub active_open_redirect: bool,
    pub active_path_traversal: bool,
    pub active_cors_reflection: bool,
    pub active_xss_enhanced: bool,
    pub active_csrf_verify: bool,
    pub active_graphql: bool,
    pub active_resource_consumption: bool,
    pub bola_diff_threshold: usize,
    pub auth_bypass_diff_threshold: usize,

    // Data detection
    pub entropy_threshold: f64,
    pub max_pii_matches: usize,
    pub tier1_secrets: bool,
    pub tier2_entropy: bool,
    pub tier3_pii: bool,
    pub min_severity: Severity,

    // Scoring
    pub score_critical_weight: i32,
    pub score_high_weight: i32,
    pub score_medium_weight: i32,
    pub score_low_weight: i32,
    pub score_critical_cap: i32,
    pub score_high_cap: i32,
    pub score_medium_cap: i32,
    pub score_low_cap: i32,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DiscoveryMode {
    Crawl,
    Artifact,
    #[default]
    Merged,
}

impl Default for ScanConfig {
    fn default() -> Self {
        Self {
            http_timeout_secs: 30,
            accept_invalid_certs: true,
            custom_user_agent: DEFAULT_CHROME_USER_AGENT.to_string(),
            custom_headers: Vec::new(),
            rate_limit_rps: 0,

            discovery_mode: DiscoveryMode::Merged,
            max_crawl_depth: 1,
            max_endpoints: 100,
            follow_robots_txt: true,
            scope_allowlist: Vec::new(),
            scope_denylist: Vec::new(),
            custom_api_paths: Vec::new(),
            artifact_input: String::new(),

            passive_server_header: true,
            passive_x_powered_by: true,
            passive_json_api: true,
            passive_hsts: true,
            passive_content_type_options: true,
            passive_frame_options: true,
            passive_csp: true,
            passive_cors: true,
            passive_referrer_policy: true,
            passive_permissions_policy: true,
            passive_cache_control: true,
            passive_cookie_flags: true,
            passive_csrf: true,
            passive_clickjack: true,
            passive_info_disclosure: true,
            passive_jwt_analysis: true,
            passive_ratelimit_check: true,
            passive_deser_check: true,
            cms_detection: true,
            generic_exposure_checks: true,
            check_exposed_services: true,
            check_admin_panels: true,

            active_bola: true,
            active_ssrf: true,
            active_injection: true,
            active_auth_bypass: true,
            active_open_redirect: true,
            active_path_traversal: true,
            active_cors_reflection: true,
            active_xss_enhanced: true,
            active_csrf_verify: true,
            active_graphql: true,
            active_resource_consumption: true,
            bola_diff_threshold: 50,
            auth_bypass_diff_threshold: 100,

            entropy_threshold: 3.0,
            max_pii_matches: 3,
            tier1_secrets: true,
            tier2_entropy: true,
            tier3_pii: true,
            min_severity: Severity::Info,

            score_critical_weight: 15,
            score_high_weight: 10,
            score_medium_weight: 5,
            score_low_weight: 2,
            score_critical_cap: 30,
            score_high_cap: 25,
            score_medium_cap: 20,
            score_low_cap: 10,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeaderPair {
    pub key: String,
    pub value: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ScanType {
    Passive,
    Active,
    Full,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Confidence {
    #[default]
    Confirmed,
    Firm,
    Tentative,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CmsType {
    WordPress,
    Drupal,
    Joomla,
    Shopify,
    Magento,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResult {
    pub url: String,
    pub scan_type: ScanType,
    pub vulnerabilities: Vec<Vulnerability>,
    pub api_exposures: Vec<ApiExposure>,
    pub data_exposures: Vec<DataExposure>,
    pub security_score: u32,
    pub scan_duration_ms: u64,
    pub cms_detected: Option<CmsType>,
    #[serde(default)]
    pub target_info: Option<TargetInfo>,
    #[serde(default)]
    pub auth_state: AuthState,
    #[serde(default)]
    pub inventory: Vec<InventorySummaryItem>,
    #[serde(default)]
    pub metrics: ScanMetrics,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TargetInfo {
    pub ip_addresses: Vec<String>,
    pub server: String,
    pub powered_by: String,
    pub content_type: String,
    pub http_version: String,
    pub status_code: u16,
    pub redirect_chain: Vec<String>,
    pub tls_issuer: String,
    pub tls_protocol: String,
    pub response_headers: Vec<HeaderPair>,
    pub cookies: Vec<CookieInfo>,
    pub technologies: Vec<String>,
    pub dns_records: Vec<String>,
    pub whois_org: String,
    pub cdn_provider: String,
    pub waf_detected: String,
    pub hosting_provider: String,
    pub framework: String,
    pub language: String,
    pub os_hint: String,
    pub open_ports_hint: Vec<String>,
    pub meta_generator: String,
    pub favicon_hash: String,
    pub robots_txt_exists: bool,
    pub sitemap_exists: bool,
    pub security_txt_exists: bool,
    pub response_time_ms: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CookieInfo {
    pub name: String,
    pub domain: String,
    pub secure: bool,
    pub http_only: bool,
    pub same_site: String,
    pub path: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Vulnerability {
    pub id: String,
    #[serde(default)]
    pub rule_id: String,
    #[serde(default)]
    pub fingerprint: String,
    pub title: String,
    pub description: String,
    #[serde(default)]
    pub severity: Severity,
    #[serde(default)]
    pub confidence: Confidence,
    pub category: String,
    pub location: String,
    pub evidence: String,
    pub impact: String,
    pub remediation: String,
    pub affected_endpoints: Vec<String>,
    #[serde(default)]
    pub evidence_items: Vec<EvidenceItem>,
    #[serde(default)]
    pub references: Vec<String>,
    #[serde(default)]
    pub cwe: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    #[default]
    Critical,
    High,
    Medium,
    Low,
    Info,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiExposure {
    #[serde(default)]
    pub fingerprint: String,
    pub endpoint: String,
    pub method: String,
    pub description: String,
    pub severity: Severity,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataExposure {
    #[serde(default)]
    pub fingerprint: String,
    pub field: String,
    pub data_type: String,
    pub location: String,
    pub severity: Severity,
    pub confidence: Confidence,
    #[serde(default)]
    pub matched_value: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EvidenceItem {
    pub kind: String,
    pub label: String,
    pub value: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AuthState {
    pub mode: String,
    pub applied: bool,
    pub status: String,
    pub details: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct InventorySummaryItem {
    pub url: String,
    pub method: String,
    pub source: String,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub parameter_names: Vec<String>,
    #[serde(default)]
    pub last_status: Option<u16>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ScanMetrics {
    pub request_count: u64,
    pub endpoint_total: u32,
    pub active_candidate_total: u32,
    pub passive_vulnerability_count: u32,
    pub active_vulnerability_count: u32,
    pub api_exposure_count: u32,
    pub data_exposure_count: u32,
    pub artifact_seed_count: u32,
    pub authenticated_request_count: u32,
    pub confirmed_finding_count: u32,
    pub tentative_finding_count: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
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

#[tauri::command]
async fn start_scan(app: tauri::AppHandle, request: ScanRequest) -> Result<ScanResult, String> {
    info!(
        "Starting scan for URL: {} with type: {:?}",
        request.url, request.scan_type
    );
    reset_scan_cancelled();

    let start_time = std::time::Instant::now();

    let result = scanner::run_scan(request, Some(app))
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
    request_scan_cancel();
    Ok(())
}

#[tauri::command]
fn get_app_info() -> serde_json::Value {
    serde_json::json!({
        "name": "Chaca",
        "version": "0.6.0",
        "description": "Web Security Scanner for vibe coders"
    })
}

#[tauri::command]
async fn activate_license(
    product_id: String,
    license_key: String,
) -> Result<license::LicenseInfo, String> {
    license::verify_license(&product_id, &license_key).await
}

#[tauri::command]
fn deactivate_license() -> Result<(), String> {
    license::deactivate_license();
    Ok(())
}

#[tauri::command]
fn get_license_status() -> serde_json::Value {
    let is_pro = license::is_pro();
    let info = license::get_license_info();
    serde_json::json!({
        "is_pro": is_pro,
        "license": info,
    })
}

#[tauri::command]
fn restore_cached_license(info: license::LicenseInfo) -> Result<(), String> {
    license::restore_cached_license(info);
    Ok(())
}

#[tauri::command]
fn check_pro_feature(_feature: String) -> Result<bool, String> {
    Ok(license::is_pro())
}

#[tauri::command]
async fn scan_folder(path: String) -> Result<ScanResult, String> {
    info!("Starting folder scan: {}", path);
    scanner::folder_scanner::scan_folder(&path)
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
            activate_license,
            deactivate_license,
            get_license_status,
            restore_cached_license,
            check_pro_feature,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
