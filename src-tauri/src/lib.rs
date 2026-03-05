use serde::{Deserialize, Serialize};
use tracing::info;

pub mod scanner;

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
    pub max_crawl_depth: u32,
    pub max_endpoints: u32,
    pub follow_robots_txt: bool,
    pub custom_api_paths: Vec<String>,

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

impl Default for ScanConfig {
    fn default() -> Self {
        Self {
            http_timeout_secs: 30,
            accept_invalid_certs: true,
            custom_user_agent: String::new(),
            custom_headers: Vec::new(),
            rate_limit_rps: 0,

            max_crawl_depth: 1,
            max_endpoints: 100,
            follow_robots_txt: true,
            custom_api_paths: Vec::new(),

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
    pub endpoint: String,
    pub method: String,
    pub description: String,
    pub severity: Severity,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataExposure {
    pub field: String,
    pub data_type: String,
    pub location: String,
    pub severity: Severity,
    pub confidence: Confidence,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanProgress {
    pub phase: String,
    pub current: u32,
    pub total: u32,
    pub message: String,
}

#[tauri::command]
async fn start_scan(app: tauri::AppHandle, request: ScanRequest) -> Result<ScanResult, String> {
    info!("Starting scan for URL: {} with type: {:?}", request.url, request.scan_type);

    let start_time = std::time::Instant::now();

    let result = scanner::run_scan(request, Some(app)).await.map_err(|e| e.to_string())?;
    
    let duration = start_time.elapsed().as_millis() as u64;
    let mut final_result = result;
    final_result.scan_duration_ms = duration;
    
    info!("Scan completed in {}ms with {} vulnerabilities", 
          duration, 
          final_result.vulnerabilities.len());
    
    Ok(final_result)
}

#[tauri::command]
fn get_app_info() -> serde_json::Value {
    serde_json::json!({
        "name": "Chaca",
        "version": "0.5.0",
        "description": "Web Security Scanner for vibe coders"
    })
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tracing_subscriber::fmt()
        .with_env_filter("securescan=info")
        .init();
    
    info!("Starting Chaca application");
    
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_http::init())
        .plugin(tauri_plugin_store::Builder::default().build())
        .invoke_handler(tauri::generate_handler![start_scan, get_app_info])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
