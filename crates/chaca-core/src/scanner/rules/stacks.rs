//! Stack-specific exposure checks.
//!
//! A probe runs only after a fingerprint that is stronger than a word in the
//! page text. Source maps are the exception: the page already names the map.
//! Nothing in this module sends an exploit payload. A Spring heap dump is
//! checked with HEAD and its body is not stored.

use super::super::domain::{HttpMethod, RequestContext, ScanRuntime};
use crate::{Confidence, ScanConfig, Severity, TargetInfo, Vulnerability};
use regex::Regex;
use std::sync::LazyLock;

static SOURCE_MAP_URL: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"(?i)sourceMappingURL=([^\s*'"<>]+)"#).unwrap());

static PROFILER_TOKEN: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"(?i)/_profiler/([A-Za-z0-9]{6,})"#).unwrap());

static LARAVEL_LOG_LINE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)\[\d{4}-\d{2}-\d{2}[^\n]{0,80}(?:local|production|staging)\.").unwrap()
});

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct StackId {
    pub laravel: bool,
    pub symfony: bool,
    pub magento: bool,
    pub django: bool,
    pub flask: bool,
    pub fastapi: bool,
    pub rails: bool,
    pub spring: bool,
    pub aspnet: bool,
    pub wordpress: bool,
}

pub fn identify(info: &TargetInfo) -> StackId {
    StackId {
        laravel: tech_is(info, "Laravel")
            || framework_is(info, "Laravel")
            || cookie_is(info, "laravel_session"),
        symfony: tech_is(info, "Symfony")
            || framework_is(info, "Symfony")
            || has_header(info, "x-debug-token")
            || has_header(info, "x-debug-token-link"),
        magento: tech_is(info, "Magento") || framework_is(info, "Magento"),
        django: tech_is(info, "Django") || framework_is(info, "Django"),
        flask: tech_is(info, "Flask") || framework_is(info, "Flask"),
        fastapi: tech_is(info, "FastAPI")
            || tech_is(info, "Starlette")
            || tech_is(info, "Uvicorn")
            || framework_is(info, "FastAPI")
            || framework_is(info, "Starlette"),
        rails: tech_is(info, "Ruby on Rails")
            || framework_is(info, "Ruby on Rails")
            || framework_is(info, "Rails"),
        spring: tech_is(info, "Spring")
            || framework_is(info, "Spring")
            || has_header(info, "x-application-context"),
        aspnet: info
            .technologies
            .iter()
            .any(|tech| tech.contains("ASP.NET"))
            || info.framework.contains("ASP.NET")
            || has_header(info, "x-aspnet-version")
            || has_header(info, "x-aspnetmvc-version"),
        wordpress: tech_is(info, "WordPress") || framework_is(info, "WordPress"),
    }
}

pub fn source_mapping_refs(body: &str) -> Vec<String> {
    SOURCE_MAP_URL
        .captures_iter(body)
        .filter_map(|captures| captures.get(1).map(|item| item.as_str().to_string()))
        .collect()
}

pub fn resolve_source_map(page_url: &str, raw: &str) -> Option<String> {
    let raw = raw.trim().trim_matches(|ch| {
        ch == ')' || ch == ';' || ch == ',' || ch == '"' || ch == '\'' || ch == '*'
    });
    if raw.is_empty() || raw.starts_with("data:") {
        return None;
    }
    let page = url::Url::parse(page_url).ok()?;
    let joined = page.join(raw).ok()?;
    if page.scheme() != joined.scheme()
        || page.host_str() != joined.host_str()
        || page.port_or_known_default() != joined.port_or_known_default()
    {
        return None;
    }
    Some(joined.to_string())
}

pub fn django_debug_page(body: &str) -> bool {
    body.contains("DEBUG = True")
}

pub fn werkzeug_debugger_page(body: &str) -> bool {
    body.contains("The debugger is active") || body.contains("Werkzeug Debugger")
}

pub fn source_map_body(body: &str) -> bool {
    let trimmed = body.trim_start();
    (trimmed.starts_with('{') || trimmed.starts_with(")]}"))
        && (body.contains("\"mappings\"") || body.contains("\"sources\""))
}

pub fn ignition_health_body(body: &str) -> bool {
    body.contains("\"can_execute_commands\"")
}

pub fn laravel_log_body(body: &str) -> bool {
    LARAVEL_LOG_LINE.is_match(body)
}

pub fn magento_version_body(body: &str) -> bool {
    let line = body.trim();
    line.len() <= 120 && line.to_ascii_lowercase().starts_with("magento/")
}

pub fn django_version_body(body: &str) -> bool {
    body.to_ascii_lowercase().contains("django version")
}

pub fn rails_properties_body(body: &str) -> bool {
    body.to_ascii_lowercase().contains("rails version")
}

pub fn rails_routes_body(body: &str) -> bool {
    body.contains("Verb") && body.contains("URI") && body.contains("Controller")
}

pub fn application_trace_body(body: &str) -> bool {
    body.contains("Application Trace")
}

pub fn elmah_body(body: &str) -> bool {
    body.contains("ELMAH") && (body.contains("Error Log") || body.contains("Error Mail"))
}

pub fn debugbar_body(body: &str) -> bool {
    body.contains("__debugbar") || body.contains("phpdebugbar")
}

pub fn profiler_index_body(body: &str) -> bool {
    body.contains("Symfony Profiler") || body.contains("sf-toolbar")
}

/// Token linked by a profiler page. Names such as `search` are profiler routes,
/// not tokens, so a token must include a digit.
pub fn profiler_token(body: &str) -> Option<String> {
    PROFILER_TOKEN.captures_iter(body).find_map(|captures| {
        let token = captures.get(1)?.as_str();
        if token.chars().any(|ch| ch.is_ascii_digit()) {
            Some(token.to_string())
        } else {
            None
        }
    })
}

pub async fn check_stacks(
    base_url: &str,
    info: &TargetInfo,
    pages: &[(&str, &str)],
    runtime: &ScanRuntime,
    config: &ScanConfig,
) -> Vec<Vulnerability> {
    let base = base_url.trim_end_matches('/').to_string();
    let id = identify(info);
    let mut notes = PageNotes::default();
    for (url, body) in pages {
        notes.observe(url, body, &base);
    }
    if !notes.saw_base {
        if let Some(fetched) = fetch(runtime, config, HttpMethod::Get, &base, 64 * 1024).await {
            if fetched.status.is_success() {
                notes.observe(&base, &fetched.prefix, &base);
            }
        }
    }

    let mut findings = Vec::new();
    if let Some(location) = notes.django_debug.clone() {
        findings.push(finding(
            "django-debug-page",
            "Django debug page is public",
            "A fetched page already says DEBUG = True.",
            Severity::High,
            &location,
            "The page contains DEBUG = True.",
            "Settings, query data, and local variables can be shown to visitors.",
            "Turn DEBUG off outside local development.",
        ));
    }
    if let Some(location) = notes.werkzeug.clone() {
        findings.push(finding(
            "werkzeug-debugger-page",
            "Werkzeug debugger page is public",
            "A fetched page is a Werkzeug debugger page.",
            Severity::High,
            &location,
            "The page contains a Werkzeug debugger.",
            "A public debugger exposes the application to anyone who can open the page.",
            "Disable the debugger outside local development.",
        ));
    }
    for map_url in &notes.map_urls {
        if let Some(fetched) = fetch(runtime, config, HttpMethod::Get, map_url, 8192).await {
            if fetched.status.is_success() && source_map_body(&fetched.prefix) {
                findings.push(finding(
                    "public-source-map",
                    "JavaScript source map is public",
                    "The page names a source map, and that map is readable.",
                    Severity::Medium,
                    map_url,
                    "The response is a source map.",
                    "A public source map exposes original source file names and, when included, source text.",
                    "Stop publishing source maps on production hosts.",
                ));
            }
        }
    }

    if id.laravel {
        probe_laravel(runtime, config, &base, &mut findings).await;
    }
    if id.symfony {
        probe_symfony(runtime, config, &base, &mut findings).await;
    }
    if id.magento {
        probe_magento(runtime, config, &base, &mut findings).await;
    }
    if id.django {
        probe_django_version(runtime, config, &base, &mut findings).await;
    }
    if id.rails {
        probe_rails(runtime, config, &base, &mut findings).await;
    }
    if id.spring {
        probe_spring_heapdump(runtime, config, &base, &mut findings).await;
    }
    if id.aspnet {
        probe_aspnet(runtime, config, &base, &mut findings).await;
    }
    findings
}

async fn probe_laravel(
    runtime: &ScanRuntime,
    config: &ScanConfig,
    base: &str,
    findings: &mut Vec<Vulnerability>,
) {
    let health = format!("{base}/_ignition/health");
    if let Some(fetched) = fetch(runtime, config, HttpMethod::Get, &health, 4096).await {
        if fetched.status.is_success() && ignition_health_body(&fetched.prefix) {
            findings.push(finding(
                "laravel-ignition-health",
                "Laravel Ignition health endpoint is public",
                "Ignition's health URL returned its JSON document.",
                Severity::High,
                &health,
                "The response is Ignition health JSON.",
                "A public Ignition endpoint confirms a debug package is reachable.",
                "Disable Ignition outside local development.",
            ));
        }
    }
    let log = format!("{base}/storage/logs/laravel.log");
    if let Some(fetched) = fetch(runtime, config, HttpMethod::Get, &log, 4096).await {
        if fetched.status.is_success() && laravel_log_body(&fetched.prefix) {
            findings.push(finding(
                "laravel-log-exposed",
                "Laravel log file is public",
                "storage/logs/laravel.log is readable and contains log lines.",
                Severity::High,
                &log,
                "The file contains log timestamps and level names.",
                "Log lines can include paths, queries, and request data.",
                "Block public access to the storage directory.",
            ));
        }
    }
    let debugbar = format!("{base}/_debugbar/open");
    if let Some(fetched) = fetch(runtime, config, HttpMethod::Get, &debugbar, 8192).await {
        if fetched.status.is_success() && debugbar_body(&fetched.prefix) {
            findings.push(finding(
                "laravel-debugbar",
                "Laravel Debugbar is public",
                "The Debugbar open endpoint is readable.",
                Severity::High,
                &debugbar,
                "The response contains Debugbar data.",
                "Debugbar can show queries, views, and request data.",
                "Disable Debugbar outside local development.",
            ));
        }
    }
}

async fn probe_symfony(
    runtime: &ScanRuntime,
    config: &ScanConfig,
    base: &str,
    findings: &mut Vec<Vulnerability>,
) {
    let index = format!("{base}/_profiler/");
    let Some(fetched) = fetch(runtime, config, HttpMethod::Get, &index, 64 * 1024).await else {
        return;
    };
    if !fetched.status.is_success() || !profiler_index_body(&fetched.prefix) {
        return;
    }
    findings.push(finding(
        "symfony-profiler",
        "Symfony profiler is public",
        "The profiler index is readable.",
        Severity::High,
        &index,
        "The response is a Symfony profiler page.",
        "The profiler shows requests, queries, and configuration.",
        "Disable the profiler outside local development.",
    ));
    let Some(token) = profiler_token(&fetched.prefix) else {
        return;
    };
    let entry = format!("{base}/_profiler/{token}");
    let Some(entry_body) = fetch(runtime, config, HttpMethod::Get, &entry, 8192).await else {
        return;
    };
    if entry_body.status.is_success() && profiler_index_body(&entry_body.prefix) {
        findings.push(finding(
            "symfony-profiler-entry",
            "Symfony profiler entry is public",
            "The profiler index links to a token page, and that page is readable.",
            Severity::High,
            &entry,
            "The linked profiler page is public.",
            "A profiler entry can include the request that created it.",
            "Disable the profiler outside local development.",
        ));
    }
}

async fn probe_magento(
    runtime: &ScanRuntime,
    config: &ScanConfig,
    base: &str,
    findings: &mut Vec<Vulnerability>,
) {
    let url = format!("{base}/magento_version");
    let Some(fetched) = fetch(runtime, config, HttpMethod::Get, &url, 256).await else {
        return;
    };
    if fetched.status.is_success() && magento_version_body(&fetched.prefix) {
        findings.push(finding(
            "magento-version-file",
            "Magento version file is public",
            "magento_version names the installed Magento release.",
            Severity::Low,
            &url,
            fetched.prefix.trim(),
            "The installed release is visible to anyone.",
            "Remove magento_version from the public web root.",
        ));
    }
}

async fn probe_django_version(
    runtime: &ScanRuntime,
    config: &ScanConfig,
    base: &str,
    findings: &mut Vec<Vulnerability>,
) {
    let url = format!("{base}/admin/login/");
    let Some(fetched) = fetch(runtime, config, HttpMethod::Get, &url, 64 * 1024).await else {
        return;
    };
    if fetched.status.is_success() && django_version_body(&fetched.prefix) {
        findings.push(finding(
            "django-admin-version",
            "Django admin page prints its version",
            "The admin login page includes a Django version.",
            Severity::Low,
            &url,
            "The page contains a Django version.",
            "The installed Django release is visible on the login page.",
            "Upgrade Django and avoid printing the version on a public page.",
        ));
    }
}

async fn probe_rails(
    runtime: &ScanRuntime,
    config: &ScanConfig,
    base: &str,
    findings: &mut Vec<Vulnerability>,
) {
    let properties = format!("{base}/rails/info/properties");
    if let Some(fetched) = fetch(runtime, config, HttpMethod::Get, &properties, 8192).await {
        if fetched.status.is_success() && rails_properties_body(&fetched.prefix) {
            findings.push(finding(
                "rails-info-properties",
                "Rails properties page is public",
                "/rails/info/properties is readable.",
                Severity::High,
                &properties,
                "The page includes a Rails version.",
                "The properties page can list internal configuration.",
                "Disable the Rails info routes outside local development.",
            ));
        }
    }
    let routes = format!("{base}/rails/info/routes");
    if let Some(fetched) = fetch(runtime, config, HttpMethod::Get, &routes, 8192).await {
        if fetched.status.is_success() && rails_routes_body(&fetched.prefix) {
            findings.push(finding(
                "rails-info-routes",
                "Rails routes page is public",
                "/rails/info/routes is readable.",
                Severity::Medium,
                &routes,
                "The page lists application routes.",
                "The route table shows internal paths.",
                "Disable the Rails info routes outside local development.",
            ));
        }
    }
}

async fn probe_spring_heapdump(
    runtime: &ScanRuntime,
    config: &ScanConfig,
    base: &str,
    findings: &mut Vec<Vulnerability>,
) {
    let url = format!("{base}/actuator/heapdump");
    // HEAD only. A GET would download the heap, and this check must not store it.
    let Some(fetched) = fetch(runtime, config, HttpMethod::Head, &url, 0).await else {
        return;
    };
    if !fetched.status.is_success() || !heapdump_content_type(&fetched.content_type) {
        return;
    }
    findings.push(finding(
        "spring-heapdump-exposed",
        "Spring Boot heap dump URL is public",
        "HEAD /actuator/heapdump succeeded. The body was not downloaded.",
        Severity::High,
        &url,
        &format!(
            "HEAD returned {}. Content-Type: {}.",
            fetched.status.as_u16(),
            if fetched.content_type.is_empty() {
                "(none)"
            } else {
                &fetched.content_type
            }
        ),
        "A public heap dump can contain secrets and session data.",
        "Disable the heapdump actuator endpoint on public hosts.",
    ));
}

async fn probe_aspnet(
    runtime: &ScanRuntime,
    config: &ScanConfig,
    base: &str,
    findings: &mut Vec<Vulnerability>,
) {
    let trace = format!("{base}/trace.axd");
    if let Some(fetched) = fetch(runtime, config, HttpMethod::Get, &trace, 8192).await {
        if fetched.status.is_success() && application_trace_body(&fetched.prefix) {
            findings.push(finding(
                "aspnet-trace-axd",
                "ASP.NET application trace is public",
                "trace.axd returned an application trace page.",
                Severity::High,
                &trace,
                "The page is titled Application Trace.",
                "The trace lists recent requests.",
                "Disable trace.axd on public hosts.",
            ));
        }
    }
    let elmah = format!("{base}/elmah.axd");
    if let Some(fetched) = fetch(runtime, config, HttpMethod::Get, &elmah, 8192).await {
        if fetched.status.is_success() && elmah_body(&fetched.prefix) {
            findings.push(finding(
                "elmah-exposed",
                "ELMAH error log is public",
                "elmah.axd returned an error log page.",
                Severity::High,
                &elmah,
                "The page is an ELMAH error log.",
                "The error log can include request details and paths.",
                "Require authentication for ELMAH or remove it from the public site.",
            ));
        }
    }
}

#[derive(Default)]
struct PageNotes {
    saw_base: bool,
    django_debug: Option<String>,
    werkzeug: Option<String>,
    map_urls: Vec<String>,
}

impl PageNotes {
    fn observe(&mut self, page_url: &str, body: &str, base: &str) {
        if page_url.trim_end_matches('/') == base.trim_end_matches('/') {
            self.saw_base = true;
        }
        if self.django_debug.is_none() && django_debug_page(body) {
            self.django_debug = Some(page_url.to_string());
        }
        if self.werkzeug.is_none() && werkzeug_debugger_page(body) {
            self.werkzeug = Some(page_url.to_string());
        }
        for raw in source_mapping_refs(body) {
            if self.map_urls.len() >= 3 {
                break;
            }
            if let Some(absolute) = resolve_source_map(page_url, &raw) {
                if !self.map_urls.contains(&absolute) {
                    self.map_urls.push(absolute);
                }
            }
        }
    }
}

struct Fetched {
    status: reqwest::StatusCode,
    content_type: String,
    prefix: String,
}

async fn fetch(
    runtime: &ScanRuntime,
    config: &ScanConfig,
    method: HttpMethod,
    url: &str,
    max_bytes: usize,
) -> Option<Fetched> {
    if crate::cancel_scan_requested() {
        return None;
    }
    let context = RequestContext::from_scan_config(method, url, config).with_label("stack_check");
    let response = runtime
        .execute_request(context.into_builder(runtime.client()))
        .await
        .ok()?;
    let status = response.status();
    let content_type = response
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("")
        .to_string();
    if method == HttpMethod::Head || max_bytes == 0 {
        return Some(Fetched {
            status,
            content_type,
            prefix: String::new(),
        });
    }
    let mut buf = Vec::new();
    let mut response = response;
    while buf.len() < max_bytes {
        match response.chunk().await {
            Ok(Some(chunk)) => {
                let room = max_bytes - buf.len();
                if chunk.len() > room {
                    buf.extend_from_slice(&chunk[..room]);
                    break;
                }
                buf.extend_from_slice(&chunk);
            }
            _ => break,
        }
    }
    drop(response);
    Some(Fetched {
        status,
        content_type,
        prefix: String::from_utf8_lossy(&buf).into_owned(),
    })
}

fn heapdump_content_type(content_type: &str) -> bool {
    let lower = content_type.to_ascii_lowercase();
    if lower.is_empty() {
        return true;
    }
    !lower.contains("text/html")
        && !lower.contains("application/json")
        && !lower.contains("text/plain")
        && !lower.contains("text/xml")
}

fn finding(
    id: &str,
    title: &str,
    description: &str,
    severity: Severity,
    location: &str,
    evidence: &str,
    impact: &str,
    remediation: &str,
) -> Vulnerability {
    Vulnerability {
        id: id.to_string(),
        rule_id: id.to_string(),
        title: title.to_string(),
        description: description.to_string(),
        severity,
        confidence: Confidence::Firm,
        category: "API8:2023 - Security Misconfiguration".to_string(),
        location: location.to_string(),
        evidence: evidence.chars().take(180).collect(),
        impact: impact.to_string(),
        remediation: remediation.to_string(),
        affected_endpoints: vec![location.to_string()],
        ..Default::default()
    }
}

fn tech_is(info: &TargetInfo, name: &str) -> bool {
    info.technologies.iter().any(|tech| tech == name)
}

fn framework_is(info: &TargetInfo, name: &str) -> bool {
    info.framework == name
}

fn cookie_is(info: &TargetInfo, name: &str) -> bool {
    info.cookies
        .iter()
        .any(|cookie| cookie.name.eq_ignore_ascii_case(name))
}

fn has_header(info: &TargetInfo, name: &str) -> bool {
    info.response_headers
        .iter()
        .any(|header| header.key.eq_ignore_ascii_case(name))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{CookieInfo, HeaderPair, TargetInfo};

    #[test]
    fn source_maps_stay_on_the_same_origin() {
        let page = "https://example.test/assets/app.js";
        let body = "//# sourceMappingURL=app.js.map\n/*# sourceMappingURL=https://cdn.example/app.js.map */";
        let refs = source_mapping_refs(body);
        assert_eq!(refs.len(), 2);
        assert_eq!(
            resolve_source_map(page, &refs[0]).as_deref(),
            Some("https://example.test/assets/app.js.map")
        );
        assert!(resolve_source_map(page, &refs[1]).is_none());
        assert!(source_map_body(
            r#"{"version":3,"sources":["src/app.ts"],"mappings":"AAAA"}"#
        ));
        assert!(!source_map_body("<html>app.js.map</html>"));
    }

    #[test]
    fn weak_words_do_not_select_a_stack() {
        let spring_word = TargetInfo {
            technologies: vec!["offspring".to_string()],
            ..Default::default()
        };
        assert!(!identify(&spring_word).spring);
        let spring = TargetInfo {
            technologies: vec!["Spring".to_string()],
            ..Default::default()
        };
        assert!(identify(&spring).spring);

        let laravel_word = TargetInfo::default();
        assert!(!identify(&laravel_word).laravel);
        let laravel = TargetInfo {
            cookies: vec![CookieInfo {
                name: "laravel_session".to_string(),
                ..Default::default()
            }],
            ..Default::default()
        };
        assert!(identify(&laravel).laravel);
        assert!(
            identify(&TargetInfo {
                technologies: vec!["Uvicorn".to_string()],
                ..Default::default()
            })
            .fastapi
        );
        assert!(
            !identify(&TargetInfo {
                response_headers: vec![HeaderPair {
                    key: "x-runtime".to_string(),
                    value: "0.01".to_string(),
                }],
                ..Default::default()
            })
            .rails
        );
    }

    #[test]
    fn exposure_signatures_do_not_match_ordinary_pages() {
        assert!(!django_debug_page("<html>django blog</html>"));
        assert!(django_debug_page(
            "You're seeing this error because you have DEBUG = True"
        ));
        assert!(werkzeug_debugger_page("The debugger is active."));
        assert!(!werkzeug_debugger_page("flask documentation"));
        assert!(ignition_health_body(r#"{"can_execute_commands":false}"#));
        assert!(!ignition_health_body("ignition"));
        assert!(laravel_log_body(
            "[2026-01-02 03:04:05] production.ERROR: failed"
        ));
        assert!(!laravel_log_body("laravel.log"));
        assert!(magento_version_body("Magento/2.4 (Community)\n"));
        assert!(!magento_version_body("<html>magento</html>"));
        assert_eq!(
            profiler_token(
                r#"<a href="/_profiler/search">search</a> <a href="/_profiler/a1b2c3d4">entry</a>"#
            )
            .as_deref(),
            Some("a1b2c3d4")
        );
        assert!(application_trace_body("Application Trace"));
        assert!(heapdump_content_type("application/octet-stream"));
        assert!(!heapdump_content_type("text/html; charset=utf-8"));
        assert!(heapdump_content_type(""));
    }
}
