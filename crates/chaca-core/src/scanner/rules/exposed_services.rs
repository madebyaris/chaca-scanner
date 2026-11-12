use super::super::domain::{HttpMethod, RequestContext, ScanRuntime};
use crate::{Confidence, ScanConfig, Severity, Vulnerability};
use std::sync::Arc;
use tokio::sync::Semaphore;
use tokio::task::JoinSet;
use tracing::info;

static SUPABASE_PATTERNS: &[&str] = &[
    "supabase.co",
    "supabase.in",
    ".supabase.co/rest/v1",
    "X-Client-Info: supabase-js",
];

static FIREBASE_PATTERNS: &[&str] = &[
    "firebaseio.com",
    "firestore.googleapis.com",
    "firebase.google.com",
    "firebaseapp.com",
    "firebase-adminsdk",
];

static POCKETBASE_PATTERNS: &[&str] = &["/api/collections/", "pocketbase", "/api/admins/auth"];

pub fn scan_for_service_urls(url: &str, body: &str) -> Vec<Vulnerability> {
    let mut vulns = Vec::new();
    let body_lower = body.to_lowercase();

    for pattern in SUPABASE_PATTERNS {
        if body_lower.contains(&pattern.to_lowercase()) {
            let pos = body_lower.find(&pattern.to_lowercase()).unwrap_or(0);
            let start = pos.saturating_sub(30);
            let end = (pos + 80).min(body.len());
            vulns.push(Vulnerability {
                id: "exposed-supabase-url".to_string(),
                title: "Supabase URL/Key in Client Code".to_string(),
                description:
                    "Supabase project reference found in client-side code. Verify RLS is enabled."
                        .to_string(),
                severity: Severity::Medium,
                confidence: Confidence::Firm,
                category: "API8:2023 - Security Misconfiguration".to_string(),
                location: url.to_string(),
                evidence: truncate(&body[start..end], 150),
                impact: "If RLS is disabled, all database data may be publicly accessible"
                    .to_string(),
                remediation:
                    "Enable Row Level Security on all Supabase tables; audit anon key permissions"
                        .to_string(),
                affected_endpoints: vec![url.to_string()],
                ..Default::default()
            });
            break;
        }
    }

    for pattern in FIREBASE_PATTERNS {
        if body_lower.contains(&pattern.to_lowercase()) {
            let pos = body_lower.find(&pattern.to_lowercase()).unwrap_or(0);
            let start = pos.saturating_sub(30);
            let end = (pos + 80).min(body.len());
            vulns.push(Vulnerability {
                id: "exposed-firebase-url".to_string(),
                title: "Firebase Config in Client Code".to_string(),
                description: "Firebase project configuration found in client-side code. Verify security rules.".to_string(),
                severity: Severity::Medium,
                confidence: Confidence::Firm,
                category: "API8:2023 - Security Misconfiguration".to_string(),
                location: url.to_string(),
                evidence: truncate(&body[start..end], 150),
                impact: "If security rules are permissive, all database data may be publicly accessible".to_string(),
                remediation: "Configure Firebase Security Rules to require authentication for all operations".to_string(),
                affected_endpoints: vec![url.to_string()],
                        ..Default::default()
            });
            break;
        }
    }

    for pattern in POCKETBASE_PATTERNS {
        if body_lower.contains(&pattern.to_lowercase()) {
            vulns.push(Vulnerability {
                id: "exposed-pocketbase".to_string(),
                title: "PocketBase Reference in Client Code".to_string(),
                description: "PocketBase API reference found in client-side code.".to_string(),
                severity: Severity::Low,
                confidence: Confidence::Tentative,
                category: "API8:2023 - Security Misconfiguration".to_string(),
                location: url.to_string(),
                evidence: format!("Pattern '{}' found in response", pattern),
                impact: "If collection rules are permissive, data may be publicly accessible"
                    .to_string(),
                remediation: "Configure PocketBase collection rules to require authentication"
                    .to_string(),
                affected_endpoints: vec![url.to_string()],
                ..Default::default()
            });
            break;
        }
    }

    vulns
}

pub async fn check_exposed_databases(
    base_url: &str,
    client: &reqwest::Client,
    body: &str,
) -> Vec<Vulnerability> {
    let mut vulns = Vec::new();
    let body_lower = body.to_lowercase();

    if let Some(supabase_url) = extract_supabase_url(&body_lower, body) {
        info!("Testing Supabase endpoint: {}", supabase_url);
        let test_url = format!("{}/rest/v1/", supabase_url.trim_end_matches('/'));
        if let Ok(resp) = client
            .get(&test_url)
            .header("apikey", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9")
            .send()
            .await
        {
            if resp.status().is_success() {
                let resp_body = resp.text().await.unwrap_or_default();
                if resp_body.len() > 10
                    && (resp_body.starts_with('[') || resp_body.starts_with('{'))
                {
                    vulns.push(Vulnerability {
                        id: "exposed-supabase".to_string(),
                        title: "Exposed Supabase Database".to_string(),
                        description: "Supabase REST API returns data without proper authentication".to_string(),
                        severity: Severity::Critical,
                        confidence: Confidence::Confirmed,
                        category: "API1:2023 - Broken Object Level Authorization".to_string(),
                        location: test_url.clone(),
                        evidence: truncate(&resp_body, 200),
                        impact: "All database records may be publicly readable, writable, or deletable".to_string(),
                        remediation: "Enable Row Level Security (RLS) on all tables; restrict anon key permissions".to_string(),
                        affected_endpoints: vec![test_url],
                        ..Default::default()
                    });
                }
            }
        }
    }

    if let Some(firebase_url) = extract_firebase_url(&body_lower, body) {
        info!("Testing Firebase endpoint: {}", firebase_url);
        let test_url = format!("{}/.json", firebase_url.trim_end_matches('/'));
        if let Ok(resp) = client.get(&test_url).send().await {
            if resp.status().is_success() {
                let resp_body = resp.text().await.unwrap_or_default();
                if resp_body != "null" && resp_body.len() > 5 {
                    vulns.push(Vulnerability {
                        id: "exposed-firebase".to_string(),
                        title: "Exposed Firebase Realtime Database".to_string(),
                        description: "Firebase Realtime Database is publicly readable without authentication".to_string(),
                        severity: Severity::Critical,
                        confidence: Confidence::Confirmed,
                        category: "API1:2023 - Broken Object Level Authorization".to_string(),
                        location: test_url.clone(),
                        evidence: truncate(&resp_body, 200),
                        impact: "All database contents are publicly accessible".to_string(),
                        remediation: "Configure Firebase Security Rules: set .read and .write to require auth".to_string(),
                        affected_endpoints: vec![test_url],
                        ..Default::default()
                    });
                }
            }
        }
    }

    let pocketbase_url = format!("{}/api/collections/", base_url.trim_end_matches('/'));
    if let Ok(resp) = client.get(&pocketbase_url).send().await {
        if resp.status().is_success() {
            let resp_body = resp.text().await.unwrap_or_default();
            if resp_body.contains("\"items\"") || resp_body.contains("\"collections\"") {
                vulns.push(Vulnerability {
                    id: "exposed-pocketbase".to_string(),
                    title: "Exposed PocketBase Collections".to_string(),
                    description: "PocketBase collections endpoint is publicly accessible"
                        .to_string(),
                    severity: Severity::Critical,
                    confidence: Confidence::Confirmed,
                    category: "API1:2023 - Broken Object Level Authorization".to_string(),
                    location: pocketbase_url.clone(),
                    evidence: truncate(&resp_body, 200),
                    impact: "All PocketBase collections and data may be publicly accessible"
                        .to_string(),
                    remediation: "Configure PocketBase collection rules to require authentication"
                        .to_string(),
                    affected_endpoints: vec![pocketbase_url],
                    ..Default::default()
                });
            }
        }
    }

    vulns
}

struct AdminPanel {
    path: &'static str,
    id: &'static str,
    title: &'static str,
    signatures: &'static [&'static str],
}

static ADMIN_PANELS: &[AdminPanel] = &[
    AdminPanel {
        path: "/phpmyadmin/",
        id: "exposed-phpmyadmin",
        title: "phpMyAdmin",
        signatures: &["phpMyAdmin", "pma_", "pmahomme"],
    },
    AdminPanel {
        path: "/phpmyadmin",
        id: "exposed-phpmyadmin",
        title: "phpMyAdmin",
        signatures: &["phpMyAdmin", "pma_"],
    },
    AdminPanel {
        path: "/adminer.php",
        id: "exposed-adminer",
        title: "Adminer",
        signatures: &["adminer", "Adminer"],
    },
    AdminPanel {
        path: "/adminer/",
        id: "exposed-adminer",
        title: "Adminer",
        signatures: &["adminer", "Adminer"],
    },
    AdminPanel {
        path: "/phpinfo.php",
        id: "exposed-phpinfo",
        title: "phpinfo()",
        signatures: &["phpinfo()", "PHP Version", "PHP License"],
    },
    AdminPanel {
        path: "/server-status",
        id: "exposed-server-status",
        title: "Apache Server Status",
        signatures: &["Apache Server Status", "Server Version:"],
    },
    AdminPanel {
        path: "/server-info",
        id: "exposed-server-status",
        title: "Apache Server Info",
        signatures: &["Apache Server Information", "Server Version:"],
    },
    AdminPanel {
        path: "/admin/",
        id: "exposed-admin-panel",
        title: "Admin Panel",
        signatures: &["admin", "login", "dashboard", "Administration"],
    },
    AdminPanel {
        path: "/administrator/",
        id: "exposed-admin-panel",
        title: "Admin Panel",
        signatures: &["administrator", "login", "Administration"],
    },
    AdminPanel {
        path: "/console",
        id: "exposed-admin-panel",
        title: "Console",
        signatures: &["console", "Console", "Interactive"],
    },
    AdminPanel {
        path: "/wp-login.php",
        id: "exposed-admin-panel",
        title: "WordPress Login",
        signatures: &["wp-login", "WordPress", "Log In"],
    },
];

pub async fn check_admin_panels(
    base_url: &str,
    runtime: &ScanRuntime,
    config: &ScanConfig,
    limit: usize,
) -> Vec<Vulnerability> {
    let base = base_url.trim_end_matches('/').to_string();
    let semaphore = Arc::new(Semaphore::new(limit.max(1)));
    let config = Arc::new(config.clone());
    let mut tasks = JoinSet::new();

    for panel in ADMIN_PANELS {
        let runtime = runtime.clone();
        let config = config.clone();
        let semaphore = semaphore.clone();
        let base = base.clone();
        let path = panel.path;
        let id = panel.id;
        let title = panel.title;
        let signatures = panel.signatures;
        tasks.spawn(async move {
            let Ok(_permit) = semaphore.acquire_owned().await else {
                return None;
            };
            if crate::cancel_scan_requested() {
                return None;
            }
            let test_url = format!("{base}{path}");
            let context = RequestContext::from_scan_config(HttpMethod::Get, &test_url, &config)
                .with_label("admin_panel");
            let Ok(response) = runtime
                .execute_request(context.into_builder(runtime.client()))
                .await
            else {
                return None;
            };
            if !response.status().is_success() {
                return None;
            }
            let body = response.text().await.unwrap_or_default();
            let body_lower = body.to_lowercase();
            let matched = signatures
                .iter()
                .any(|signature| body_lower.contains(&signature.to_lowercase()));
            if !matched {
                return None;
            }
            Some(Vulnerability {
                id: id.to_string(),
                title: format!("Exposed: {title}"),
                description: format!("{title} is publicly accessible at {path}"),
                severity: Severity::High,
                confidence: Confidence::Confirmed,
                category: "API8:2023 - Security Misconfiguration".to_string(),
                location: test_url.clone(),
                evidence: format!("HTTP 200 at {path} with matching content"),
                impact: format!("{title} interface exposed to the internet"),
                remediation: format!(
                    "Restrict access to {path} via IP whitelist or remove from production"
                ),
                affected_endpoints: vec![test_url],
                ..Default::default()
            })
        });
    }

    let mut vulns = Vec::new();
    while let Some(joined) = tasks.join_next().await {
        if let Ok(Some(vulnerability)) = joined {
            vulns.push(vulnerability);
        }
    }
    vulns.sort_by(|left, right| left.location.cmp(&right.location));
    vulns
}

fn extract_supabase_url(body_lower: &str, body: &str) -> Option<String> {
    let patterns = ["https://", "http://"];
    for prefix in patterns {
        if let Some(start) = body_lower.find(&format!("{}", prefix)) {
            let slice = &body[start..];
            if let Some(end) = slice
                .find(|c: char| c.is_whitespace() || c == '"' || c == '\'' || c == '`' || c == ')')
            {
                let url = &slice[..end];
                if url.contains("supabase.co") || url.contains("supabase.in") {
                    return Some(url.to_string());
                }
            }
        }
    }
    None
}

fn extract_firebase_url(body_lower: &str, body: &str) -> Option<String> {
    if let Some(pos) = body_lower.find("firebaseio.com") {
        let search_start = pos.saturating_sub(100);
        let slice = &body[search_start..];
        if let Some(url_start) = slice.find("https://") {
            let url_slice = &slice[url_start..];
            if let Some(end) = url_slice
                .find(|c: char| c.is_whitespace() || c == '"' || c == '\'' || c == '`' || c == ')')
            {
                return Some(url_slice[..end].to_string());
            }
        }
    }
    None
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() > max {
        format!("{}...", &s[..max])
    } else {
        s.to_string()
    }
}
