use crate::{Confidence, Severity, Vulnerability};
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
        path: "/_debugbar/open",
        id: "exposed-debugbar",
        title: "Laravel Debugbar",
        signatures: &["debugbar", "Debugbar", "__debugbar"],
    },
    AdminPanel {
        path: "/_profiler/",
        id: "exposed-debugbar",
        title: "Symfony Profiler",
        signatures: &["Symfony Profiler", "sf-toolbar"],
    },
    AdminPanel {
        path: "/elmah.axd",
        id: "exposed-debugbar",
        title: "ELMAH Error Log",
        signatures: &["ELMAH", "Error Log", "Error Mail"],
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

pub async fn check_admin_panels(base_url: &str, client: &reqwest::Client) -> Vec<Vulnerability> {
    let mut vulns = Vec::new();
    let base = base_url.trim_end_matches('/');

    for panel in ADMIN_PANELS {
        let test_url = format!("{}{}", base, panel.path);
        if let Ok(resp) = client.get(&test_url).send().await {
            if resp.status().is_success() {
                let body = resp.text().await.unwrap_or_default();
                let body_lower = body.to_lowercase();
                let matched = panel
                    .signatures
                    .iter()
                    .any(|sig| body_lower.contains(&sig.to_lowercase()));
                if matched {
                    vulns.push(Vulnerability {
                        id: panel.id.to_string(),
                        title: format!("Exposed: {}", panel.title),
                        description: format!(
                            "{} is publicly accessible at {}",
                            panel.title, panel.path
                        ),
                        severity: if panel.id == "exposed-phpinfo" || panel.id == "exposed-debugbar"
                        {
                            Severity::High
                        } else {
                            Severity::High
                        },
                        confidence: Confidence::Confirmed,
                        category: "API8:2023 - Security Misconfiguration".to_string(),
                        location: test_url.clone(),
                        evidence: format!("HTTP 200 at {} with matching content", panel.path),
                        impact: format!("{} interface exposed to the internet", panel.title),
                        remediation: format!(
                            "Restrict access to {} via IP whitelist or remove from production",
                            panel.path
                        ),
                        affected_endpoints: vec![test_url],
                        ..Default::default()
                    });
                }
            }
        }
    }

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
