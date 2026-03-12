use crate::{Confidence, Severity, Vulnerability};

static STACK_TRACE_PATTERNS: &[(&str, &str)] = &[
    ("Traceback (most recent call last)", "Python"),
    ("at com.", "Java"),
    ("at org.", "Java"),
    ("java.lang.", "Java"),
    ("Caused by:", "Java/JVM"),
    ("Exception in thread", "Java"),
    ("NullPointerException", "Java"),
    ("ClassNotFoundException", "Java"),
    ("javax.servlet", "Java Servlet"),
    ("File \"", "Python"),
    ("raise ", "Python"),
    ("Fatal error:", "PHP"),
    ("Stack trace:", "PHP"),
    ("Call Stack:", "PHP"),
    ("on line ", "PHP"),
    ("Parse error:", "PHP"),
    ("Warning: ", "PHP"),
    ("Notice: ", "PHP"),
    ("SQLSTATE[", "PHP/PDO"),
    ("Microsoft.AspNetCore", ".NET"),
    ("System.Exception", ".NET"),
    ("System.NullReferenceException", ".NET"),
    ("at System.", ".NET"),
    ("goroutine ", "Go"),
    ("panic: runtime error", "Go"),
    ("ActionView::Template::Error", "Ruby/Rails"),
    ("ActiveRecord::RecordNotFound", "Ruby/Rails"),
    ("NoMethodError", "Ruby"),
    ("SyntaxError:", "JavaScript/Node"),
    ("ReferenceError:", "JavaScript/Node"),
    ("TypeError:", "JavaScript/Node"),
    ("Error: ENOENT", "Node.js"),
];

static FILE_PATH_PATTERNS: &[&str] = &[
    "/home/",
    "/var/www/",
    "/var/log/",
    "/usr/local/",
    "/opt/",
    "/etc/",
    "/srv/",
    "C:\\Users\\",
    "C:\\inetpub\\",
    "C:\\Windows\\",
    "D:\\",
];

static DEBUG_HEADERS: &[(&str, &str)] = &[
    ("x-debug-token", "Symfony Debug Token"),
    ("x-debug-token-link", "Symfony Debug Link"),
    ("x-aspnet-version", "ASP.NET Version"),
    ("x-aspnetmvc-version", "ASP.NET MVC Version"),
    ("x-sourcefiles", "ASP.NET Source Files"),
    ("x-runtime", "Ruby/Rails Runtime"),
    ("x-request-id", "Request ID (may leak internal info)"),
    ("x-powered-cms", "CMS Version"),
    ("server-timing", "Server Timing (may leak internal details)"),
];

pub fn check_info_disclosure(
    url: &str,
    headers: &reqwest::header::HeaderMap,
    body: &str,
) -> Vec<Vulnerability> {
    let mut vulns = Vec::new();
    let body_lower = body.to_lowercase();

    for (pattern, tech) in STACK_TRACE_PATTERNS {
        if body_lower.contains(&pattern.to_lowercase()) {
            let pos = body_lower.find(&pattern.to_lowercase()).unwrap_or(0);
            let start = pos.saturating_sub(20);
            let end = (pos + 120).min(body.len());
            let evidence = &body[start..end];

            vulns.push(Vulnerability {
                id: "passive-info-disclosure".to_string(),
                title: "Information Disclosure: Stack Trace".to_string(),
                description: format!("{} stack trace or error message detected in response", tech),
                severity: Severity::Medium,
                confidence: Confidence::Confirmed,
                category: "CWE-200 - Exposure of Sensitive Information".to_string(),
                location: url.to_string(),
                evidence: truncate(evidence, 200),
                impact: "Reveals internal architecture, file paths, and technology versions"
                    .to_string(),
                remediation: "Configure error handling to return generic messages in production"
                    .to_string(),
                affected_endpoints: vec![url.to_string()],
                ..Default::default()
            });
            break;
        }
    }

    for path_pattern in FILE_PATH_PATTERNS {
        if body.contains(path_pattern) {
            let pos = body.find(path_pattern).unwrap_or(0);
            let end = (pos + 100).min(body.len());
            let evidence = &body[pos..end];

            if !is_benign_path_context(body, pos) {
                vulns.push(Vulnerability {
                    id: "passive-info-disclosure".to_string(),
                    title: "Information Disclosure: File Path".to_string(),
                    description: format!(
                        "Internal file path '{}' leaked in response",
                        path_pattern
                    ),
                    severity: Severity::Low,
                    confidence: Confidence::Firm,
                    category: "CWE-200 - Exposure of Sensitive Information".to_string(),
                    location: url.to_string(),
                    evidence: truncate(evidence, 200),
                    impact: "Reveals internal server directory structure".to_string(),
                    remediation: "Remove file paths from error messages and responses".to_string(),
                    affected_endpoints: vec![url.to_string()],
                    ..Default::default()
                });
                break;
            }
        }
    }

    for (header_name, header_desc) in DEBUG_HEADERS {
        if let Some(val) = headers.get(*header_name) {
            if let Ok(val_str) = val.to_str() {
                vulns.push(Vulnerability {
                    id: "passive-debug-header".to_string(),
                    title: format!("Debug Header: {}", header_desc),
                    description: format!("{} header detected: {}", header_name, val_str),
                    severity: Severity::Low,
                    confidence: Confidence::Confirmed,
                    category: "CWE-200 - Exposure of Sensitive Information".to_string(),
                    location: url.to_string(),
                    evidence: format!("{}: {}", header_name, val_str),
                    impact: "Reveals debug information useful for targeted attacks".to_string(),
                    remediation: "Remove debug headers in production deployments".to_string(),
                    affected_endpoints: vec![url.to_string()],
                    ..Default::default()
                });
                break;
            }
        }
    }

    vulns
}

fn is_benign_path_context(body: &str, pos: usize) -> bool {
    let start = pos.saturating_sub(50);
    let context = &body[start..pos].to_lowercase();
    context.contains("href=") || context.contains("src=") || context.contains("url(")
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() > max {
        format!("{}...", &s[..max])
    } else {
        s.to_string()
    }
}
