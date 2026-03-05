use crate::{Confidence, ScanConfig, Severity, Vulnerability};
use tracing::info;

pub async fn test_vulnerabilities(
    url: &str,
    config: &ScanConfig,
) -> Result<Vec<Vulnerability>, Box<dyn std::error::Error + Send + Sync>> {
    info!("Running active vulnerability tests for: {}", url);

    let mut vulnerabilities = Vec::new();

    let mut client_builder = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(config.http_timeout_secs));
    if config.accept_invalid_certs {
        client_builder = client_builder.danger_accept_invalid_certs(true);
    }
    if !config.custom_user_agent.is_empty() {
        client_builder = client_builder.user_agent(&config.custom_user_agent);
    }
    let client = client_builder.build()?;

    if config.active_bola {
        vulnerabilities.extend(test_bola(url, &client, config.bola_diff_threshold).await?);
    }
    if config.active_ssrf {
        vulnerabilities.extend(test_ssrf(url, &client).await?);
    }
    if config.active_injection {
        vulnerabilities.extend(test_injection(url, &client).await?);
    }
    if config.active_auth_bypass {
        vulnerabilities.extend(test_auth_bypass(url, &client, config.auth_bypass_diff_threshold).await?);
    }
    if config.active_open_redirect {
        vulnerabilities.extend(test_open_redirect(url, &client).await?);
    }
    if config.active_path_traversal {
        vulnerabilities.extend(test_path_traversal(url, &client).await?);
    }
    if config.active_cors_reflection {
        vulnerabilities.extend(test_cors_reflection(url, &client).await?);
    }
    if config.active_xss_enhanced {
        vulnerabilities.extend(test_xss_enhanced(url, &client).await?);
    }
    if config.active_csrf_verify {
        vulnerabilities.extend(test_csrf_active(url, &client).await?);
    }

    Ok(vulnerabilities)
}

async fn test_bola(
    url: &str,
    client: &reqwest::Client,
    diff_threshold: usize,
) -> Result<Vec<Vulnerability>, Box<dyn std::error::Error + Send + Sync>> {
    let mut vulnerabilities = Vec::new();

    // Baseline: fetch a known-unlikely ID to get the "not found" response shape
    let baseline_url = format!("{}/{}", url.trim_end_matches('/'), "99999999");
    let baseline_len = match client.get(&baseline_url).send().await {
        Ok(resp) => resp.text().await.unwrap_or_default().len(),
        Err(_) => return Ok(vulnerabilities),
    };

    let test_ids = vec!["1", "2", "admin"];
    for id in test_ids {
        let test_url = format!("{}/{}", url.trim_end_matches('/'), id);
        if let Ok(response) = client.get(&test_url).send().await {
            if response.status() == reqwest::StatusCode::OK {
                let body = response.text().await.unwrap_or_default();
                let diff = (body.len() as i64 - baseline_len as i64).unsigned_abs() as usize;
                // Only flag if the response is meaningfully different from baseline
                if diff > diff_threshold && body.len() != baseline_len {
                    vulnerabilities.push(Vulnerability {
                        id: format!("bola-{}", id),
                        title: "Potential Broken Object Level Authorization (BOLA)".to_string(),
                        description: format!(
                            "Resource /{} returns different data than /99999999 ({} bytes vs {} bytes)",
                            id,
                            body.len(),
                            baseline_len
                        ),
                        severity: Severity::High,
                        confidence: Confidence::Tentative,
                        category: "API1:2023 - Broken Object Level Authorization".to_string(),
                        location: test_url.clone(),
                        evidence: format!(
                            "GET {} returned 200 OK with {} bytes (baseline: {} bytes)",
                            test_url,
                            body.len(),
                            baseline_len
                        ),
                        impact: "Unauthorized access to resources belonging to other users"
                            .to_string(),
                        remediation:
                            "Implement proper authorization checks for all object references"
                                .to_string(),
                        affected_endpoints: vec![test_url],
                        ..Default::default()
                    });
                    break;
                }
            }
        }
    }

    Ok(vulnerabilities)
}

async fn test_ssrf(
    url: &str,
    client: &reqwest::Client,
) -> Result<Vec<Vulnerability>, Box<dyn std::error::Error + Send + Sync>> {
    let mut vulnerabilities = Vec::new();

    // Get baseline response (no SSRF payload) to compare
    let baseline_body = match client.get(url).send().await {
        Ok(resp) => resp.text().await.unwrap_or_default().to_lowercase(),
        Err(_) => return Ok(vulnerabilities),
    };

    let baseline_has_internal = baseline_body.contains("localhost")
        || baseline_body.contains("127.0.0.1")
        || baseline_body.contains("::1");

    let ssrf_payloads = vec!["http://localhost/", "http://127.0.0.1/", "http://[::1]/"];

    for payload in ssrf_payloads {
        if let Ok(response) = client.get(url).query(&[("url", payload)]).send().await {
            let body = response.text().await.unwrap_or_default();
            let body_lower = body.to_lowercase();

            let has_internal = body_lower.contains("localhost")
                || body_lower.contains("127.0.0.1")
                || body_lower.contains("::1");

            // Only flag if internal references appear in the payload response but NOT in baseline
            if has_internal && !baseline_has_internal {
                vulnerabilities.push(Vulnerability {
                    id: "ssrf-1".to_string(),
                    title: "Potential Server-Side Request Forgery (SSRF)".to_string(),
                    description: "Internal network references appeared after SSRF payload"
                        .to_string(),
                    severity: Severity::Critical,
                    confidence: Confidence::Firm,
                    category: "API7:2023 - Server-Side Request Forgery".to_string(),
                    location: url.to_string(),
                    evidence: format!(
                        "Payload: {} caused internal references in response",
                        payload
                    ),
                    impact: "Attacker can access internal resources and services".to_string(),
                    remediation: "Validate and sanitize all user-supplied URLs".to_string(),
                    affected_endpoints: vec![url.to_string()],
                        ..Default::default()
                });
                break;
            }
        }
    }

    Ok(vulnerabilities)
}

async fn test_injection(
    url: &str,
    client: &reqwest::Client,
) -> Result<Vec<Vulnerability>, Box<dyn std::error::Error + Send + Sync>> {
    let mut vulnerabilities = Vec::new();

    // SQL error signatures
    let sql_errors = [
        "sql syntax",
        "mysql_",
        "pg_query",
        "sqlite3",
        "ora-",
        "unclosed quotation mark",
        "quoted string not properly terminated",
        "syntax error at or near",
        "you have an error in your sql",
    ];

    // SQLi: send a single quote and look for SQL error messages
    if let Ok(response) = client.get(url).query(&[("q", "'")]).send().await {
        if let Ok(body) = response.text().await {
            let body_lower = body.to_lowercase();
            for err in &sql_errors {
                if body_lower.contains(err) {
                    vulnerabilities.push(Vulnerability {
                        id: "inj-sqli".to_string(),
                        title: "SQL Injection (SQLi)".to_string(),
                        description: "SQL error message triggered by single quote injection"
                            .to_string(),
                        severity: Severity::High,
                        confidence: Confidence::Firm,
                        category: "API8:2023 - Security Misconfiguration".to_string(),
                        location: url.to_string(),
                        evidence: format!("SQL error pattern '{}' found in response", err),
                        impact: "Database queries may be manipulated to extract or modify data"
                            .to_string(),
                        remediation: "Use parameterized queries and input validation".to_string(),
                        affected_endpoints: vec![url.to_string()],
                        ..Default::default()
                    });
                    break;
                }
            }
        }
    }

    // XSS: send a unique canary and check for reflection
    let xss_canary = "<scr1pt>xss_canary_8372</scr1pt>";
    if let Ok(response) = client.get(url).query(&[("q", xss_canary)]).send().await {
        if let Ok(body) = response.text().await {
            if body.contains(xss_canary) {
                vulnerabilities.push(Vulnerability {
                    id: "inj-xss".to_string(),
                    title: "Reflected Cross-Site Scripting (XSS)".to_string(),
                    description: "Injected HTML canary was reflected in response without encoding"
                        .to_string(),
                    severity: Severity::High,
                    confidence: Confidence::Firm,
                    category: "API8:2023 - Security Misconfiguration".to_string(),
                    location: url.to_string(),
                    evidence: format!("Canary '{}' reflected in response body", xss_canary),
                    impact: "Attacker can execute JavaScript in victim's browser".to_string(),
                    remediation: "Implement output encoding and Content-Security-Policy".to_string(),
                    affected_endpoints: vec![url.to_string()],
                        ..Default::default()
                });
            }
        }
    }

    // SSTI: use a unique multiplication that won't appear naturally
    let ssti_payload = "{{91283*91283}}";
    let ssti_result = "8332583289";
    if let Ok(response) = client.get(url).query(&[("q", ssti_payload)]).send().await {
        if let Ok(body) = response.text().await {
            if body.contains(ssti_result) {
                vulnerabilities.push(Vulnerability {
                    id: "inj-ssti".to_string(),
                    title: "Server-Side Template Injection (SSTI)".to_string(),
                    description: format!(
                        "Template expression {} evaluated to {}",
                        ssti_payload, ssti_result
                    ),
                    severity: Severity::Critical,
                    confidence: Confidence::Confirmed,
                    category: "API8:2023 - Security Misconfiguration".to_string(),
                    location: url.to_string(),
                    evidence: format!(
                        "Payload {} produced result {} in response",
                        ssti_payload, ssti_result
                    ),
                    impact: "Attacker can execute arbitrary code on the server".to_string(),
                    remediation: "Sanitize template inputs; use logic-less templates".to_string(),
                    affected_endpoints: vec![url.to_string()],
                        ..Default::default()
                });
            }
        }
    }

    Ok(vulnerabilities)
}

async fn test_auth_bypass(
    url: &str,
    client: &reqwest::Client,
    diff_threshold: usize,
) -> Result<Vec<Vulnerability>, Box<dyn std::error::Error + Send + Sync>> {
    let mut vulnerabilities = Vec::new();

    // Get baseline response
    let baseline = match client.get(url).send().await {
        Ok(resp) => {
            let status = resp.status().as_u16();
            let body_len = resp.text().await.unwrap_or_default().len();
            (status, body_len)
        }
        Err(_) => return Ok(vulnerabilities),
    };

    let bypass_headers = vec![
        ("X-Api-Version", "1"),
        ("Authorization", "Bearer null"),
        ("X-Forwarded-For", "127.0.0.1"),
        ("X-Original-URL", "/admin"),
        ("X-Rewrite-URL", "/admin"),
    ];

    for (header, value) in bypass_headers {
        if let Ok(response) = client.get(url).header(header, value).send().await {
            let status = response.status().as_u16();
            let is_ok = response.status() == reqwest::StatusCode::OK;
            let body_len = response.text().await.unwrap_or_default().len();

            let status_changed = status != baseline.0;
            let size_diff = (body_len as i64 - baseline.1 as i64).unsigned_abs() as usize;
            let meaningful_change = status_changed || size_diff > diff_threshold;

            if is_ok && meaningful_change {
                vulnerabilities.push(Vulnerability {
                    id: format!("auth-bypass-{}", header.to_lowercase().replace('-', "_")),
                    title: "Potential Authentication Bypass".to_string(),
                    description: format!(
                        "Response changed when {} header was added (status: {} -> {}, size diff: {} bytes)",
                        header, baseline.0, status, size_diff
                    ),
                    severity: Severity::Medium,
                    confidence: Confidence::Tentative,
                    category: "API2:2023 - Broken Authentication".to_string(),
                    location: url.to_string(),
                    evidence: format!(
                        "Header {}: {} changed response (baseline: {} {} bytes, test: {} {} bytes)",
                        header, value, baseline.0, baseline.1, status, body_len
                    ),
                    impact: "Authentication mechanisms may be weak or bypassable".to_string(),
                    remediation: "Review and strengthen authentication implementation".to_string(),
                    affected_endpoints: vec![url.to_string()],
                        ..Default::default()
                });
                break;
            }
        }
    }

    Ok(vulnerabilities)
}

async fn test_open_redirect(
    url: &str,
    _client: &reqwest::Client,
) -> Result<Vec<Vulnerability>, Box<dyn std::error::Error + Send + Sync>> {
    let mut vulnerabilities = Vec::new();

    let redirect_params = [
        "redirect", "redirect_to", "redirect_url", "url", "next", "return_to",
        "dest", "destination", "goto", "forward", "target", "continue", "rurl",
    ];
    let payloads = [
        "https://evil.example.com",
        "//evil.example.com",
        "/\\evil.example.com",
    ];

    let redir_client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(std::time::Duration::from_secs(10))
        .build()?;

    for param in &redirect_params {
        for payload in &payloads {
            if let Ok(response) = redir_client.get(url).query(&[(*param, *payload)]).send().await {
                if response.status().is_redirection() {
                    if let Some(location) = response.headers().get("location") {
                        if let Ok(loc) = location.to_str() {
                            let loc_lower = loc.to_lowercase();
                            if loc_lower.contains("evil.example.com") {
                                vulnerabilities.push(Vulnerability {
                                    id: "active-open-redirect".to_string(),
                                    title: "Open Redirect".to_string(),
                                    description: format!(
                                        "Parameter '{}' redirects to external URL without validation",
                                        param
                                    ),
                                    severity: Severity::Medium,
                                    confidence: Confidence::Firm,
                                    category: "CWE-601 - URL Redirection to Untrusted Site".to_string(),
                                    location: url.to_string(),
                                    evidence: format!("{}={} -> Location: {}", param, payload, loc),
                                    impact: "Attackers can redirect users to phishing sites using a trusted domain".to_string(),
                                    remediation: "Validate redirect targets against an allowlist".to_string(),
                                    affected_endpoints: vec![url.to_string()],
                        ..Default::default()
                                });
                                return Ok(vulnerabilities);
                            }
                        }
                    }
                }
            }
        }
    }

    Ok(vulnerabilities)
}

async fn test_path_traversal(
    url: &str,
    client: &reqwest::Client,
) -> Result<Vec<Vulnerability>, Box<dyn std::error::Error + Send + Sync>> {
    let mut vulnerabilities = Vec::new();

    let file_params = ["file", "path", "template", "document", "page", "include", "dir", "folder", "load", "read"];
    let payloads = [
        ("../../../etc/passwd", &["root:", "bin:", "daemon:", "nobody:"] as &[&str]),
        ("....//....//....//etc/passwd", &["root:", "bin:", "daemon:"]),
        ("..\\..\\..\\windows\\win.ini", &["[extensions]", "[fonts]"]),
    ];

    for param in &file_params {
        for (payload, signatures) in &payloads {
            if let Ok(response) = client.get(url).query(&[(*param, *payload)]).send().await {
                if response.status().is_success() {
                    if let Ok(body) = response.text().await {
                        let body_lower = body.to_lowercase();
                        let matched = signatures.iter().any(|sig| body_lower.contains(&sig.to_lowercase()));
                        if matched {
                            vulnerabilities.push(Vulnerability {
                                id: "active-path-traversal".to_string(),
                                title: "Path Traversal / Directory Traversal".to_string(),
                                description: format!(
                                    "Parameter '{}' allows reading files outside the web root",
                                    param
                                ),
                                severity: Severity::High,
                                confidence: Confidence::Firm,
                                category: "CWE-22 - Path Traversal".to_string(),
                                location: url.to_string(),
                                evidence: format!("{}={} returned file content signatures", param, payload),
                                impact: "Attackers can read sensitive system files and source code".to_string(),
                                remediation: "Validate and canonicalize file paths; use a whitelist of allowed files".to_string(),
                                affected_endpoints: vec![url.to_string()],
                        ..Default::default()
                            });
                            return Ok(vulnerabilities);
                        }
                    }
                }
            }
        }
    }

    Ok(vulnerabilities)
}

async fn test_cors_reflection(
    url: &str,
    client: &reqwest::Client,
) -> Result<Vec<Vulnerability>, Box<dyn std::error::Error + Send + Sync>> {
    let mut vulnerabilities = Vec::new();

    let evil_origin = "https://evil.example.com";
    if let Ok(response) = client.get(url).header("Origin", evil_origin).send().await {
        let headers = response.headers();
        if let Some(acao) = headers.get("access-control-allow-origin") {
            if let Ok(acao_str) = acao.to_str() {
                if acao_str.contains("evil.example.com") {
                    let has_creds = headers.get("access-control-allow-credentials")
                        .and_then(|v| v.to_str().ok())
                        .map(|v| v.eq_ignore_ascii_case("true"))
                        .unwrap_or(false);
                    if has_creds {
                        vulnerabilities.push(Vulnerability {
                            id: "active-cors-reflection".to_string(),
                            title: "CORS Origin Reflection with Credentials".to_string(),
                            description: "Server reflects arbitrary Origin with Access-Control-Allow-Credentials: true".to_string(),
                            severity: Severity::High,
                            confidence: Confidence::Confirmed,
                            category: "CWE-942 - Permissive Cross-domain Policy".to_string(),
                            location: url.to_string(),
                            evidence: format!("Origin: {} reflected in ACAO with credentials", evil_origin),
                            impact: "Any website can make authenticated cross-origin requests and steal user data".to_string(),
                            remediation: "Validate Origin against an allowlist; never reflect arbitrary origins with credentials".to_string(),
                            affected_endpoints: vec![url.to_string()],
                        ..Default::default()
                        });
                    } else {
                        vulnerabilities.push(Vulnerability {
                            id: "active-cors-reflection".to_string(),
                            title: "CORS Origin Reflection".to_string(),
                            description: "Server reflects arbitrary Origin in Access-Control-Allow-Origin".to_string(),
                            severity: Severity::Medium,
                            confidence: Confidence::Confirmed,
                            category: "CWE-942 - Permissive Cross-domain Policy".to_string(),
                            location: url.to_string(),
                            evidence: format!("Origin: {} reflected in ACAO (no credentials)", evil_origin),
                            impact: "API responses may be readable from any origin".to_string(),
                            remediation: "Validate Origin against an allowlist".to_string(),
                            affected_endpoints: vec![url.to_string()],
                        ..Default::default()
                        });
                    }
                }
            }
        }
    }

    Ok(vulnerabilities)
}

async fn test_xss_enhanced(
    url: &str,
    client: &reqwest::Client,
) -> Result<Vec<Vulnerability>, Box<dyn std::error::Error + Send + Sync>> {
    let mut vulnerabilities = Vec::new();

    let params = ["q", "search", "query", "name", "input", "value", "s", "keyword"];

    let attr_payload = "xss\"onmouseover=\"alert(73519)\"x=\"";
    let attr_marker = "onmouseover=\"alert(73519)\"";

    for param in &params {
        if let Ok(response) = client.get(url).query(&[(*param, attr_payload)]).send().await {
            if let Ok(body) = response.text().await {
                if body.contains(attr_marker) {
                    vulnerabilities.push(Vulnerability {
                        id: "active-xss-attr".to_string(),
                        title: "XSS via Attribute Injection".to_string(),
                        description: format!(
                            "Parameter '{}' reflects input inside HTML attributes without encoding",
                            param
                        ),
                        severity: Severity::High,
                        confidence: Confidence::Firm,
                        category: "CWE-79 - Cross-site Scripting".to_string(),
                        location: url.to_string(),
                        evidence: format!("{}={} reflected as attribute injection", param, attr_payload),
                        impact: "Attackers can execute JavaScript via crafted attribute values".to_string(),
                        remediation: "Apply attribute-context output encoding; implement CSP".to_string(),
                        affected_endpoints: vec![url.to_string()],
                        ..Default::default()
                    });
                    return Ok(vulnerabilities);
                }
            }
        }
    }

    let event_payload = "<img src=x onerror=alert(73519)>";
    let event_marker = "onerror=alert(73519)";

    for param in &params {
        if let Ok(response) = client.get(url).query(&[(*param, event_payload)]).send().await {
            if let Ok(body) = response.text().await {
                if body.contains(event_marker) {
                    vulnerabilities.push(Vulnerability {
                        id: "active-xss-event".to_string(),
                        title: "XSS via Event Handler Injection".to_string(),
                        description: format!(
                            "Parameter '{}' allows injection of HTML event handlers",
                            param
                        ),
                        severity: Severity::High,
                        confidence: Confidence::Firm,
                        category: "CWE-79 - Cross-site Scripting".to_string(),
                        location: url.to_string(),
                        evidence: format!("{}={} reflected with event handler", param, event_payload),
                        impact: "Attackers can execute arbitrary JavaScript".to_string(),
                        remediation: "Encode all user input in HTML contexts; implement CSP".to_string(),
                        affected_endpoints: vec![url.to_string()],
                        ..Default::default()
                    });
                    return Ok(vulnerabilities);
                }
            }
        }
    }

    Ok(vulnerabilities)
}

async fn test_csrf_active(
    url: &str,
    client: &reqwest::Client,
) -> Result<Vec<Vulnerability>, Box<dyn std::error::Error + Send + Sync>> {
    let mut vulnerabilities = Vec::new();

    if let Ok(response) = client.get(url).send().await {
        if let Ok(body) = response.text().await {
            let body_lower = body.to_lowercase();
            if body_lower.contains("<form") && (body_lower.contains("method=\"post\"") || body_lower.contains("method='post'")) {
                let action = extract_form_action(&body_lower, url);
                if let Some(form_url) = action {
                    if let Ok(post_resp) = client.post(&form_url)
                        .header("Content-Type", "application/x-www-form-urlencoded")
                        .body("test=1")
                        .send().await
                    {
                        let status = post_resp.status().as_u16();
                        if status == 200 || status == 302 || status == 303 {
                            vulnerabilities.push(Vulnerability {
                                id: "active-csrf-no-token".to_string(),
                                title: "CSRF: Form Accepts Request Without Token".to_string(),
                                description: format!("POST to {} accepted without CSRF token (status: {})", form_url, status),
                                severity: Severity::Medium,
                                confidence: Confidence::Firm,
                                category: "CWE-352 - Cross-Site Request Forgery".to_string(),
                                location: url.to_string(),
                                evidence: format!("POST {} without token returned {}", form_url, status),
                                impact: "Attackers can forge requests on behalf of authenticated users".to_string(),
                                remediation: "Require and validate CSRF tokens on all state-changing requests".to_string(),
                                affected_endpoints: vec![form_url],
                        ..Default::default()
                            });
                        }
                    }
                }
            }
        }
    }

    Ok(vulnerabilities)
}

fn extract_form_action(body_lower: &str, base_url: &str) -> Option<String> {
    if let Some(form_pos) = body_lower.find("<form") {
        let form_slice = &body_lower[form_pos..];
        let end = form_slice.find('>').unwrap_or(form_slice.len());
        let form_tag = &form_slice[..end];
        if let Some(action_pos) = form_tag.find("action=") {
            let after_action = &form_tag[action_pos + 7..];
            let quote = after_action.chars().next().unwrap_or('"');
            if quote == '"' || quote == '\'' {
                let inner = &after_action[1..];
                if let Some(end_quote) = inner.find(quote) {
                    let action = &inner[..end_quote];
                    if action.starts_with("http") {
                        return Some(action.to_string());
                    } else {
                        return Some(format!("{}{}", base_url.trim_end_matches('/'), if action.starts_with('/') { action.to_string() } else { format!("/{}", action) }));
                    }
                }
            }
        }
        return Some(base_url.to_string());
    }
    None
}
