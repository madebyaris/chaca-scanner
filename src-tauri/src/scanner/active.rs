use crate::{Confidence, ScanConfig, Severity, Vulnerability};
use reqwest::header::LOCATION;
use tracing::info;

use super::domain::{
    apply_endpoint_defaults, EndpointInventory, EndpointTag, EvidenceBundle, FindingFingerprint,
    HttpMethod, InventoryEndpoint, ParameterLocation, RequestContext, ScanRuntime,
};

struct ResponseSnapshot {
    status: u16,
    body: String,
}

impl ResponseSnapshot {
    fn len(&self) -> usize {
        self.body.len()
    }
}

pub async fn test_vulnerabilities(
    url: &str,
    config: &ScanConfig,
) -> Result<Vec<Vulnerability>, Box<dyn std::error::Error + Send + Sync>> {
    let runtime = ScanRuntime::new(config)?;
    let mut inventory = EndpointInventory::new(url);
    inventory.endpoints.push(InventoryEndpoint {
        url: url.to_string(),
        normalized_location: super::domain::normalize_fingerprint_location(url),
        method: HttpMethod::Get,
        source: super::domain::EndpointSource::Seed,
        tags: vec![EndpointTag::Api],
        parameters: Vec::new(),
        depth: 0,
        last_status: None,
        baseline_length: None,
    });
    let noop_emitter = super::engine::ProgressEmitter::new(None);
    test_inventory(&inventory, &runtime, config, &noop_emitter).await
}

pub async fn test_inventory(
    inventory: &EndpointInventory,
    runtime: &ScanRuntime,
    config: &ScanConfig,
    emitter: &super::engine::ProgressEmitter,
) -> Result<Vec<Vulnerability>, Box<dyn std::error::Error + Send + Sync>> {
    let candidates: Vec<&InventoryEndpoint> = inventory.active_candidates().collect();
    let total = candidates.len();
    info!(
        "Running active vulnerability tests across {} endpoints",
        total
    );

    let mut vulnerabilities = Vec::new();
    for (i, endpoint) in candidates.iter().enumerate() {
        if crate::cancel_scan_requested() {
            return Err("Scan cancelled".into());
        }
        let pct = 70 + (i as u32 * 19 / total.max(1) as u32);
        let short = short_endpoint_label(&endpoint.url);
        emitter.emit_detail(
            "active",
            pct,
            100,
            &format!("Testing endpoint {}/{}", i + 1, total),
            &short,
        );

        let Some(baseline) = fetch_baseline(endpoint, runtime, config).await else {
            continue;
        };

        let checks: &[(&str, bool)] = &[
            ("BOLA", config.active_bola),
            ("SSRF", config.active_ssrf),
            ("Injection (SQLi/XSS/SSTI)", config.active_injection),
            ("Auth Bypass", config.active_auth_bypass),
            ("Open Redirect", config.active_open_redirect),
            ("Path Traversal", config.active_path_traversal),
            ("CORS Reflection", config.active_cors_reflection),
            ("XSS Enhanced", config.active_xss_enhanced),
            ("CSRF Verify", config.active_csrf_verify),
            ("GraphQL", config.active_graphql),
            ("Resource Consumption", config.active_resource_consumption),
        ];

        for (check_name, enabled) in checks {
            if !enabled {
                continue;
            }
            emitter.emit_detail(
                "active",
                pct,
                100,
                &format!("Testing endpoint {}/{}", i + 1, total),
                &format!("{} → {}", check_name, short),
            );

            let results = match *check_name {
                "BOLA" => test_bola(endpoint, &baseline, runtime, config).await?,
                "SSRF" => test_ssrf(endpoint, &baseline, runtime, config).await?,
                "Injection (SQLi/XSS/SSTI)" => test_injection(endpoint, runtime, config).await?,
                "Auth Bypass" => test_auth_bypass(endpoint, &baseline, runtime, config).await?,
                "Open Redirect" => test_open_redirect(endpoint, runtime, config).await?,
                "Path Traversal" => test_path_traversal(endpoint, runtime, config).await?,
                "CORS Reflection" => test_cors_reflection(endpoint, runtime, config).await?,
                "XSS Enhanced" => test_xss_enhanced(endpoint, runtime, config).await?,
                "CSRF Verify" => test_csrf_active(endpoint, runtime, config).await?,
                "GraphQL" => test_graphql(endpoint, runtime, config).await?,
                "Resource Consumption" => {
                    test_resource_consumption(endpoint, &baseline, runtime, config).await?
                }
                _ => Vec::new(),
            };
            vulnerabilities.extend(results);
        }
    }

    Ok(vulnerabilities)
}

fn short_endpoint_label(url: &str) -> String {
    if let Ok(parsed) = url::Url::parse(url) {
        let path = parsed.path();
        if path.len() > 50 {
            format!("...{}", &path[path.len() - 47..])
        } else {
            path.to_string()
        }
    } else {
        url.to_string()
    }
}

async fn fetch_baseline(
    endpoint: &InventoryEndpoint,
    runtime: &ScanRuntime,
    config: &ScanConfig,
) -> Option<ResponseSnapshot> {
    let context = RequestContext::from_scan_config(endpoint.method, &endpoint.url, config)
        .with_label("baseline");
    let response = runtime
        .execute_request(apply_endpoint_defaults(
            context.into_builder(runtime.client()),
            endpoint,
            "baseline",
        ))
        .await
        .ok()?;
    let status = response.status().as_u16();
    let body = response.text().await.ok()?;
    Some(ResponseSnapshot { status, body })
}

async fn test_bola(
    endpoint: &InventoryEndpoint,
    baseline: &ResponseSnapshot,
    runtime: &ScanRuntime,
    config: &ScanConfig,
) -> Result<Vec<Vulnerability>, Box<dyn std::error::Error + Send + Sync>> {
    let mut vulnerabilities = Vec::new();

    let id_like_params = candidate_params(
        endpoint,
        &[
            "id", "user", "account", "object", "record", "order", "invoice",
        ],
        &["id", "user_id", "account_id"],
        &[
            ParameterLocation::Query,
            ParameterLocation::Path,
            ParameterLocation::Form,
        ],
    );
    for param in id_like_params {
        for payload in ["1", "2", "admin", "99999999"] {
            if let Some(response) =
                send_param_probe(endpoint, runtime, config, &param, payload, "bola").await?
            {
                let diff = response.len().abs_diff(baseline.len());
                if response.status == 200 && diff > config.bola_diff_threshold {
                    let mut evidence = EvidenceBundle::new(
                        "Object reference mutation produced a materially different response.",
                    )
                    .with_request(
                        RequestContext::from_scan_config(HttpMethod::Get, &endpoint.url, config)
                            .with_label("bola"),
                    );
                    evidence.push_comparison(
                        "baseline_vs_probe",
                        format!(
                            "baseline={} bytes, probe={} bytes, param={} payload={}",
                            baseline.len(),
                            response.len(),
                            param,
                            payload
                        ),
                    );
                    vulnerabilities.push(build_vulnerability(
                        "active-bola",
                        "Potential Broken Object Level Authorization (BOLA)",
                        format!(
                            "Parameter '{}' appears to expose different object data when set to '{}'.",
                            param, payload
                        ),
                        Severity::High,
                        Confidence::Tentative,
                        "API1:2023 - Broken Object Level Authorization",
                        endpoint,
                        FindingFingerprint::for_param(
                            "active-bola",
                            Severity::High,
                            endpoint.method,
                            &endpoint.url,
                            &param,
                        ),
                        evidence,
                        "Unauthorized users may access data belonging to other objects or tenants.",
                        "Enforce server-side object authorization checks on every object reference.",
                    ));
                    return Ok(vulnerabilities);
                }
            }
        }
    }

    Ok(vulnerabilities)
}

async fn test_ssrf(
    endpoint: &InventoryEndpoint,
    baseline: &ResponseSnapshot,
    runtime: &ScanRuntime,
    config: &ScanConfig,
) -> Result<Vec<Vulnerability>, Box<dyn std::error::Error + Send + Sync>> {
    let mut vulnerabilities = Vec::new();
    let baseline_lower = baseline.body.to_lowercase();
    let baseline_has_internal = contains_internal_reference(&baseline_lower);
    let params = candidate_params(
        endpoint,
        &[
            "url", "uri", "callback", "image", "avatar", "link", "redirect", "endpoint",
        ],
        &["url", "callback_url", "image_url"],
        &[ParameterLocation::Query, ParameterLocation::Form],
    );
    for param in params {
        for payload in ["http://localhost/", "http://127.0.0.1/", "http://[::1]/"] {
            if let Some(response) =
                send_param_probe(endpoint, runtime, config, &param, payload, "ssrf").await?
            {
                let lowered = response.body.to_lowercase();
                if contains_internal_reference(&lowered) && !baseline_has_internal {
                    let mut evidence = EvidenceBundle::new(
                        "Internal network indicators appeared only after an SSRF-style URL probe.",
                    )
                    .with_request(
                        RequestContext::from_scan_config(HttpMethod::Get, &endpoint.url, config)
                            .with_label("ssrf"),
                    );
                    evidence.push_match("param", param.clone());
                    evidence.push_match("payload", payload.to_string());
                    evidence.push_status(response.status);
                    vulnerabilities.push(build_vulnerability(
                        "active-ssrf",
                        "Potential Server-Side Request Forgery (SSRF)",
                        format!(
                            "Parameter '{}' appears to fetch or reflect internal network locations.",
                            param
                        ),
                        Severity::Critical,
                        Confidence::Firm,
                        "API7:2023 - Server-Side Request Forgery",
                        endpoint,
                        FindingFingerprint::for_param(
                            "active-ssrf",
                            Severity::Critical,
                            endpoint.method,
                            &endpoint.url,
                            &param,
                        ),
                        evidence,
                        "Attackers may pivot into internal services or cloud metadata endpoints.",
                        "Validate outbound targets with an allowlist and block private network ranges.",
                    ));
                    return Ok(vulnerabilities);
                }
            }
        }
    }

    Ok(vulnerabilities)
}

async fn test_injection(
    endpoint: &InventoryEndpoint,
    runtime: &ScanRuntime,
    config: &ScanConfig,
) -> Result<Vec<Vulnerability>, Box<dyn std::error::Error + Send + Sync>> {
    let mut vulnerabilities = Vec::new();
    let params = candidate_params(
        endpoint,
        &[
            "q", "search", "query", "name", "input", "value", "keyword", "term",
        ],
        &["q", "search", "query"],
        &[ParameterLocation::Query, ParameterLocation::Form],
    );

    let sql_errors = [
        "sql syntax",
        "mysql_",
        "pg_query",
        "sqlite3",
        "ora-",
        "quoted string not properly terminated",
        "syntax error at or near",
        "you have an error in your sql",
    ];

    for param in &params {
        if let Some(response) =
            send_param_probe(endpoint, runtime, config, param, "'", "sqli").await?
        {
            let lowered = response.body.to_lowercase();
            if let Some(error) = sql_errors.iter().find(|item| lowered.contains(**item)) {
                let mut evidence = EvidenceBundle::new(
                    "A single-quote payload triggered a database-style error message.",
                );
                evidence.push_match("param", param.clone());
                evidence.push_match("error", (*error).to_string());
                vulnerabilities.push(build_vulnerability(
                    "active-sqli",
                    "SQL Injection (SQLi)",
                    format!(
                        "Parameter '{}' appears to trigger SQL error feedback.",
                        param
                    ),
                    Severity::High,
                    Confidence::Firm,
                    "CWE-89 - SQL Injection",
                    endpoint,
                    FindingFingerprint::for_param(
                        "active-sqli",
                        Severity::High,
                        endpoint.method,
                        &endpoint.url,
                        param,
                    ),
                    evidence,
                    "Attackers may extract, corrupt, or modify backend data.",
                    "Use parameterized queries and strict input validation.",
                ));
                return Ok(vulnerabilities);
            }
        }
    }

    for param in &params {
        let xss_payload = "<scr1pt>xss_canary_8372</scr1pt>";
        if let Some(response) =
            send_param_probe(endpoint, runtime, config, param, xss_payload, "xss").await?
        {
            if response.body.contains(xss_payload) {
                let mut evidence = EvidenceBundle::new(
                    "A unique HTML canary was reflected without output encoding.",
                );
                evidence.push_match("param", param.clone());
                evidence.push_match("payload", xss_payload.to_string());
                vulnerabilities.push(build_vulnerability(
                    "active-xss",
                    "Reflected Cross-Site Scripting (XSS)",
                    format!(
                        "Parameter '{}' reflects HTML input back into the response.",
                        param
                    ),
                    Severity::High,
                    Confidence::Firm,
                    "CWE-79 - Cross-site Scripting",
                    endpoint,
                    FindingFingerprint::for_param(
                        "active-xss",
                        Severity::High,
                        endpoint.method,
                        &endpoint.url,
                        param,
                    ),
                    evidence,
                    "Attackers may execute script in a victim browser under the trusted origin.",
                    "Encode output for the correct HTML context and enforce a restrictive CSP.",
                ));
                return Ok(vulnerabilities);
            }
        }
    }

    for param in &params {
        let ssti_payload = "{{91283*91283}}";
        let ssti_result = "8332583289";
        if let Some(response) =
            send_param_probe(endpoint, runtime, config, param, ssti_payload, "ssti").await?
        {
            if response.body.contains(ssti_result) {
                let mut evidence =
                    EvidenceBundle::new("A template expression was evaluated server-side.");
                evidence.push_match("param", param.clone());
                evidence.push_match("payload", ssti_payload.to_string());
                vulnerabilities.push(build_vulnerability(
                    "active-ssti",
                    "Server-Side Template Injection (SSTI)",
                    format!(
                        "Parameter '{}' appears to evaluate template expressions on the server.",
                        param
                    ),
                    Severity::Critical,
                    Confidence::Confirmed,
                    "CWE-1336 - Improper Neutralization of Special Elements Used in a Template Engine",
                    endpoint,
                    FindingFingerprint::for_param(
                        "active-ssti",
                        Severity::Critical,
                        endpoint.method,
                        &endpoint.url,
                        param,
                    ),
                    evidence,
                    "Attackers may execute server-side code or read sensitive server data.",
                    "Sanitize template inputs and prefer logic-less rendering where possible.",
                ));
                return Ok(vulnerabilities);
            }
        }
    }

    Ok(vulnerabilities)
}

async fn test_auth_bypass(
    endpoint: &InventoryEndpoint,
    baseline: &ResponseSnapshot,
    runtime: &ScanRuntime,
    config: &ScanConfig,
) -> Result<Vec<Vulnerability>, Box<dyn std::error::Error + Send + Sync>> {
    let mut vulnerabilities = Vec::new();
    let lower = endpoint.url.to_lowercase();
    if !endpoint.tags.contains(&EndpointTag::Admin)
        && !endpoint.tags.contains(&EndpointTag::AuthRelated)
        && !lower.contains("/admin")
        && !lower.contains("/internal")
        && !lower.contains("/private")
    {
        return Ok(vulnerabilities);
    }

    for (header, value) in [
        ("X-Forwarded-For", "127.0.0.1"),
        ("X-Original-URL", "/admin"),
        ("X-Rewrite-URL", "/admin"),
        ("Authorization", "Bearer null"),
    ] {
        let context = RequestContext::from_scan_config(HttpMethod::Get, &endpoint.url, config)
            .with_label("auth_bypass")
            .with_header(header, value);
        let response = runtime
            .execute_request(context.clone().into_builder(runtime.client()))
            .await;
        if let Ok(response) = response {
            let status = response.status().as_u16();
            let body = response.text().await.unwrap_or_default();
            let diff = body.len().abs_diff(baseline.len());
            if status == 200
                && (status != baseline.status || diff > config.auth_bypass_diff_threshold)
            {
                let mut evidence = EvidenceBundle::new(
                    "A spoofed upstream header changed the authentication response shape.",
                )
                .with_request(context);
                evidence.push_comparison(
                    "baseline_vs_probe",
                    format!(
                        "baseline_status={} probe_status={} baseline_len={} probe_len={}",
                        baseline.status,
                        status,
                        baseline.len(),
                        body.len()
                    ),
                );
                vulnerabilities.push(build_vulnerability(
                    "active-auth-bypass",
                    "Potential Authentication Bypass",
                    format!(
                        "Endpoint behavior changed when '{}' was injected into the request.",
                        header
                    ),
                    Severity::Medium,
                    Confidence::Tentative,
                    "API2:2023 - Broken Authentication",
                    endpoint,
                    FindingFingerprint::for_endpoint(
                        format!("active-auth-bypass:{}", header),
                        Severity::Medium,
                        endpoint.method,
                        &endpoint.url,
                    ),
                    evidence,
                    "Attackers may be able to bypass auth or route requests into privileged handlers.",
                    "Validate upstream trust boundaries and ignore spoofable routing headers.",
                ));
                return Ok(vulnerabilities);
            }
        }
    }

    Ok(vulnerabilities)
}

async fn test_open_redirect(
    endpoint: &InventoryEndpoint,
    _runtime: &ScanRuntime,
    config: &ScanConfig,
) -> Result<Vec<Vulnerability>, Box<dyn std::error::Error + Send + Sync>> {
    let mut vulnerabilities = Vec::new();
    let params = candidate_params(
        endpoint,
        &[
            "redirect", "url", "next", "return", "dest", "goto", "forward", "target",
        ],
        &["redirect", "next", "return_to"],
        &[ParameterLocation::Query, ParameterLocation::Form],
    );
    let redir_client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(std::time::Duration::from_secs(config.http_timeout_secs))
        .danger_accept_invalid_certs(config.accept_invalid_certs)
        .build()?;

    for param in params {
        for payload in [
            "https://evil.example.com",
            "//evil.example.com",
            "/\\evil.example.com",
        ] {
            let context = RequestContext::from_scan_config(endpoint.method, &endpoint.url, config)
                .with_label("redirect");
            let builder = apply_param(
                context.into_builder(&redir_client),
                endpoint,
                &param,
                payload,
            );
            let response = builder.send().await;
            if let Ok(response) = response {
                if response.status().is_redirection() {
                    if let Some(location) = response.headers().get(LOCATION) {
                        if let Ok(location) = location.to_str() {
                            if location.to_lowercase().contains("evil.example.com") {
                                let mut evidence = EvidenceBundle::new(
                                    "A redirect-style parameter sent the browser to an external destination.",
                                );
                                evidence.push_match("param", param.clone());
                                evidence.push_match("payload", payload.to_string());
                                evidence.push_header("location", location.to_string());
                                vulnerabilities.push(build_vulnerability(
                                    "active-open-redirect",
                                    "Open Redirect",
                                    format!(
                                        "Parameter '{}' redirects users to an external destination without validation.",
                                        param
                                    ),
                                    Severity::Medium,
                                    Confidence::Firm,
                                    "CWE-601 - URL Redirection to Untrusted Site",
                                    endpoint,
                                    FindingFingerprint::for_param(
                                        "active-open-redirect",
                                        Severity::Medium,
                                        endpoint.method,
                                        &endpoint.url,
                                        &param,
                                    ),
                                    evidence,
                                    "Attackers may turn trusted links into phishing or token-stealing redirects.",
                                    "Validate redirect destinations against an allowlist.",
                                ));
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
    endpoint: &InventoryEndpoint,
    runtime: &ScanRuntime,
    config: &ScanConfig,
) -> Result<Vec<Vulnerability>, Box<dyn std::error::Error + Send + Sync>> {
    let mut vulnerabilities = Vec::new();
    let params = candidate_params(
        endpoint,
        &[
            "file", "path", "template", "document", "page", "include", "dir", "folder", "load",
        ],
        &["file", "path", "template"],
        &[ParameterLocation::Query, ParameterLocation::Form],
    );
    for param in params {
        for (payload, signatures) in [
            ("../../../etc/passwd", vec!["root:", "daemon:", "bin:"]),
            ("....//....//....//etc/passwd", vec!["root:", "daemon:"]),
            (
                "..\\..\\..\\windows\\win.ini",
                vec!["[extensions]", "[fonts]"],
            ),
        ] {
            if let Some(response) =
                send_param_probe(endpoint, runtime, config, &param, payload, "path_traversal")
                    .await?
            {
                let lowered = response.body.to_lowercase();
                if signatures
                    .iter()
                    .any(|signature| lowered.contains(&signature.to_lowercase()))
                {
                    let mut evidence = EvidenceBundle::new(
                        "A file path probe returned contents matching a system file.",
                    );
                    evidence.push_match("param", param.clone());
                    evidence.push_match("payload", payload.to_string());
                    vulnerabilities.push(build_vulnerability(
                        "active-path-traversal",
                        "Path Traversal / Directory Traversal",
                        format!(
                            "Parameter '{}' appears to allow file reads outside the intended directory.",
                            param
                        ),
                        Severity::High,
                        Confidence::Firm,
                        "CWE-22 - Path Traversal",
                        endpoint,
                        FindingFingerprint::for_param(
                            "active-path-traversal",
                            Severity::High,
                            endpoint.method,
                            &endpoint.url,
                            &param,
                        ),
                        evidence,
                        "Attackers may read source code, credentials, or system configuration files.",
                        "Canonicalize file paths and whitelist allowed resources.",
                    ));
                    return Ok(vulnerabilities);
                }
            }
        }
    }

    Ok(vulnerabilities)
}

async fn test_cors_reflection(
    endpoint: &InventoryEndpoint,
    runtime: &ScanRuntime,
    config: &ScanConfig,
) -> Result<Vec<Vulnerability>, Box<dyn std::error::Error + Send + Sync>> {
    let mut vulnerabilities = Vec::new();
    let evil_origin = "https://evil.example.com";
    let context = RequestContext::from_scan_config(HttpMethod::Get, &endpoint.url, config)
        .with_label("cors")
        .with_header("Origin", evil_origin);
    let response = runtime
        .execute_request(context.into_builder(runtime.client()))
        .await;
    if let Ok(response) = response {
        if let Some(acao) = response.headers().get("access-control-allow-origin") {
            if let Ok(acao) = acao.to_str() {
                if acao.contains("evil.example.com") {
                    let has_creds = response
                        .headers()
                        .get("access-control-allow-credentials")
                        .and_then(|value| value.to_str().ok())
                        .map(|value| value.eq_ignore_ascii_case("true"))
                        .unwrap_or(false);
                    let mut evidence = EvidenceBundle::new(
                        "The server reflected an untrusted Origin header in the CORS policy.",
                    );
                    evidence.push_header("acao", acao.to_string());
                    if has_creds {
                        evidence.push_header("allow_credentials", "true".to_string());
                    }
                    vulnerabilities.push(build_vulnerability(
                        "active-cors-reflection",
                        if has_creds {
                            "CORS Origin Reflection with Credentials"
                        } else {
                            "CORS Origin Reflection"
                        },
                        "The server reflects arbitrary origins in CORS response headers.".to_string(),
                        if has_creds { Severity::High } else { Severity::Medium },
                        Confidence::Confirmed,
                        "CWE-942 - Permissive Cross-domain Policy",
                        endpoint,
                        FindingFingerprint::for_endpoint(
                            "active-cors-reflection",
                            if has_creds { Severity::High } else { Severity::Medium },
                            endpoint.method,
                            &endpoint.url,
                        ),
                        evidence,
                        "Any website may be able to read privileged responses through the victim browser.",
                        "Restrict allowed origins to a trusted allowlist and avoid reflecting arbitrary values.",
                    ));
                }
            }
        }
    }

    Ok(vulnerabilities)
}

async fn test_xss_enhanced(
    endpoint: &InventoryEndpoint,
    runtime: &ScanRuntime,
    config: &ScanConfig,
) -> Result<Vec<Vulnerability>, Box<dyn std::error::Error + Send + Sync>> {
    let mut vulnerabilities = Vec::new();
    let params = candidate_params(
        endpoint,
        &[
            "q", "search", "query", "name", "input", "value", "keyword", "comment",
        ],
        &["q", "search", "query"],
        &[ParameterLocation::Query, ParameterLocation::Form],
    );

    for param in &params {
        let payload = "xss\"onmouseover=\"alert(73519)\"x=\"";
        if let Some(response) =
            send_param_probe(endpoint, runtime, config, param, payload, "xss_attr").await?
        {
            if response.body.contains("onmouseover=\"alert(73519)\"") {
                let mut evidence = EvidenceBundle::new(
                    "User input was reflected into an HTML attribute context without encoding.",
                );
                evidence.push_match("param", param.clone());
                evidence.push_match("payload", payload.to_string());
                vulnerabilities.push(build_vulnerability(
                    "active-xss-attr",
                    "XSS via Attribute Injection",
                    format!(
                        "Parameter '{}' appears to inject into HTML attributes.",
                        param
                    ),
                    Severity::High,
                    Confidence::Firm,
                    "CWE-79 - Cross-site Scripting",
                    endpoint,
                    FindingFingerprint::for_param(
                        "active-xss-attr",
                        Severity::High,
                        endpoint.method,
                        &endpoint.url,
                        param,
                    ),
                    evidence,
                    "Attackers may trigger script execution via crafted attribute payloads.",
                    "Apply attribute-context encoding and tighten CSP.",
                ));
                return Ok(vulnerabilities);
            }
        }
    }

    for param in &params {
        let payload = "<img src=x onerror=alert(73519)>";
        if let Some(response) =
            send_param_probe(endpoint, runtime, config, param, payload, "xss_event").await?
        {
            if response.body.contains("onerror=alert(73519)") {
                let mut evidence =
                    EvidenceBundle::new("User input was reflected with a live HTML event handler.");
                evidence.push_match("param", param.clone());
                evidence.push_match("payload", payload.to_string());
                vulnerabilities.push(build_vulnerability(
                    "active-xss-event",
                    "XSS via Event Handler Injection",
                    format!(
                        "Parameter '{}' appears to allow event-handler injection.",
                        param
                    ),
                    Severity::High,
                    Confidence::Firm,
                    "CWE-79 - Cross-site Scripting",
                    endpoint,
                    FindingFingerprint::for_param(
                        "active-xss-event",
                        Severity::High,
                        endpoint.method,
                        &endpoint.url,
                        param,
                    ),
                    evidence,
                    "Attackers may execute arbitrary script in the browser.",
                    "Encode untrusted input and render it only in safe contexts.",
                ));
                return Ok(vulnerabilities);
            }
        }
    }

    Ok(vulnerabilities)
}

async fn test_csrf_active(
    endpoint: &InventoryEndpoint,
    runtime: &ScanRuntime,
    config: &ScanConfig,
) -> Result<Vec<Vulnerability>, Box<dyn std::error::Error + Send + Sync>> {
    let mut vulnerabilities = Vec::new();
    if endpoint.method != HttpMethod::Post || !endpoint.tags.contains(&EndpointTag::Form) {
        return Ok(vulnerabilities);
    }
    let has_csrf_param = endpoint.parameters.iter().any(|parameter| {
        parameter.name.to_lowercase().contains("csrf")
            || parameter.name.to_lowercase().contains("token")
    });
    if has_csrf_param {
        return Ok(vulnerabilities);
    }

    let context = RequestContext::from_scan_config(HttpMethod::Post, &endpoint.url, config)
        .with_label("csrf");
    let response = runtime
        .execute_request(
            context
                .into_builder(runtime.client())
                .header("Content-Type", "application/x-www-form-urlencoded")
                .body("test=1"),
        )
        .await;
    if let Ok(response) = response {
        let status = response.status().as_u16();
        if matches!(status, 200 | 201 | 202 | 204 | 302 | 303) {
            let mut evidence = EvidenceBundle::new(
                "A state-changing form endpoint accepted a request without a CSRF token.",
            );
            evidence.push_status(status);
            vulnerabilities.push(build_vulnerability(
                "active-csrf-no-token",
                "CSRF: Form Accepts Request Without Token",
                "A POST form endpoint accepted a request without an anti-CSRF token.".to_string(),
                Severity::Medium,
                Confidence::Firm,
                "CWE-352 - Cross-Site Request Forgery",
                endpoint,
                FindingFingerprint::for_endpoint(
                    "active-csrf-no-token",
                    Severity::Medium,
                    endpoint.method,
                    &endpoint.url,
                ),
                evidence,
                "Attackers may forge requests on behalf of authenticated victims.",
                "Require and verify CSRF tokens on all state-changing routes.",
            ));
        }
    }

    Ok(vulnerabilities)
}

async fn test_graphql(
    endpoint: &InventoryEndpoint,
    runtime: &ScanRuntime,
    config: &ScanConfig,
) -> Result<Vec<Vulnerability>, Box<dyn std::error::Error + Send + Sync>> {
    let mut vulnerabilities = Vec::new();
    if !endpoint.tags.contains(&EndpointTag::GraphQl)
        && !endpoint.url.to_lowercase().contains("graphql")
    {
        return Ok(vulnerabilities);
    }

    let introspection = r#"{"query":"query IntrospectionQuery { __schema { queryType { name } mutationType { name } } }"}"#;
    let context = RequestContext::from_scan_config(HttpMethod::Post, &endpoint.url, config)
        .with_label("graphql");
    let response = runtime
        .execute_request(
            context
                .into_builder(runtime.client())
                .header("Content-Type", "application/json")
                .body(introspection),
        )
        .await;
    if let Ok(response) = response {
        let status = response.status().as_u16();
        let body = response.text().await.unwrap_or_default();
        if status == 200 && body.contains("__schema") {
            let mut evidence = EvidenceBundle::new(
                "The GraphQL endpoint returned schema metadata to an introspection query.",
            );
            evidence.push_status(status);
            vulnerabilities.push(build_vulnerability(
                "active-graphql-introspection",
                "GraphQL Introspection Enabled",
                "A production GraphQL endpoint responded to a schema introspection query.".to_string(),
                Severity::Medium,
                Confidence::Firm,
                "WSTG-APIT-99 - Testing GraphQL",
                endpoint,
                FindingFingerprint::for_endpoint(
                    "active-graphql-introspection",
                    Severity::Medium,
                    endpoint.method,
                    &endpoint.url,
                ),
                evidence,
                "Attackers can map the full schema and accelerate authorization and data exposure attacks.",
                "Disable or restrict introspection on production GraphQL deployments.",
            ));
        }
    }

    Ok(vulnerabilities)
}

async fn test_resource_consumption(
    endpoint: &InventoryEndpoint,
    baseline: &ResponseSnapshot,
    runtime: &ScanRuntime,
    config: &ScanConfig,
) -> Result<Vec<Vulnerability>, Box<dyn std::error::Error + Send + Sync>> {
    let mut vulnerabilities = Vec::new();
    let params = candidate_params(
        endpoint,
        &[
            "limit",
            "size",
            "take",
            "per_page",
            "page_size",
            "count",
            "batch",
        ],
        &["limit", "size", "take"],
        &[ParameterLocation::Query, ParameterLocation::Form],
    );
    for param in params {
        if let Some(response) =
            send_param_probe(endpoint, runtime, config, &param, "5000", "resource").await?
        {
            if response.status == 200 && response.len() > baseline.len().saturating_add(512) {
                let mut evidence = EvidenceBundle::new(
                    "A high-volume query parameter significantly increased the response size without rejection.",
                );
                evidence.push_comparison(
                    "baseline_vs_probe",
                    format!(
                        "baseline={} bytes, probe={} bytes, param={} payload=5000",
                        baseline.len(),
                        response.len(),
                        param
                    ),
                );
                vulnerabilities.push(build_vulnerability(
                    "active-resource-consumption",
                    "Potential Unrestricted Resource Consumption",
                    format!(
                        "Parameter '{}' accepted a high-volume request and returned a much larger response.",
                        param
                    ),
                    Severity::Medium,
                    Confidence::Tentative,
                    "API4:2023 - Unrestricted Resource Consumption",
                    endpoint,
                    FindingFingerprint::for_param(
                        "active-resource-consumption",
                        Severity::Medium,
                        endpoint.method,
                        &endpoint.url,
                        &param,
                    ),
                    evidence,
                    "Attackers may abuse pagination or batching to exhaust compute, memory, or downstream service budgets.",
                    "Enforce server-side page-size, batch-size, and operation-cost limits.",
                ));
                return Ok(vulnerabilities);
            }
        }
    }

    Ok(vulnerabilities)
}

async fn send_param_probe(
    endpoint: &InventoryEndpoint,
    runtime: &ScanRuntime,
    config: &ScanConfig,
    param: &str,
    payload: &str,
    label: &str,
) -> Result<Option<ResponseSnapshot>, Box<dyn std::error::Error + Send + Sync>> {
    let context =
        RequestContext::from_scan_config(endpoint.method, &endpoint.url, config).with_label(label);
    let builder = apply_param(
        context.into_builder(runtime.client()),
        endpoint,
        param,
        payload,
    );
    let response = match runtime.execute_request(builder).await {
        Ok(response) => response,
        Err(_) => return Ok(None),
    };
    let status = response.status().as_u16();
    let body = response.text().await.unwrap_or_default();
    Ok(Some(ResponseSnapshot { status, body }))
}

fn apply_param(
    builder: reqwest::RequestBuilder,
    endpoint: &InventoryEndpoint,
    param: &str,
    payload: &str,
) -> reqwest::RequestBuilder {
    match endpoint.method {
        HttpMethod::Post | HttpMethod::Put | HttpMethod::Patch => {
            let mut form_parameters: Vec<(String, String)> = endpoint
                .parameters
                .iter()
                .filter(|parameter| {
                    matches!(
                        parameter.location,
                        ParameterLocation::Form | ParameterLocation::Json
                    )
                })
                .map(|parameter| (parameter.name.clone(), "baseline".to_string()))
                .collect();
            if let Some(existing) = form_parameters.iter_mut().find(|(name, _)| name == param) {
                existing.1 = payload.to_string();
            } else {
                form_parameters.push((param.to_string(), payload.to_string()));
            }
            builder
                .header("Content-Type", "application/x-www-form-urlencoded")
                .form(&form_parameters)
        }
        _ => builder.query(&[(param, payload)]),
    }
}

fn candidate_params(
    endpoint: &InventoryEndpoint,
    hints: &[&str],
    fallbacks: &[&str],
    locations: &[ParameterLocation],
) -> Vec<String> {
    let mut params = Vec::new();
    for parameter in &endpoint.parameters {
        if !locations.contains(&parameter.location) {
            continue;
        }
        let lower = parameter.name.to_lowercase();
        if hints.iter().any(|hint| lower.contains(hint)) {
            params.push(parameter.name.clone());
        }
    }
    if params.is_empty() {
        for parameter in &endpoint.parameters {
            if locations.contains(&parameter.location) {
                params.push(parameter.name.clone());
            }
        }
    }
    if params.is_empty() {
        params.extend(fallbacks.iter().map(|item| item.to_string()));
    }
    params.sort();
    params.dedup();
    params
}

fn build_vulnerability(
    rule_id: &str,
    title: &str,
    description: String,
    severity: Severity,
    confidence: Confidence,
    category: &str,
    endpoint: &InventoryEndpoint,
    fingerprint: FindingFingerprint,
    evidence: EvidenceBundle,
    impact: &str,
    remediation: &str,
) -> Vulnerability {
    Vulnerability {
        id: rule_id.to_string(),
        rule_id: rule_id.to_string(),
        fingerprint: fingerprint.as_dedup_key(),
        title: title.to_string(),
        description,
        severity,
        confidence,
        category: category.to_string(),
        location: endpoint.url.clone(),
        evidence: evidence.to_text(),
        impact: impact.to_string(),
        remediation: remediation.to_string(),
        affected_endpoints: vec![endpoint.url.clone()],
        evidence_items: evidence.to_items(),
        ..Default::default()
    }
}

fn contains_internal_reference(body: &str) -> bool {
    body.contains("localhost") || body.contains("127.0.0.1") || body.contains("::1")
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn endpoint(url: String) -> InventoryEndpoint {
        InventoryEndpoint {
            url: url.clone(),
            normalized_location: super::super::domain::normalize_fingerprint_location(&url),
            method: HttpMethod::Get,
            source: super::super::domain::EndpointSource::Seed,
            tags: vec![EndpointTag::Api],
            parameters: vec![super::super::domain::EndpointParameter {
                name: "q".to_string(),
                location: ParameterLocation::Query,
            }],
            depth: 0,
            last_status: None,
            baseline_length: None,
        }
    }

    #[tokio::test]
    async fn send_param_probe_returns_none_on_request_errors() {
        let mut config = ScanConfig::default();
        config.http_timeout_secs = 1;
        let runtime = ScanRuntime::new(&config).expect("runtime should initialize");
        let unreachable = endpoint("http://127.0.0.1:1/probe".to_string());

        let result = send_param_probe(&unreachable, &runtime, &config, "q", "x", "probe")
            .await
            .expect("request failures should be skipped");

        assert!(result.is_none(), "failed probes should be skipped");
    }

    #[tokio::test]
    async fn send_param_probe_keeps_successful_responses() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("listener should bind");
        let addr = listener
            .local_addr()
            .expect("listener should expose address");
        let server = tokio::spawn(async move {
            if let Ok((mut socket, _)) = listener.accept().await {
                let mut buffer = vec![0u8; 2048];
                let _ = socket.read(&mut buffer).await;
                let response =
                    b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok";
                let _ = socket.write_all(response).await;
                let _ = socket.shutdown().await;
            }
        });

        let config = ScanConfig::default();
        let runtime = ScanRuntime::new(&config).expect("runtime should initialize");
        let live = endpoint(format!("http://{}/probe", addr));

        let result = send_param_probe(&live, &runtime, &config, "q", "x", "probe")
            .await
            .expect("successful probes should succeed")
            .expect("successful probes should return a snapshot");

        assert_eq!(result.status, 200);
        assert_eq!(result.body, "ok");
        server.await.expect("server task should complete");
    }
}
