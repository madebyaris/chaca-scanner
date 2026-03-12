use crate::{Confidence, ScanConfig, Severity, Vulnerability};
use regex::Regex;
use tracing::info;

pub fn analyze_response(
    url: &str,
    status: u16,
    headers: &reqwest::header::HeaderMap,
    body: &str,
    config: &ScanConfig,
) -> Vec<Vulnerability> {
    info!("Analyzing response from: {}", url);

    let mut vulnerabilities = Vec::new();

    if status == 200 {
        if config.passive_server_header {
            if let Some(server) = headers.get("server") {
                if let Ok(server_str) = server.to_str() {
                    if !server_str.is_empty() {
                        vulnerabilities.push(Vulnerability {
                            id: "passive-server-info".to_string(),
                            title: "Server Information Disclosure".to_string(),
                            description: format!("Server header reveals: {}", server_str),
                            severity: Severity::Info,
                            confidence: Confidence::Confirmed,
                            category: "API9:2023 - Improper Inventory Management".to_string(),
                            location: url.to_string(),
                            evidence: format!("Server: {}", server_str),
                            impact: "Attackers can identify server technology and version"
                                .to_string(),
                            remediation: "Configure server to suppress version information"
                                .to_string(),
                            affected_endpoints: vec![url.to_string()],
                            ..Default::default()
                        });
                    }
                }
            }
        }

        if config.passive_x_powered_by {
            if let Some(x_powered_by) = headers.get("x-powered-by") {
                if let Ok(powered_by) = x_powered_by.to_str() {
                    vulnerabilities.push(Vulnerability {
                        id: "passive-x-powered-by".to_string(),
                        title: "X-Powered-By Header".to_string(),
                        description: format!("X-Powered-By header reveals: {}", powered_by),
                        severity: Severity::Info,
                        confidence: Confidence::Confirmed,
                        category: "API9:2023 - Improper Inventory Management".to_string(),
                        location: url.to_string(),
                        evidence: format!("X-Powered-By: {}", powered_by),
                        impact: "Reveals technology stack to attackers".to_string(),
                        remediation: "Remove X-Powered-By header".to_string(),
                        affected_endpoints: vec![url.to_string()],
                        ..Default::default()
                    });
                }
            }
        }

        if config.passive_json_api {
            if let Some(content_type) = headers.get("content-type") {
                if let Ok(ct) = content_type.to_str() {
                    if ct.contains("application/json") {
                        vulnerabilities.push(Vulnerability {
                            id: "passive-json-api".to_string(),
                            title: "JSON API Endpoint".to_string(),
                            description: "This is a JSON API endpoint".to_string(),
                            severity: Severity::Info,
                            confidence: Confidence::Confirmed,
                            category: "API Discovery".to_string(),
                            location: url.to_string(),
                            evidence: format!("Content-Type: {}", ct),
                            impact: "API endpoint identified".to_string(),
                            remediation: "Ensure proper authentication is in place".to_string(),
                            affected_endpoints: vec![url.to_string()],
                            ..Default::default()
                        });
                    }
                }
            }
        }

        if config.passive_hsts {
            if url.starts_with("https://") && headers.get("strict-transport-security").is_none() {
                vulnerabilities.push(Vulnerability {
                    id: "passive-hsts".to_string(),
                    title: "Missing Strict-Transport-Security (HSTS)".to_string(),
                    description: "HTTPS site does not set HSTS header".to_string(),
                    severity: Severity::Medium,
                    confidence: Confidence::Confirmed,
                    category: "API8:2023 - Security Misconfiguration".to_string(),
                    location: url.to_string(),
                    evidence: "strict-transport-security header is absent".to_string(),
                    impact: "Users may be vulnerable to SSL stripping attacks".to_string(),
                    remediation:
                        "Add Strict-Transport-Security: max-age=31536000; includeSubDomains"
                            .to_string(),
                    affected_endpoints: vec![url.to_string()],
                    ..Default::default()
                });
            }
        }

        if config.passive_content_type_options {
            if headers.get("x-content-type-options").is_none() {
                vulnerabilities.push(Vulnerability {
                    id: "passive-xcto".to_string(),
                    title: "Missing X-Content-Type-Options".to_string(),
                    description: "X-Content-Type-Options: nosniff is not set".to_string(),
                    severity: Severity::Low,
                    confidence: Confidence::Confirmed,
                    category: "API8:2023 - Security Misconfiguration".to_string(),
                    location: url.to_string(),
                    evidence: "x-content-type-options header is absent".to_string(),
                    impact: "Browser may MIME-sniff and execute malicious content".to_string(),
                    remediation: "Add X-Content-Type-Options: nosniff".to_string(),
                    affected_endpoints: vec![url.to_string()],
                    ..Default::default()
                });
            }
        }

        if config.passive_frame_options {
            if headers.get("x-frame-options").is_none() {
                vulnerabilities.push(Vulnerability {
                    id: "passive-xfo".to_string(),
                    title: "Missing X-Frame-Options".to_string(),
                    description: "X-Frame-Options header is not set".to_string(),
                    severity: Severity::Medium,
                    confidence: Confidence::Confirmed,
                    category: "API8:2023 - Security Misconfiguration".to_string(),
                    location: url.to_string(),
                    evidence: "x-frame-options header is absent".to_string(),
                    impact: "Page may be embedded in iframes (clickjacking risk)".to_string(),
                    remediation: "Add X-Frame-Options: DENY or SAMEORIGIN".to_string(),
                    affected_endpoints: vec![url.to_string()],
                    ..Default::default()
                });
            }
        }

        if config.passive_csp {
            if let Some(csp) = headers.get("content-security-policy") {
                if let Ok(csp_str) = csp.to_str() {
                    if csp_str.is_empty()
                        || csp_str.contains("'unsafe-inline'")
                        || csp_str.contains("'unsafe-eval'")
                    {
                        vulnerabilities.push(Vulnerability {
                            id: "passive-csp-weak".to_string(),
                            title: "Weak Content-Security-Policy".to_string(),
                            description: "CSP allows unsafe-inline or unsafe-eval".to_string(),
                            severity: Severity::Medium,
                            confidence: Confidence::Confirmed,
                            category: "API8:2023 - Security Misconfiguration".to_string(),
                            location: url.to_string(),
                            evidence: format!("CSP: {}", csp_str),
                            impact: "XSS attacks may succeed despite CSP".to_string(),
                            remediation: "Remove unsafe-inline and unsafe-eval from CSP"
                                .to_string(),
                            affected_endpoints: vec![url.to_string()],
                            ..Default::default()
                        });
                    }
                }
            } else {
                vulnerabilities.push(Vulnerability {
                    id: "passive-csp-missing".to_string(),
                    title: "Missing Content-Security-Policy".to_string(),
                    description: "Content-Security-Policy header is not set".to_string(),
                    severity: Severity::Medium,
                    confidence: Confidence::Confirmed,
                    category: "API8:2023 - Security Misconfiguration".to_string(),
                    location: url.to_string(),
                    evidence: "content-security-policy header is absent".to_string(),
                    impact: "No protection against XSS and injection attacks".to_string(),
                    remediation: "Add a restrictive Content-Security-Policy header".to_string(),
                    affected_endpoints: vec![url.to_string()],
                    ..Default::default()
                });
            }
        }

        if config.passive_cors {
            if let Some(acao) = headers.get("access-control-allow-origin") {
                if let Ok(acao_str) = acao.to_str() {
                    if acao_str.trim() == "*" {
                        let acac = headers.get("access-control-allow-credentials");
                        let has_creds = acac
                            .and_then(|v| v.to_str().ok())
                            .map(|v| v.eq_ignore_ascii_case("true"))
                            .unwrap_or(false);
                        if has_creds {
                            vulnerabilities.push(Vulnerability {
                                id: "passive-cors-creds".to_string(),
                                title: "CORS Misconfiguration: Credentials with Wildcard".to_string(),
                                description:
                                    "Access-Control-Allow-Origin: * with Allow-Credentials: true"
                                        .to_string(),
                                severity: Severity::Critical,
                                confidence: Confidence::Confirmed,
                                category: "API8:2023 - Security Misconfiguration".to_string(),
                                location: url.to_string(),
                                evidence:
                                    "Access-Control-Allow-Origin: * and Access-Control-Allow-Credentials: true"
                                        .to_string(),
                                impact: "Any site can make credentialed requests and steal user data"
                                    .to_string(),
                                remediation:
                                    "Use specific origin instead of * when credentials are allowed"
                                        .to_string(),
                                affected_endpoints: vec![url.to_string()],
                        ..Default::default()
                            });
                        } else {
                            vulnerabilities.push(Vulnerability {
                                id: "passive-cors-wildcard".to_string(),
                                title: "CORS Wildcard Origin".to_string(),
                                description: "Access-Control-Allow-Origin: * allows any origin"
                                    .to_string(),
                                severity: Severity::High,
                                confidence: Confidence::Confirmed,
                                category: "API8:2023 - Security Misconfiguration".to_string(),
                                location: url.to_string(),
                                evidence: "Access-Control-Allow-Origin: *".to_string(),
                                impact: "API is accessible from any website".to_string(),
                                remediation: "Restrict to specific origins".to_string(),
                                affected_endpoints: vec![url.to_string()],
                                ..Default::default()
                            });
                        }
                    }
                }
            }
        }

        if config.passive_referrer_policy {
            if headers.get("referrer-policy").is_none() {
                vulnerabilities.push(Vulnerability {
                    id: "passive-referrer".to_string(),
                    title: "Missing Referrer-Policy".to_string(),
                    description: "Referrer-Policy header is not set".to_string(),
                    severity: Severity::Low,
                    confidence: Confidence::Confirmed,
                    category: "API8:2023 - Security Misconfiguration".to_string(),
                    location: url.to_string(),
                    evidence: "referrer-policy header is absent".to_string(),
                    impact: "Full URL may leak in Referer header to third parties".to_string(),
                    remediation: "Add Referrer-Policy: strict-origin-when-cross-origin".to_string(),
                    affected_endpoints: vec![url.to_string()],
                    ..Default::default()
                });
            }
        }

        if config.passive_permissions_policy {
            if headers.get("permissions-policy").is_none()
                && headers.get("feature-policy").is_none()
            {
                vulnerabilities.push(Vulnerability {
                    id: "passive-permissions".to_string(),
                    title: "Missing Permissions-Policy".to_string(),
                    description: "Permissions-Policy (Feature-Policy) header is not set"
                        .to_string(),
                    severity: Severity::Low,
                    confidence: Confidence::Confirmed,
                    category: "API8:2023 - Security Misconfiguration".to_string(),
                    location: url.to_string(),
                    evidence: "permissions-policy and feature-policy headers are absent"
                        .to_string(),
                    impact: "Browser features may be used without restriction".to_string(),
                    remediation: "Add Permissions-Policy to restrict unnecessary features"
                        .to_string(),
                    affected_endpoints: vec![url.to_string()],
                    ..Default::default()
                });
            }
        }

        if config.passive_cache_control {
            if let Some(ct) = headers.get("content-type") {
                if let Ok(ct_str) = ct.to_str() {
                    if ct_str.contains("application/json") && headers.get("cache-control").is_none()
                    {
                        vulnerabilities.push(Vulnerability {
                            id: "passive-cache-json".to_string(),
                            title: "JSON Response Without Cache-Control".to_string(),
                            description: "JSON API response may be cached by browsers".to_string(),
                            severity: Severity::Medium,
                            confidence: Confidence::Confirmed,
                            category: "API10:2023 - Unsafe Consumption of API".to_string(),
                            location: url.to_string(),
                            evidence: "cache-control header is absent for JSON response"
                                .to_string(),
                            impact: "Sensitive data may be cached and exposed".to_string(),
                            remediation: "Add Cache-Control: no-store for sensitive responses"
                                .to_string(),
                            affected_endpoints: vec![url.to_string()],
                            ..Default::default()
                        });
                    }
                }
            }
        }

        if config.passive_cookie_flags {
            for (idx, cookie_header) in headers.get_all("set-cookie").iter().enumerate() {
                if let Ok(cookie_str) = cookie_header.to_str() {
                    let lower = cookie_str.to_lowercase();
                    let missing_secure = !lower.contains("secure");
                    let missing_httponly = !lower.contains("httponly");
                    let missing_samesite = !lower.contains("samesite=");
                    if missing_secure || missing_httponly || missing_samesite {
                        let mut issues = Vec::new();
                        if missing_secure {
                            issues.push("Secure");
                        }
                        if missing_httponly {
                            issues.push("HttpOnly");
                        }
                        if missing_samesite {
                            issues.push("SameSite");
                        }
                        vulnerabilities.push(Vulnerability {
                            id: format!("passive-cookie-{}", idx),
                            title: "Cookie Missing Security Flags".to_string(),
                            description: format!("Cookie missing: {}", issues.join(", ")),
                            severity: Severity::Medium,
                            confidence: Confidence::Confirmed,
                            category: "API8:2023 - Security Misconfiguration".to_string(),
                            location: url.to_string(),
                            evidence: format!(
                                "Set-Cookie: {}...",
                                &cookie_str[..cookie_str.len().min(80)]
                            ),
                            impact: "Cookie may be exposed to XSS or transmitted over HTTP"
                                .to_string(),
                            remediation: "Add Secure, HttpOnly, and SameSite=Strict to cookies"
                                .to_string(),
                            affected_endpoints: vec![url.to_string()],
                            ..Default::default()
                        });
                        break;
                    }
                }
            }
        }
    }

    // ── CSRF Detection ──
    if config.passive_csrf {
        if status == 200 {
            let body_lower = body.to_lowercase();
            let has_form = body_lower.contains("<form");
            if has_form {
                let has_csrf_token = body_lower.contains("csrf")
                    || body_lower.contains("_token")
                    || body_lower.contains("authenticity_token")
                    || body_lower.contains("__requestverificationtoken")
                    || body_lower.contains("antiforgery");
                if !has_csrf_token {
                    let has_post = body_lower.contains("method=\"post\"")
                        || body_lower.contains("method='post'");
                    if has_post {
                        vulnerabilities.push(Vulnerability {
                            id: "passive-csrf-missing".to_string(),
                            title: "Missing CSRF Protection".to_string(),
                            description: "HTML form with POST method lacks CSRF token fields".to_string(),
                            severity: Severity::Medium,
                            confidence: Confidence::Firm,
                            category: "CWE-352 - Cross-Site Request Forgery".to_string(),
                            location: url.to_string(),
                            evidence: "POST form without csrf/token/authenticity_token hidden field".to_string(),
                            impact: "Attackers can forge cross-site requests on behalf of authenticated users".to_string(),
                            remediation: "Add CSRF tokens to all state-changing forms; set SameSite=Strict on cookies".to_string(),
                            affected_endpoints: vec![url.to_string()],
                        ..Default::default()
                        });
                    }
                }
            }
        }
    }

    // ── Enhanced Clickjacking ──
    if config.passive_clickjack {
        if status == 200 {
            let has_xfo = headers.get("x-frame-options").is_some();
            let has_frame_ancestors = headers
                .get("content-security-policy")
                .and_then(|v| v.to_str().ok())
                .map(|csp| csp.to_lowercase().contains("frame-ancestors"))
                .unwrap_or(false);
            if !has_xfo && !has_frame_ancestors {
                vulnerabilities.push(Vulnerability {
                    id: "passive-clickjack".to_string(),
                    title: "Clickjacking: No Frame Protection".to_string(),
                    description: "Both X-Frame-Options and CSP frame-ancestors are missing"
                        .to_string(),
                    severity: Severity::Medium,
                    confidence: Confidence::Confirmed,
                    category: "CWE-1021 - Improper Restriction of Rendered UI Layers".to_string(),
                    location: url.to_string(),
                    evidence: "Neither X-Frame-Options nor frame-ancestors directive present"
                        .to_string(),
                    impact: "Page can be embedded in iframes for clickjacking attacks".to_string(),
                    remediation: "Set X-Frame-Options: DENY and CSP frame-ancestors 'none'"
                        .to_string(),
                    affected_endpoints: vec![url.to_string()],
                    ..Default::default()
                });
            }
        }
    }

    // ── Information Disclosure ──
    if config.passive_info_disclosure {
        let info_vulns = super::rules::info_disclosure::check_info_disclosure(url, headers, body);
        vulnerabilities.extend(info_vulns);
    }

    // ── JWT in Response Body ──
    if config.passive_jwt_analysis {
        if status == 200 {
            let jwt_re =
                Regex::new(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}").ok();
            if let Some(re) = jwt_re {
                if let Some(m) = re.find(body) {
                    let jwt_str = m.as_str();
                    let parts: Vec<&str> = jwt_str.splitn(3, '.').collect();
                    if parts.len() >= 2 {
                        use base64::Engine;
                        let engine = base64::engine::general_purpose::URL_SAFE_NO_PAD;
                        if let Ok(header_bytes) = engine.decode(parts[0]) {
                            let header_str = String::from_utf8_lossy(&header_bytes).to_lowercase();
                            if header_str.contains("\"alg\"")
                                && (header_str.contains("\"none\"") || header_str.contains("\"\""))
                            {
                                vulnerabilities.push(Vulnerability {
                                    id: "passive-jwt-none-alg".to_string(),
                                    title: "JWT with 'none' Algorithm".to_string(),
                                    description:
                                        "JWT in response uses alg:none — no signature verification"
                                            .to_string(),
                                    severity: Severity::High,
                                    confidence: Confidence::Confirmed,
                                    category: "API2:2023 - Broken Authentication".to_string(),
                                    location: url.to_string(),
                                    evidence: format!("JWT header: {}", header_str),
                                    impact: "Attackers can forge arbitrary JWT tokens".to_string(),
                                    remediation:
                                        "Reject JWTs with alg:none; enforce RS256 or ES256"
                                            .to_string(),
                                    affected_endpoints: vec![url.to_string()],
                                    ..Default::default()
                                });
                            } else {
                                vulnerabilities.push(Vulnerability {
                                    id: "passive-jwt-exposed".to_string(),
                                    title: "JWT Token Exposed in Response".to_string(),
                                    description: "A JWT token was found in the response body"
                                        .to_string(),
                                    severity: Severity::Medium,
                                    confidence: Confidence::Firm,
                                    category: "API2:2023 - Broken Authentication".to_string(),
                                    location: url.to_string(),
                                    evidence: format!(
                                        "JWT found: {}...{}",
                                        &jwt_str[..20.min(jwt_str.len())],
                                        &jwt_str[jwt_str.len().saturating_sub(10)..]
                                    ),
                                    impact: "Leaked JWTs can be used to impersonate users"
                                        .to_string(),
                                    remediation:
                                        "Never include JWTs in HTML responses; use HttpOnly cookies"
                                            .to_string(),
                                    affected_endpoints: vec![url.to_string()],
                                    ..Default::default()
                                });
                            }
                        }
                    }
                }
            }
        }
    }

    // ── Rate Limit Headers Missing ──
    if config.passive_ratelimit_check {
        if status == 200 {
            let is_api = headers
                .get("content-type")
                .and_then(|v| v.to_str().ok())
                .map(|ct| ct.contains("application/json"))
                .unwrap_or(false);
            if is_api {
                let has_ratelimit = headers.keys().any(|k| {
                    let name = k.as_str().to_lowercase();
                    name.starts_with("x-ratelimit")
                        || name.starts_with("ratelimit")
                        || name == "retry-after"
                });
                if !has_ratelimit {
                    vulnerabilities.push(Vulnerability {
                        id: "passive-no-ratelimit".to_string(),
                        title: "No Rate Limiting Headers on API".to_string(),
                        description: "API endpoint lacks rate-limiting headers".to_string(),
                        severity: Severity::Low,
                        confidence: Confidence::Tentative,
                        category: "API4:2023 - Unrestricted Resource Consumption".to_string(),
                        location: url.to_string(),
                        evidence: "No X-RateLimit-*, RateLimit-*, or Retry-After headers found"
                            .to_string(),
                        impact: "Endpoint may be vulnerable to brute force or denial of service"
                            .to_string(),
                        remediation:
                            "Implement rate limiting and return standard rate-limit headers"
                                .to_string(),
                        affected_endpoints: vec![url.to_string()],
                        ..Default::default()
                    });
                }
            }
        }
    }

    // ── Insecure Deserialization Indicators ──
    if config.passive_deser_check {
        if status == 200 {
            let deser_patterns: &[(&str, &str)] = &[
                ("rO0AB", "Java serialized object (Base64)"),
                ("aced0005", "Java serialized object (hex)"),
                ("O:", "PHP serialized object"),
                ("a:", "PHP serialized array"),
                ("TypeObject", ".NET serialized object"),
            ];
            for (pattern, desc) in deser_patterns {
                if body.contains(pattern) {
                    let is_php = *pattern == "O:" || *pattern == "a:";
                    if is_php {
                        let re = Regex::new(&format!(r#"{}[0-9]+:"#, regex::escape(pattern))).ok();
                        if let Some(re) = re {
                            if re.is_match(body) {
                                vulnerabilities.push(Vulnerability {
                                    id: "passive-deser-indicator".to_string(),
                                    title: "Serialized Object in Response".to_string(),
                                    description: format!("{} detected in response body", desc),
                                    severity: Severity::Medium,
                                    confidence: Confidence::Tentative,
                                    category: "CWE-502 - Deserialization of Untrusted Data"
                                        .to_string(),
                                    location: url.to_string(),
                                    evidence: format!("Pattern '{}' matched", pattern),
                                    impact:
                                        "Insecure deserialization may lead to remote code execution"
                                            .to_string(),
                                    remediation:
                                        "Avoid deserializing untrusted data; use JSON instead"
                                            .to_string(),
                                    affected_endpoints: vec![url.to_string()],
                                    ..Default::default()
                                });
                                break;
                            }
                        }
                    } else {
                        vulnerabilities.push(Vulnerability {
                            id: "passive-deser-indicator".to_string(),
                            title: "Serialized Object in Response".to_string(),
                            description: format!("{} detected in response body", desc),
                            severity: Severity::Medium,
                            confidence: Confidence::Tentative,
                            category: "CWE-502 - Deserialization of Untrusted Data".to_string(),
                            location: url.to_string(),
                            evidence: format!("Pattern '{}' matched", pattern),
                            impact: "Insecure deserialization may lead to remote code execution"
                                .to_string(),
                            remediation: "Avoid deserializing untrusted data; use JSON instead"
                                .to_string(),
                            affected_endpoints: vec![url.to_string()],
                            ..Default::default()
                        });
                        break;
                    }
                }
            }
        }
    }

    // ── Exposed Service URLs in Response Body ──
    if config.check_exposed_services {
        if status == 200 {
            let svc_vulns = super::rules::exposed_services::scan_for_service_urls(url, body);
            vulnerabilities.extend(svc_vulns);
        }
    }

    vulnerabilities
}
