use crate::ScanConfig;
use regex::Regex;
use std::collections::HashSet;
use tracing::info;
use url::Url;

/// Crawl a URL and discover endpoints from HTML and JavaScript.
/// Returns the input URL plus any discovered same-origin endpoints.
pub async fn crawl(
    url: &str,
    config: &ScanConfig,
) -> Result<Vec<String>, Box<dyn std::error::Error + Send + Sync>> {
    info!("Crawling URL: {}", url);

    let base_url = Url::parse(url).map_err(|e| format!("Invalid URL: {}", e))?;
    let origin = base_url.origin().ascii_serialization();

    let mut client_builder = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(config.http_timeout_secs));
    if config.accept_invalid_certs {
        client_builder = client_builder.danger_accept_invalid_certs(true);
    }
    let client = client_builder.build()?;
    let max_endpoints = config.max_endpoints as usize;

    let mut endpoints = HashSet::new();
    endpoints.insert(url.to_string());

    let response = match client.get(url).send().await {
        Ok(r) => r,
        Err(e) => {
            info!("Failed to fetch {}: {}", url, e);
            return Ok(vec![url.to_string()]);
        }
    };

    let status = response.status();
    if !status.is_success() {
        return Ok(vec![url.to_string()]);
    }

    let _content_type = response
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_lowercase();

    let body = match response.text().await {
        Ok(b) => b,
        Err(_) => return Ok(vec![url.to_string()]),
    };

    // Discover from HTML/JS
    let discovered = discover_from_response(url, &body)?;
    for endpoint in discovered {
        if let Ok(parsed) = Url::parse(&endpoint) {
            if parsed.origin().ascii_serialization() == origin {
                endpoints.insert(endpoint);
            }
        } else if endpoint.starts_with('/') {
            if let Ok(absolute) = base_url.join(&endpoint) {
                endpoints.insert(absolute.to_string());
            }
        }
    }

    // Also add common API paths from rules
    let api_checks = super::rules::api_exposure::get_api_exposure_checks();
    for (path, _severity) in api_checks {
        if let Ok(absolute) = base_url.join(path) {
            let s = absolute.to_string();
            if Url::parse(&s).map(|u| u.origin().ascii_serialization() == origin).unwrap_or(false) {
                endpoints.insert(s);
            }
        }
    }

    let mut result: Vec<String> = endpoints.into_iter().collect();
    result.sort();
    result.truncate(max_endpoints);
    Ok(result)
}

/// Extract URLs and API-like paths from HTML/JavaScript response body.
pub fn discover_from_response(
    base_url: &str,
    body: &str,
) -> Result<Vec<String>, Box<dyn std::error::Error + Send + Sync>> {
    let mut discovered = HashSet::new();

    let base = Url::parse(base_url).map_err(|e| format!("Invalid base URL: {}", e))?;
    let origin = base.origin().ascii_serialization();

    // href="..." or href='...'
    let href_re = Regex::new(r#"href\s*=\s*["']([^"']+)["']"#).unwrap();
    for cap in href_re.captures_iter(body) {
        if let Some(m) = cap.get(1) {
            let s = m.as_str().trim();
            if !s.is_empty() && !s.starts_with('#') && !s.starts_with("javascript:") {
                discovered.insert(normalize_url(&base, s, &origin));
            }
        }
    }

    // action="..." or action='...'
    let action_re = Regex::new(r#"action\s*=\s*["']([^"']+)["']"#).unwrap();
    for cap in action_re.captures_iter(body) {
        if let Some(m) = cap.get(1) {
            let s = m.as_str().trim();
            if !s.is_empty() {
                discovered.insert(normalize_url(&base, s, &origin));
            }
        }
    }

    // src="..." or src='...'
    let src_re = Regex::new(r#"src\s*=\s*["']([^"']+)["']"#).unwrap();
    for cap in src_re.captures_iter(body) {
        if let Some(m) = cap.get(1) {
            let s = m.as_str().trim();
            if !s.is_empty() {
                discovered.insert(normalize_url(&base, s, &origin));
            }
        }
    }

    // API-like paths in JavaScript: "/api/...", "/graphql", etc.
    let api_path_re = Regex::new(r#"["']/(api(?:/[\w\-./]*)?|graphql|graphiql|swagger|openapi|health|status|metrics|debug|actuator[\w\-./]*)["']"#).unwrap();
    for cap in api_path_re.captures_iter(body) {
        if let Some(m) = cap.get(1) {
            let path = format!("/{}", m.as_str());
            if let Ok(absolute) = base.join(&path) {
                if absolute.origin().ascii_serialization() == origin {
                    discovered.insert(absolute.to_string());
                }
            }
        }
    }

    // Fetch URLs that look like /api/... without quotes
    let api_bare_re = Regex::new(r#"(?:fetch|axios|request)\s*\(\s*["']([^"']+)["']"#).unwrap();
    for cap in api_bare_re.captures_iter(body) {
        if let Some(m) = cap.get(1) {
            let s = m.as_str().trim();
            if !s.is_empty() {
                discovered.insert(normalize_url(&base, s, &origin));
            }
        }
    }

    let result: Vec<String> = discovered
        .into_iter()
        .filter(|s| !s.is_empty())
        .collect();
    Ok(result)
}

fn normalize_url(base: &Url, s: &str, origin: &str) -> String {
    let s = s.trim();
    if s.is_empty() {
        return String::new();
    }
    if let Ok(parsed) = Url::parse(s) {
        if parsed.origin().ascii_serialization() == origin {
            return parsed.to_string();
        }
        return String::new();
    }
    if s.starts_with('/') {
        if let Ok(absolute) = base.join(s) {
            if absolute.origin().ascii_serialization() == origin {
                return absolute.to_string();
            }
        }
    }
    if let Ok(absolute) = base.join(s) {
        if absolute.origin().ascii_serialization() == origin {
            return absolute.to_string();
        }
    }
    String::new()
}
