use crate::{DiscoveryMode, ScanConfig};
use regex::Regex;
use serde_json::Value;
use std::collections::{HashSet, VecDeque};
use tracing::info;
use url::Url;

use super::domain::{
    normalize_fingerprint_location, EndpointInventory, EndpointParameter, EndpointSource,
    EndpointTag, HttpMethod, InventoryEndpoint, ParameterLocation, RequestContext, ScanRuntime,
};

#[derive(Debug, Clone)]
struct DiscoveredEndpoint {
    url: String,
    method: HttpMethod,
    source: EndpointSource,
    tags: Vec<EndpointTag>,
    parameters: Vec<EndpointParameter>,
}

pub async fn crawl(
    url: &str,
    config: &ScanConfig,
) -> Result<Vec<String>, Box<dyn std::error::Error + Send + Sync>> {
    let runtime = ScanRuntime::new(config)?;
    let noop_emitter = super::engine::ProgressEmitter::new(None);
    Ok(crawl_inventory(url, config, &runtime, &noop_emitter)
        .await?
        .urls())
}

pub async fn crawl_inventory(
    url: &str,
    config: &ScanConfig,
    runtime: &ScanRuntime,
    emitter: &super::engine::ProgressEmitter,
) -> Result<EndpointInventory, Box<dyn std::error::Error + Send + Sync>> {
    info!("Crawling URL: {}", url);
    let base_url = Url::parse(url).map_err(|e| format!("Invalid URL: {}", e))?;
    let origin = base_url.origin().ascii_serialization();
    let max_endpoints = config.max_endpoints as usize;
    let mut inventory = EndpointInventory::new(url);
    let mut queued = HashSet::new();
    let mut queue = VecDeque::new();

    enqueue_endpoint(
        &mut queue,
        &mut queued,
        url.to_string(),
        0,
        EndpointSource::Seed,
    );

    if matches!(
        config.discovery_mode,
        DiscoveryMode::Artifact | DiscoveryMode::Merged
    ) {
        for artifact_endpoint in extract_artifact_endpoints(&base_url, config) {
            inventory.artifact_seed_count += 1;
            let in_scope = within_scope(&artifact_endpoint.url, &origin, config);
            if in_scope {
                inventory.add_or_merge(build_endpoint(
                    &artifact_endpoint.url,
                    artifact_endpoint.method,
                    artifact_endpoint.source,
                    0,
                    None,
                    None,
                    artifact_endpoint.tags.clone(),
                    artifact_endpoint.parameters.clone(),
                ));
                enqueue_endpoint(
                    &mut queue,
                    &mut queued,
                    artifact_endpoint.url.clone(),
                    1,
                    artifact_endpoint.source,
                );
            }
        }
    }

    if config.follow_robots_txt {
        for (path, source) in fetch_known_paths(url, runtime, config).await? {
            if let Ok(absolute) = base_url.join(&path) {
                let candidate = absolute.to_string();
                if within_scope(&candidate, &origin, config) {
                    inventory.add_or_merge(build_endpoint(
                        &candidate,
                        HttpMethod::Get,
                        source,
                        1,
                        None,
                        None,
                        infer_tags(&candidate, None),
                        collect_parameters_from_url(&candidate),
                    ));
                    enqueue_endpoint(&mut queue, &mut queued, candidate, 1, source);
                }
            }
        }
    }

    if matches!(config.discovery_mode, DiscoveryMode::Artifact) {
        inventory.add_or_merge(build_endpoint(
            url,
            HttpMethod::Get,
            EndpointSource::Seed,
            0,
            None,
            None,
            infer_tags(url, None),
            collect_parameters_from_url(url),
        ));
        inventory
            .endpoints
            .sort_by(|left, right| left.url.cmp(&right.url));
        inventory.endpoints.truncate(max_endpoints);
        return Ok(inventory);
    }

    let mut visited = HashSet::new();
    let mut crawl_step = 0u32;
    while let Some((current_url, depth, source)) = queue.pop_front() {
        if crate::cancel_scan_requested() {
            return Err("Scan cancelled".into());
        }
        if inventory.endpoints.len() >= max_endpoints || depth > config.max_crawl_depth {
            break;
        }

        let normalized = normalize_fingerprint_location(&current_url);
        if !visited.insert(normalized.clone()) {
            continue;
        }

        crawl_step += 1;
        let crawl_pct = (crawl_step * 14 / max_endpoints.max(1) as u32).min(14);
        let short = if current_url.len() > 60 {
            format!(
                "...{}",
                &current_url[current_url.len().saturating_sub(57)..]
            )
        } else {
            current_url.clone()
        };
        emitter.emit_detail(
            "crawling",
            crawl_pct,
            100,
            &format!(
                "Crawling depth {} — {} endpoints found",
                depth,
                inventory.endpoints.len()
            ),
            &short,
        );

        let context = RequestContext::from_scan_config(HttpMethod::Get, &current_url, config)
            .with_label("crawl");
        let response = match runtime
            .execute_request(context.into_builder(runtime.client()))
            .await
        {
            Ok(response) => response,
            Err(error) => {
                info!("Failed to fetch {}: {}", current_url, error);
                inventory.add_or_merge(build_endpoint(
                    &current_url,
                    HttpMethod::Get,
                    source,
                    depth,
                    None,
                    None,
                    infer_tags(&current_url, None),
                    collect_parameters_from_url(&current_url),
                ));
                continue;
            }
        };

        let status = response.status().as_u16();
        let headers = response.headers().clone();
        let content_type = headers
            .get("content-type")
            .and_then(|value| value.to_str().ok())
            .map(|value| value.to_lowercase());
        let body = response.text().await.unwrap_or_default();
        let baseline_length = Some(body.len());

        inventory.add_or_merge(build_endpoint(
            &current_url,
            HttpMethod::Get,
            source,
            depth,
            Some(status),
            baseline_length,
            infer_tags(&current_url, content_type.as_deref()),
            collect_parameters_from_url(&current_url),
        ));

        if status < 200 || status >= 400 {
            continue;
        }

        if depth >= config.max_crawl_depth {
            continue;
        }

        for discovered in discover_from_response(&current_url, &body)? {
            if !within_scope(&discovered.url, &origin, config) {
                continue;
            }

            inventory.add_or_merge(build_endpoint(
                &discovered.url,
                discovered.method,
                discovered.source,
                depth + 1,
                None,
                None,
                discovered.tags.clone(),
                discovered.parameters.clone(),
            ));
            enqueue_endpoint(
                &mut queue,
                &mut queued,
                discovered.url,
                depth + 1,
                discovered.source,
            );
        }
    }

    inventory
        .endpoints
        .sort_by(|left, right| left.url.cmp(&right.url));
    inventory.endpoints.truncate(max_endpoints);
    Ok(inventory)
}

fn discover_from_response(
    base_url: &str,
    body: &str,
) -> Result<Vec<DiscoveredEndpoint>, Box<dyn std::error::Error + Send + Sync>> {
    let base = Url::parse(base_url).map_err(|e| format!("Invalid base URL: {}", e))?;
    let origin = base.origin().ascii_serialization();
    let mut discovered = Vec::new();
    let mut seen = HashSet::new();

    let href_re = Regex::new(r#"href\s*=\s*["']([^"']+)["']"#).unwrap();
    for captures in href_re.captures_iter(body) {
        if let Some(value) = captures.get(1) {
            push_discovered(
                &mut discovered,
                &mut seen,
                normalize_url(&base, value.as_str(), &origin),
                HttpMethod::Get,
                EndpointSource::HtmlHref,
                vec![EndpointTag::Html],
                Vec::new(),
            );
        }
    }

    let src_re = Regex::new(r#"src\s*=\s*["']([^"']+)["']"#).unwrap();
    for captures in src_re.captures_iter(body) {
        if let Some(value) = captures.get(1) {
            let normalized = normalize_url(&base, value.as_str(), &origin);
            let tags = infer_tags(&normalized, None);
            push_discovered(
                &mut discovered,
                &mut seen,
                normalized,
                HttpMethod::Get,
                EndpointSource::ScriptSrc,
                tags,
                Vec::new(),
            );
        }
    }

    let api_path_re = Regex::new(
        r#"["']/(api(?:/[\w\-./]*)?|graphql|graphiql|swagger|openapi|health|status|metrics|debug|actuator[\w\-./]*|ws(?:/[\w\-./]*)?)["']"#,
    )
    .unwrap();
    for captures in api_path_re.captures_iter(body) {
        if let Some(value) = captures.get(1) {
            let path = format!("/{}", value.as_str());
            if let Ok(absolute) = base.join(&path) {
                push_discovered(
                    &mut discovered,
                    &mut seen,
                    absolute.to_string(),
                    HttpMethod::Get,
                    EndpointSource::JsFetch,
                    infer_tags(absolute.as_str(), None),
                    collect_parameters_from_url(absolute.as_str()),
                );
            }
        }
    }

    let api_bare_re = Regex::new(r#"(?:fetch|axios|request)\s*\(\s*["']([^"']+)["']"#).unwrap();
    for captures in api_bare_re.captures_iter(body) {
        if let Some(value) = captures.get(1) {
            let normalized = normalize_url(&base, value.as_str(), &origin);
            push_discovered(
                &mut discovered,
                &mut seen,
                normalized.clone(),
                HttpMethod::Get,
                EndpointSource::JsFetch,
                infer_tags(&normalized, None),
                collect_parameters_from_url(&normalized),
            );
        }
    }

    discover_forms(body, &base, &origin, &mut discovered, &mut seen);

    Ok(discovered)
}

fn enqueue_endpoint(
    queue: &mut VecDeque<(String, u32, EndpointSource)>,
    queued: &mut HashSet<String>,
    url: String,
    depth: u32,
    source: EndpointSource,
) {
    if url.is_empty() {
        return;
    }
    if queued.insert(normalize_fingerprint_location(&url)) {
        queue.push_back((url, depth, source));
    }
}

fn build_endpoint(
    url: &str,
    method: HttpMethod,
    source: EndpointSource,
    depth: u32,
    last_status: Option<u16>,
    baseline_length: Option<usize>,
    mut tags: Vec<EndpointTag>,
    mut parameters: Vec<EndpointParameter>,
) -> InventoryEndpoint {
    if tags.is_empty() {
        tags = infer_tags(url, None);
    }
    if parameters.is_empty() {
        parameters = collect_parameters_from_url(url);
    }

    InventoryEndpoint {
        url: url.to_string(),
        normalized_location: normalize_fingerprint_location(url),
        method,
        source,
        tags,
        parameters,
        depth,
        last_status,
        baseline_length,
    }
}

fn infer_tags(url: &str, content_type: Option<&str>) -> Vec<EndpointTag> {
    let mut tags = Vec::new();
    let lower = url.to_lowercase();

    if lower.contains("/api") || lower.contains("/graphql") {
        tags.push(EndpointTag::Api);
    }
    if lower.contains("/graphql") || lower.contains("graphiql") {
        tags.push(EndpointTag::GraphQl);
    }
    if lower.contains("/admin") || lower.contains("wp-login") {
        tags.push(EndpointTag::Admin);
    }
    if lower.contains("/docs") || lower.contains("swagger") || lower.contains("openapi") {
        tags.push(EndpointTag::Docs);
    }
    if lower.ends_with(".js")
        || lower.ends_with(".css")
        || lower.ends_with(".png")
        || lower.ends_with(".svg")
        || lower.ends_with(".jpg")
        || lower.ends_with(".ico")
    {
        tags.push(EndpointTag::Static);
    }
    if lower.contains("login")
        || lower.contains("signin")
        || lower.contains("logout")
        || lower.contains("oauth")
        || lower.contains("auth")
    {
        tags.push(EndpointTag::AuthRelated);
    }
    if let Some(content_type) = content_type {
        if content_type.contains("application/json") {
            tags.push(EndpointTag::Json);
            if !tags.contains(&EndpointTag::Api) {
                tags.push(EndpointTag::Api);
            }
        }
        if content_type.contains("text/html") && !tags.contains(&EndpointTag::Html) {
            tags.push(EndpointTag::Html);
        }
    }

    tags.sort_by(|left, right| left.as_str().cmp(right.as_str()));
    tags.dedup_by(|left, right| left.as_str() == right.as_str());
    tags
}

fn collect_parameters_from_url(url: &str) -> Vec<EndpointParameter> {
    let mut parameters = Vec::new();
    if let Ok(parsed) = Url::parse(url) {
        for (name, _) in parsed.query_pairs() {
            parameters.push(EndpointParameter {
                name: name.to_string(),
                location: ParameterLocation::Query,
            });
        }
    }
    parameters
}

fn normalize_url(base: &Url, value: &str, origin: &str) -> String {
    let trimmed = value.trim();
    if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with("javascript:") {
        return String::new();
    }

    if let Ok(parsed) = Url::parse(trimmed) {
        if parsed.origin().ascii_serialization() == origin {
            return parsed.to_string();
        }
        return String::new();
    }

    if let Ok(absolute) = base.join(trimmed) {
        if absolute.origin().ascii_serialization() == origin {
            return absolute.to_string();
        }
    }

    String::new()
}

fn push_discovered(
    discovered: &mut Vec<DiscoveredEndpoint>,
    seen: &mut HashSet<String>,
    url: String,
    method: HttpMethod,
    source: EndpointSource,
    tags: Vec<EndpointTag>,
    parameters: Vec<EndpointParameter>,
) {
    if url.is_empty() {
        return;
    }
    let key = format!(
        "{}|{}|{}",
        method.as_str(),
        source.as_str(),
        normalize_fingerprint_location(&url)
    );
    if seen.insert(key) {
        discovered.push(DiscoveredEndpoint {
            url,
            method,
            source,
            tags,
            parameters,
        });
    }
}

fn discover_forms(
    body: &str,
    base: &Url,
    origin: &str,
    discovered: &mut Vec<DiscoveredEndpoint>,
    seen: &mut HashSet<String>,
) {
    let form_re = Regex::new(r#"(?is)<form\b([^>]*)>(.*?)</form>"#).unwrap();
    let action_re = Regex::new(r#"action\s*=\s*["']([^"']+)["']"#).unwrap();
    let method_re = Regex::new(r#"method\s*=\s*["']([^"']+)["']"#).unwrap();
    let input_re = Regex::new(r#"name\s*=\s*["']([^"']+)["']"#).unwrap();

    for captures in form_re.captures_iter(body) {
        let attrs = captures.get(1).map(|match_| match_.as_str()).unwrap_or("");
        let inner = captures.get(2).map(|match_| match_.as_str()).unwrap_or("");
        let action = action_re
            .captures(attrs)
            .and_then(|capture| capture.get(1))
            .map(|match_| match_.as_str())
            .unwrap_or(base.as_str());
        let method = method_re
            .captures(attrs)
            .and_then(|capture| capture.get(1))
            .map(|match_| match_.as_str().to_uppercase())
            .unwrap_or_else(|| "GET".to_string());
        let normalized = normalize_url(base, action, origin);
        let mut parameters = collect_parameters_from_url(&normalized);
        for captures in input_re.captures_iter(inner) {
            if let Some(name) = captures.get(1) {
                parameters.push(EndpointParameter {
                    name: name.as_str().to_string(),
                    location: ParameterLocation::Form,
                });
            }
        }

        let method = match method.as_str() {
            "POST" => HttpMethod::Post,
            "PUT" => HttpMethod::Put,
            "PATCH" => HttpMethod::Patch,
            "DELETE" => HttpMethod::Delete,
            _ => HttpMethod::Get,
        };
        push_discovered(
            discovered,
            seen,
            normalized,
            method,
            EndpointSource::FormAction,
            vec![EndpointTag::Form],
            parameters,
        );
    }
}

fn within_scope(url: &str, origin: &str, config: &ScanConfig) -> bool {
    let parsed = match Url::parse(url) {
        Ok(parsed) => parsed,
        Err(_) => return false,
    };
    if parsed.origin().ascii_serialization() != origin {
        return false;
    }

    let candidate = parsed.path().to_string();
    if !config.scope_allowlist.is_empty()
        && !config
            .scope_allowlist
            .iter()
            .any(|allowed| !allowed.trim().is_empty() && candidate.starts_with(allowed.trim()))
    {
        return false;
    }

    if config
        .scope_denylist
        .iter()
        .any(|blocked| !blocked.trim().is_empty() && candidate.starts_with(blocked.trim()))
    {
        return false;
    }

    true
}

fn extract_artifact_endpoints(base_url: &Url, config: &ScanConfig) -> Vec<DiscoveredEndpoint> {
    let mut discovered = Vec::new();
    let mut seen = HashSet::new();

    for custom_path in &config.custom_api_paths {
        if let Ok(absolute) = base_url.join(custom_path.trim()) {
            push_discovered(
                &mut discovered,
                &mut seen,
                absolute.to_string(),
                HttpMethod::Get,
                EndpointSource::CustomPath,
                infer_tags(absolute.as_str(), None),
                collect_parameters_from_url(absolute.as_str()),
            );
        }
    }

    let artifact_input = config.artifact_input.trim();
    if artifact_input.is_empty() {
        return discovered;
    }

    if let Ok(value) = serde_json::from_str::<Value>(artifact_input) {
        extract_json_artifact_endpoints(base_url, &value, &mut discovered, &mut seen);
    } else {
        for line in artifact_input.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            let candidate = if trimmed.starts_with("http://") || trimmed.starts_with("https://") {
                trimmed.to_string()
            } else if let Ok(absolute) = base_url.join(trimmed) {
                absolute.to_string()
            } else {
                continue;
            };
            push_discovered(
                &mut discovered,
                &mut seen,
                candidate.clone(),
                HttpMethod::Get,
                EndpointSource::Artifact,
                infer_tags(&candidate, None),
                collect_parameters_from_url(&candidate),
            );
        }
    }

    discovered
}

fn extract_json_artifact_endpoints(
    base_url: &Url,
    value: &Value,
    discovered: &mut Vec<DiscoveredEndpoint>,
    seen: &mut HashSet<String>,
) {
    if let Some(paths) = value.get("paths").and_then(|value| value.as_object()) {
        for (path, methods) in paths {
            if let Ok(absolute) = base_url.join(path) {
                let supported_methods: Vec<HttpMethod> = methods
                    .as_object()
                    .map(|object| {
                        object
                            .keys()
                            .filter_map(|name| match name.as_str() {
                                "get" => Some(HttpMethod::Get),
                                "post" => Some(HttpMethod::Post),
                                "put" => Some(HttpMethod::Put),
                                "patch" => Some(HttpMethod::Patch),
                                "delete" => Some(HttpMethod::Delete),
                                _ => None,
                            })
                            .collect()
                    })
                    .unwrap_or_else(|| vec![HttpMethod::Get]);
                for method in supported_methods {
                    push_discovered(
                        discovered,
                        seen,
                        absolute.to_string(),
                        method,
                        EndpointSource::Artifact,
                        infer_tags(absolute.as_str(), None),
                        collect_parameters_from_url(absolute.as_str()),
                    );
                }
            }
        }
    }

    if let Some(items) = value.get("item").and_then(|value| value.as_array()) {
        extract_postman_items(base_url, items, discovered, seen);
    }

    if let Some(entries) = value
        .get("log")
        .and_then(|value| value.get("entries"))
        .and_then(|value| value.as_array())
    {
        for entry in entries {
            if let Some(request) = entry.get("request") {
                if let Some(url) = request
                    .get("url")
                    .and_then(|value| value.as_str())
                    .map(|value| value.to_string())
                {
                    push_discovered(
                        discovered,
                        seen,
                        url.clone(),
                        HttpMethod::Get,
                        EndpointSource::Artifact,
                        infer_tags(&url, None),
                        collect_parameters_from_url(&url),
                    );
                }
            }
        }
    }

    if let Some(items) = value.get("inventory").and_then(|value| value.as_array()) {
        for item in items {
            if let Some(url) = item.get("url").and_then(|value| value.as_str()) {
                push_discovered(
                    discovered,
                    seen,
                    url.to_string(),
                    HttpMethod::Get,
                    EndpointSource::Artifact,
                    infer_tags(url, None),
                    collect_parameters_from_url(url),
                );
            }
        }
    }
}

fn extract_postman_items(
    base_url: &Url,
    items: &[Value],
    discovered: &mut Vec<DiscoveredEndpoint>,
    seen: &mut HashSet<String>,
) {
    for item in items {
        if let Some(children) = item.get("item").and_then(|value| value.as_array()) {
            extract_postman_items(base_url, children, discovered, seen);
        }

        let request = match item.get("request") {
            Some(request) => request,
            None => continue,
        };

        let method = request
            .get("method")
            .and_then(|value| value.as_str())
            .map(|value| value.to_uppercase())
            .unwrap_or_else(|| "GET".to_string());
        let method = match method.as_str() {
            "POST" => HttpMethod::Post,
            "PUT" => HttpMethod::Put,
            "PATCH" => HttpMethod::Patch,
            "DELETE" => HttpMethod::Delete,
            _ => HttpMethod::Get,
        };

        let url_value = request.get("url");
        let raw = url_value
            .and_then(|value| value.get("raw"))
            .and_then(|value| value.as_str())
            .map(|value| value.to_string())
            .or_else(|| {
                url_value
                    .and_then(|value| value.as_str())
                    .map(|value| value.to_string())
            });
        let Some(raw) = raw else {
            continue;
        };

        let candidate = if raw.starts_with("http://") || raw.starts_with("https://") {
            raw
        } else if let Ok(absolute) = base_url.join(&raw) {
            absolute.to_string()
        } else {
            continue;
        };

        push_discovered(
            discovered,
            seen,
            candidate.clone(),
            method,
            EndpointSource::Artifact,
            infer_tags(&candidate, None),
            collect_parameters_from_url(&candidate),
        );
    }
}

async fn fetch_known_paths(
    url: &str,
    runtime: &ScanRuntime,
    config: &ScanConfig,
) -> Result<Vec<(String, EndpointSource)>, Box<dyn std::error::Error + Send + Sync>> {
    let mut discovered = Vec::new();
    let base = url.trim_end_matches('/');

    let robots_url = format!("{}/robots.txt", base);
    let robots_context =
        RequestContext::from_scan_config(HttpMethod::Get, &robots_url, config).with_label("robots");
    if let Ok(response) = runtime
        .execute_request(robots_context.into_builder(runtime.client()))
        .await
    {
        if response.status().is_success() {
            let body = response.text().await.unwrap_or_default();
            let path_re = Regex::new(r#"(?im)^(?:allow|disallow)\s*:\s*(/[^\s#]*)"#).unwrap();
            for captures in path_re.captures_iter(&body) {
                if let Some(path) = captures.get(1) {
                    discovered.push((path.as_str().to_string(), EndpointSource::RobotsTxt));
                }
            }
        }
    }

    let sitemap_url = format!("{}/sitemap.xml", base);
    let sitemap_context = RequestContext::from_scan_config(HttpMethod::Get, &sitemap_url, config)
        .with_label("sitemap");
    if let Ok(response) = runtime
        .execute_request(sitemap_context.into_builder(runtime.client()))
        .await
    {
        if response.status().is_success() {
            let body = response.text().await.unwrap_or_default();
            let loc_re = Regex::new(r#"(?is)<loc>\s*([^<]+)\s*</loc>"#).unwrap();
            for captures in loc_re.captures_iter(&body) {
                if let Some(loc) = captures.get(1) {
                    discovered.push((loc.as_str().to_string(), EndpointSource::SitemapXml));
                }
            }
        }
    }

    Ok(discovered)
}
