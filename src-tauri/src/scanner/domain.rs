use crate::{
    AuthState, EvidenceItem, HeaderPair, InventorySummaryItem, ScanConfig, Severity, Vulnerability,
};
use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
use std::collections::{BTreeSet, HashMap};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};
use tokio::sync::Mutex;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HttpMethod {
    Get,
    Post,
    Put,
    Patch,
    Delete,
    Head,
    Options,
}

impl HttpMethod {
    pub fn as_reqwest(self) -> reqwest::Method {
        match self {
            Self::Get => reqwest::Method::GET,
            Self::Post => reqwest::Method::POST,
            Self::Put => reqwest::Method::PUT,
            Self::Patch => reqwest::Method::PATCH,
            Self::Delete => reqwest::Method::DELETE,
            Self::Head => reqwest::Method::HEAD,
            Self::Options => reqwest::Method::OPTIONS,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Get => "GET",
            Self::Post => "POST",
            Self::Put => "PUT",
            Self::Patch => "PATCH",
            Self::Delete => "DELETE",
            Self::Head => "HEAD",
            Self::Options => "OPTIONS",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EndpointSource {
    Seed,
    HtmlHref,
    FormAction,
    ScriptSrc,
    JsFetch,
    ApiWordlist,
    CustomPath,
    Artifact,
    RobotsTxt,
    SitemapXml,
}

impl EndpointSource {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Seed => "seed",
            Self::HtmlHref => "html_href",
            Self::FormAction => "form_action",
            Self::ScriptSrc => "script_src",
            Self::JsFetch => "js_fetch",
            Self::ApiWordlist => "api_wordlist",
            Self::CustomPath => "custom_path",
            Self::Artifact => "artifact",
            Self::RobotsTxt => "robots_txt",
            Self::SitemapXml => "sitemap_xml",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EndpointTag {
    Api,
    Html,
    Form,
    Docs,
    GraphQl,
    Admin,
    Static,
    AuthRelated,
    Json,
}

impl EndpointTag {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Api => "api",
            Self::Html => "html",
            Self::Form => "form",
            Self::Docs => "docs",
            Self::GraphQl => "graphql",
            Self::Admin => "admin",
            Self::Static => "static",
            Self::AuthRelated => "auth_related",
            Self::Json => "json",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ParameterLocation {
    Query,
    Form,
    Json,
    Path,
}

impl ParameterLocation {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Query => "query",
            Self::Form => "form",
            Self::Json => "json",
            Self::Path => "path",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct EndpointParameter {
    pub name: String,
    pub location: ParameterLocation,
}

#[derive(Debug, Clone)]
pub struct InventoryEndpoint {
    pub url: String,
    pub normalized_location: String,
    pub method: HttpMethod,
    pub source: EndpointSource,
    pub tags: Vec<EndpointTag>,
    pub parameters: Vec<EndpointParameter>,
    pub depth: u32,
    pub last_status: Option<u16>,
    pub baseline_length: Option<usize>,
}

impl InventoryEndpoint {
    pub fn to_summary(&self) -> InventorySummaryItem {
        InventorySummaryItem {
            url: self.url.clone(),
            method: self.method.as_str().to_string(),
            source: self.source.as_str().to_string(),
            tags: self.tags.iter().map(|tag| tag.as_str().to_string()).collect(),
            parameter_names: self
                .parameters
                .iter()
                .map(|param| format!("{}:{}", param.location.as_str(), param.name))
                .collect(),
            last_status: self.last_status,
        }
    }
}

#[derive(Debug, Clone)]
pub struct EndpointInventory {
    pub root_url: String,
    pub endpoints: Vec<InventoryEndpoint>,
    pub artifact_seed_count: usize,
}

impl EndpointInventory {
    pub fn new(root_url: impl Into<String>) -> Self {
        Self {
            root_url: root_url.into(),
            endpoints: Vec::new(),
            artifact_seed_count: 0,
        }
    }

    pub fn add_or_merge(&mut self, endpoint: InventoryEndpoint) {
        if let Some(existing) = self
            .endpoints
            .iter_mut()
            .find(|item| {
                item.normalized_location == endpoint.normalized_location
                    && item.method == endpoint.method
            })
        {
            existing.last_status = existing.last_status.or(endpoint.last_status);
            existing.baseline_length = existing.baseline_length.or(endpoint.baseline_length);
            existing.depth = existing.depth.min(endpoint.depth);
            merge_tags(&mut existing.tags, &endpoint.tags);
            merge_parameters(&mut existing.parameters, &endpoint.parameters);
            return;
        }

        self.endpoints.push(endpoint);
    }

    pub fn urls(&self) -> Vec<String> {
        self.endpoints.iter().map(|endpoint| endpoint.url.clone()).collect()
    }

    pub fn active_candidates(&self) -> impl Iterator<Item = &InventoryEndpoint> {
        self.endpoints.iter().filter(|endpoint| {
            !endpoint.tags.contains(&EndpointTag::Static) && !endpoint.tags.contains(&EndpointTag::Docs)
        })
    }

    pub fn passive_candidates(&self) -> impl Iterator<Item = &InventoryEndpoint> {
        self.endpoints.iter()
    }
}

#[derive(Debug, Clone)]
pub enum AuthProfile {
    Anonymous,
    BearerToken,
    Basic,
    Cookie,
    CustomHeaders,
}

impl AuthProfile {
    pub fn mode_label(&self) -> &'static str {
        match self {
            Self::Anonymous => "anonymous",
            Self::BearerToken => "bearer_token",
            Self::Basic => "basic_auth",
            Self::Cookie => "cookie",
            Self::CustomHeaders => "custom_headers",
        }
    }
}

#[derive(Debug, Clone)]
pub struct RequestContext {
    pub method: HttpMethod,
    pub url: String,
    pub headers: Vec<HeaderPair>,
    pub auth_profile: AuthProfile,
    pub label: Option<String>,
}

impl RequestContext {
    pub fn from_scan_config(
        method: HttpMethod,
        url: impl Into<String>,
        config: &ScanConfig,
    ) -> Self {
        let headers = config.custom_headers.clone();
        let auth_profile = detect_auth_profile(&headers);
        Self {
            method,
            url: url.into(),
            headers,
            auth_profile,
            label: None,
        }
    }

    pub fn with_header(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.push(HeaderPair {
            key: key.into(),
            value: value.into(),
        });
        self
    }

    pub fn with_label(mut self, label: impl Into<String>) -> Self {
        self.label = Some(label.into());
        self
    }

    pub fn into_builder<'a>(&self, client: &'a reqwest::Client) -> reqwest::RequestBuilder {
        let mut builder = client.request(self.method.as_reqwest(), &self.url);
        for header in &self.headers {
            if let (Ok(name), Ok(value)) = (
                HeaderName::from_bytes(header.key.as_bytes()),
                HeaderValue::from_str(&header.value),
            ) {
                builder = builder.header(name, value);
            }
        }
        builder
    }

    pub fn redacted_summary(&self) -> String {
        let mut rendered_headers = Vec::new();
        for header in &self.headers {
            let key = header.key.to_lowercase();
            let value = if key == "authorization" || key == "cookie" {
                "[redacted]".to_string()
            } else {
                header.value.clone()
            };
            rendered_headers.push(format!("{}={}", header.key, value));
        }

        let label = self
            .label
            .as_ref()
            .map(|value| format!(" ({})", value))
            .unwrap_or_default();
        if rendered_headers.is_empty() {
            format!("{} {}{}", self.method.as_str(), self.url, label)
        } else {
            format!(
                "{} {}{} [{}]",
                self.method.as_str(),
                self.url,
                label,
                rendered_headers.join(", ")
            )
        }
    }

    pub fn auth_state(&self) -> AuthState {
        let applied = !matches!(self.auth_profile, AuthProfile::Anonymous);
        AuthState {
            mode: self.auth_profile.mode_label().to_string(),
            applied,
            status: if applied { "applied".to_string() } else { "anonymous".to_string() },
            details: self.redacted_summary(),
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub enum EvidenceKind {
    Status,
    Header,
    BodySnippet,
    PatternMatch,
    Comparison,
    Note,
}

impl EvidenceKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Status => "status",
            Self::Header => "header",
            Self::BodySnippet => "body",
            Self::PatternMatch => "pattern",
            Self::Comparison => "comparison",
            Self::Note => "note",
        }
    }
}

#[derive(Debug, Clone)]
pub struct EvidenceEntry {
    pub kind: EvidenceKind,
    pub label: String,
    pub value: String,
}

#[derive(Debug, Clone)]
pub struct EvidenceBundle {
    pub summary: String,
    pub request: Option<RequestContext>,
    pub entries: Vec<EvidenceEntry>,
}

impl EvidenceBundle {
    pub fn new(summary: impl Into<String>) -> Self {
        Self {
            summary: summary.into(),
            request: None,
            entries: Vec::new(),
        }
    }

    pub fn with_request(mut self, request: RequestContext) -> Self {
        self.request = Some(request);
        self
    }

    pub fn push_status(&mut self, status: u16) {
        self.entries.push(EvidenceEntry {
            kind: EvidenceKind::Status,
            label: "status".to_string(),
            value: status.to_string(),
        });
    }

    pub fn push_header(&mut self, name: impl Into<String>, value: impl Into<String>) {
        self.entries.push(EvidenceEntry {
            kind: EvidenceKind::Header,
            label: name.into(),
            value: value.into(),
        });
    }

    pub fn push_match(&mut self, label: impl Into<String>, value: impl Into<String>) {
        self.entries.push(EvidenceEntry {
            kind: EvidenceKind::PatternMatch,
            label: label.into(),
            value: value.into(),
        });
    }

    pub fn push_comparison(&mut self, label: impl Into<String>, value: impl Into<String>) {
        self.entries.push(EvidenceEntry {
            kind: EvidenceKind::Comparison,
            label: label.into(),
            value: value.into(),
        });
    }

    pub fn push_note(&mut self, label: impl Into<String>, value: impl Into<String>) {
        self.entries.push(EvidenceEntry {
            kind: EvidenceKind::Note,
            label: label.into(),
            value: value.into(),
        });
    }

    pub fn to_items(&self) -> Vec<EvidenceItem> {
        self.entries
            .iter()
            .map(|entry| EvidenceItem {
                kind: entry.kind.as_str().to_string(),
                label: entry.label.clone(),
                value: entry.value.clone(),
            })
            .collect()
    }

    pub fn to_text(&self) -> String {
        let mut lines = vec![self.summary.clone()];
        if let Some(request) = &self.request {
            lines.push(format!("Request: {}", request.redacted_summary()));
        }
        for entry in &self.entries {
            lines.push(format!("{}: {}", entry.label, entry.value));
        }
        lines.join("\n")
    }
}

#[derive(Debug, Clone)]
pub struct FindingFingerprint {
    pub rule_id: String,
    pub severity: Severity,
    pub method: HttpMethod,
    pub location_key: String,
    pub variant: Option<String>,
}

impl FindingFingerprint {
    pub fn for_endpoint(
        rule_id: impl Into<String>,
        severity: Severity,
        method: HttpMethod,
        url: &str,
    ) -> Self {
        Self {
            rule_id: rule_id.into(),
            severity,
            method,
            location_key: normalize_fingerprint_location(url),
            variant: None,
        }
    }

    pub fn for_param(
        rule_id: impl Into<String>,
        severity: Severity,
        method: HttpMethod,
        url: &str,
        param_name: &str,
    ) -> Self {
        Self {
            rule_id: rule_id.into(),
            severity,
            method,
            location_key: normalize_fingerprint_location(url),
            variant: Some(format!("param:{}", param_name)),
        }
    }

    pub fn from_vulnerability(vulnerability: &Vulnerability) -> Self {
        let method = HttpMethod::Get;
        let location = vulnerability
            .affected_endpoints
            .first()
            .cloned()
            .unwrap_or_else(|| vulnerability.location.clone());
        let variant = if vulnerability.fingerprint.is_empty() {
            None
        } else {
            Some(vulnerability.fingerprint.clone())
        };
        Self {
            rule_id: if vulnerability.rule_id.is_empty() {
                vulnerability.id.clone()
            } else {
                vulnerability.rule_id.clone()
            },
            severity: vulnerability.severity.clone(),
            method,
            location_key: normalize_fingerprint_location(&location),
            variant,
        }
    }

    pub fn as_dedup_key(&self) -> String {
        let variant = self.variant.clone().unwrap_or_default();
        format!(
            "{}|{:?}|{}|{}|{}",
            self.rule_id,
            self.severity,
            self.method.as_str(),
            self.location_key,
            variant
        )
    }
}

pub struct ScanRuntime {
    client: reqwest::Client,
    min_interval: Option<Duration>,
    last_request_at: Arc<Mutex<Option<Instant>>>,
    request_count: Arc<AtomicU64>,
}

impl ScanRuntime {
    pub fn new(config: &ScanConfig) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let mut builder = reqwest::Client::builder()
            .timeout(Duration::from_secs(config.http_timeout_secs));
        if config.accept_invalid_certs {
            builder = builder.danger_accept_invalid_certs(true);
        }
        if !config.custom_user_agent.is_empty() {
            builder = builder.user_agent(&config.custom_user_agent);
        }

        let client = builder.build()?;
        let min_interval = if config.rate_limit_rps == 0 {
            None
        } else {
            Some(Duration::from_secs_f64(1.0 / config.rate_limit_rps as f64))
        };

        Ok(Self {
            client,
            min_interval,
            last_request_at: Arc::new(Mutex::new(None)),
            request_count: Arc::new(AtomicU64::new(0)),
        })
    }

    pub fn client(&self) -> &reqwest::Client {
        &self.client
    }

    pub fn request_count(&self) -> u64 {
        self.request_count.load(Ordering::Relaxed)
    }

    pub async fn execute_request(
        &self,
        builder: reqwest::RequestBuilder,
    ) -> Result<reqwest::Response, reqwest::Error> {
        if let Some(min_interval) = self.min_interval {
            let mut last_request_at = self.last_request_at.lock().await;
            if let Some(last) = *last_request_at {
                let elapsed = last.elapsed();
                if elapsed < min_interval {
                    tokio::time::sleep(min_interval - elapsed).await;
                }
            }
            *last_request_at = Some(Instant::now());
        }

        self.request_count.fetch_add(1, Ordering::Relaxed);
        builder.send().await
    }
}

pub fn headers_to_map(headers: &[HeaderPair]) -> HeaderMap {
    let mut map = HeaderMap::new();
    for header in headers {
        if let (Ok(name), Ok(value)) = (
            HeaderName::from_bytes(header.key.as_bytes()),
            HeaderValue::from_str(&header.value),
        ) {
            map.insert(name, value);
        }
    }
    map
}

pub fn merge_tags(existing: &mut Vec<EndpointTag>, incoming: &[EndpointTag]) {
    let mut seen: BTreeSet<&'static str> = existing.iter().map(|tag| tag.as_str()).collect();
    for tag in incoming {
        if seen.insert(tag.as_str()) {
            existing.push(*tag);
        }
    }
}

pub fn merge_parameters(existing: &mut Vec<EndpointParameter>, incoming: &[EndpointParameter]) {
    let mut seen: HashMap<(String, &'static str), ()> = existing
        .iter()
        .map(|parameter| ((parameter.name.clone(), parameter.location.as_str()), ()))
        .collect();

    for parameter in incoming {
        let key = (parameter.name.clone(), parameter.location.as_str());
        if seen.insert(key, ()).is_none() {
            existing.push(parameter.clone());
        }
    }
}

pub fn detect_auth_profile(headers: &[HeaderPair]) -> AuthProfile {
    for header in headers {
        let key = header.key.to_lowercase();
        if key == "authorization" {
            let value = header.value.to_lowercase();
            if value.starts_with("bearer ") {
                return AuthProfile::BearerToken;
            }
            if value.starts_with("basic ") {
                return AuthProfile::Basic;
            }
            return AuthProfile::CustomHeaders;
        }

        if key == "cookie" {
            return AuthProfile::Cookie;
        }
    }

    if headers.is_empty() {
        AuthProfile::Anonymous
    } else {
        AuthProfile::CustomHeaders
    }
}

pub fn normalize_fingerprint_location(url: &str) -> String {
    if let Ok(parsed) = url::Url::parse(url) {
        let mut normalized = parsed.path().to_string();
        if let Some(query) = parsed.query() {
            let mut pairs: Vec<_> = url::form_urlencoded::parse(query.as_bytes())
                .map(|(key, _)| key.to_string())
                .collect();
            pairs.sort();
            pairs.dedup();
            if !pairs.is_empty() {
                normalized.push('?');
                normalized.push_str(&pairs.join("&"));
            }
        }
        return normalized;
    }

    url.to_string()
}

pub fn apply_endpoint_defaults(
    builder: reqwest::RequestBuilder,
    endpoint: &InventoryEndpoint,
    default_value: &str,
) -> reqwest::RequestBuilder {
    match endpoint.method {
        HttpMethod::Post | HttpMethod::Put | HttpMethod::Patch => {
            let form_parameters: Vec<(String, String)> = endpoint
                .parameters
                .iter()
                .filter(|parameter| matches!(parameter.location, ParameterLocation::Form | ParameterLocation::Json))
                .map(|parameter| (parameter.name.clone(), default_value.to_string()))
                .collect();
            if form_parameters.is_empty() {
                builder
            } else {
                builder
                    .header("Content-Type", "application/x-www-form-urlencoded")
                    .form(&form_parameters)
            }
        }
        _ => builder,
    }
}
