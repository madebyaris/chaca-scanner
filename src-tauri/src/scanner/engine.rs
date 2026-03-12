use crate::{
    ApiExposure, AuthState, DataExposure, ScanConfig, ScanMetrics, ScanProgress, ScanRequest,
    ScanResult, ScanType, Severity, Vulnerability,
};
use super::domain::{FindingFingerprint, HttpMethod, RequestContext, ScanRuntime, apply_endpoint_defaults};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, Ordering as AtomicOrdering};
use std::sync::Arc;
use tauri::Emitter;
use tracing::info;

#[derive(Clone)]
pub struct ProgressEmitter {
    app_handle: Option<tauri::AppHandle>,
    findings_count: Arc<AtomicU32>,
}

impl ProgressEmitter {
    pub fn new(app_handle: Option<tauri::AppHandle>) -> Self {
        Self {
            app_handle,
            findings_count: Arc::new(AtomicU32::new(0)),
        }
    }

    pub fn emit(&self, phase: &str, current: u32, total: u32, message: &str) {
        self.emit_detail(phase, current, total, message, "");
    }

    pub fn emit_detail(&self, phase: &str, current: u32, total: u32, message: &str, detail: &str) {
        if let Some(app) = &self.app_handle {
            let _ = app.emit(
                "scan-progress",
                ScanProgress {
                    phase: phase.to_string(),
                    current,
                    total,
                    message: message.to_string(),
                    detail: detail.to_string(),
                    findings_so_far: self.findings_count.load(AtomicOrdering::Relaxed),
                },
            );
        }
    }

    pub fn add_findings(&self, count: u32) {
        self.findings_count.fetch_add(count, AtomicOrdering::Relaxed);
    }

    pub fn findings(&self) -> u32 {
        self.findings_count.load(AtomicOrdering::Relaxed)
    }
}

pub async fn run_scan(
    request: ScanRequest,
    app_handle: Option<tauri::AppHandle>,
) -> Result<ScanResult, Box<dyn std::error::Error + Send + Sync>> {
    fn ensure_not_cancelled() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        if crate::cancel_scan_requested() {
            return Err("Scan cancelled".into());
        }
        Ok(())
    }

    let config = &request.config;
    info!(
        "Initializing scanner engine for URL: {} with type: {:?}",
        request.url, request.scan_type
    );

    let emitter = ProgressEmitter::new(app_handle);

    let runtime = ScanRuntime::new(config)?;
    let base_request = RequestContext::from_scan_config(HttpMethod::Get, &request.url, config)
        .with_label("root");

    emitter.emit("crawling", 0, 100, "Discovering endpoints...");
    ensure_not_cancelled()?;
    let mut inventory = super::crawler::crawl_inventory(&request.url, config, &runtime, &emitter).await?;
    let endpoint_count = inventory.endpoints.len().max(1) as u32;
    emitter.emit(
        "crawling",
        15,
        100,
        &format!("Found {} endpoints to scan", endpoint_count),
    );

    let mut all_vulnerabilities = Vec::new();
    let mut all_api_exposures = Vec::new();
    let mut all_data_exposures = Vec::new();
    let mut response_cache: HashMap<String, (u16, reqwest::header::HeaderMap, String)> =
        HashMap::new();

    emitter.emit_detail("recon", 16, 100, "Collecting target intelligence...", "DNS resolution, TLS, headers");
    ensure_not_cancelled()?;
    let target_info = super::recon::collect_target_info(&request.url, &runtime, config).await;
    info!(
        "Target info collected: {} IPs, {} technologies, server: {}",
        target_info.ip_addresses.len(),
        target_info.technologies.len(),
        target_info.server
    );

    let run_passive = matches!(request.scan_type, ScanType::Passive | ScanType::Full);
    let run_active = matches!(request.scan_type, ScanType::Active | ScanType::Full);
    let mut auth_validated = false;
    let mut auth_failed = false;
    let mut passive_vulnerability_count = 0u32;
    let mut active_vulnerability_count = 0u32;

    let cms_detected = if config.cms_detection {
        emitter.emit_detail("fingerprint", 18, 100, "Detecting CMS...", "Analyzing response headers and body");
        match runtime
            .execute_request(base_request.clone().into_builder(runtime.client()))
            .await
        {
            Ok(response) => {
                let headers = response.headers().clone();
                let body = response.text().await.unwrap_or_default();
                super::cms::fingerprint_cms(&headers, &body)
            }
            Err(_) => None,
        }
    } else {
        None
    };

    if let Some(ref cms) = cms_detected {
        info!("CMS detected: {:?}", cms);
        emitter.emit("fingerprint", 20, 100, &format!("Detected CMS: {:?}", cms));
    } else {
        emitter.emit("fingerprint", 20, 100, "No CMS detected");
    }

    if run_passive {
        emitter.emit("passive", 22, 100, "Running passive analysis...");
        for (i, endpoint) in inventory.endpoints.iter_mut().enumerate() {
            ensure_not_cancelled()?;
            let pct = 22 + (i as u32 * 28 / endpoint_count);
            let short_path = shorten_url(&endpoint.url);
            emitter.emit_detail(
                "passive",
                pct,
                100,
                &format!("Analyzing endpoint {}/{}", i + 1, endpoint_count),
                &short_path,
            );

            let passive_method = match endpoint.method {
                HttpMethod::Get | HttpMethod::Head | HttpMethod::Options => endpoint.method,
                _ => HttpMethod::Options,
            };
            let context =
                RequestContext::from_scan_config(passive_method, &endpoint.url, config)
                    .with_label("passive");
            let request_builder = apply_endpoint_defaults(
                context.into_builder(runtime.client()),
                endpoint,
                "baseline",
            );
            if let Ok(response) = runtime.execute_request(request_builder).await
            {
                let status = response.status().as_u16();
                let headers = response.headers().clone();
                let body = response.text().await.unwrap_or_default();
                endpoint.last_status = Some(status);
                endpoint.baseline_length = Some(body.len());

                if !matches!(base_request.auth_profile, super::domain::AuthProfile::Anonymous) {
                    let auth_candidate = endpoint.tags.contains(&super::domain::EndpointTag::Admin)
                        || endpoint.tags.contains(&super::domain::EndpointTag::AuthRelated)
                        || endpoint.tags.contains(&super::domain::EndpointTag::Api)
                        || endpoint.url.to_lowercase().contains("/graphql");
                    if auth_candidate && (status == 401 || status == 403) {
                        auth_failed = true;
                    } else if auth_candidate && !(status == 401 || status == 403) {
                        auth_validated = true;
                    }
                }

                response_cache.insert(endpoint.url.clone(), (status, headers.clone(), body.clone()));
                let vulns = super::passive::analyze_response(
                    &endpoint.url,
                    status,
                    &headers,
                    &body,
                    config,
                );
                if !vulns.is_empty() {
                    emitter.add_findings(vulns.len() as u32);
                }
                all_vulnerabilities.extend(vulns);
            }
        }
        passive_vulnerability_count = all_vulnerabilities.len() as u32;

        emitter.emit("passive", 52, 100, "Checking API exposures...");
        let mut api_checks = super::rules::api_exposure::get_api_exposure_checks();
        for custom_path in &config.custom_api_paths {
            let trimmed = custom_path.trim();
            if !trimmed.is_empty() {
                api_checks.push((trimmed, Severity::Medium));
            }
        }
        let base_url = request.url.trim_end_matches('/');
        let total_api_checks = api_checks.len();
        for (api_i, (path, severity)) in api_checks.iter().enumerate() {
            ensure_not_cancelled()?;
            let test_url = format!("{}{}", base_url, path);
            let api_pct = 52 + (api_i as u32 * 5 / total_api_checks.max(1) as u32);
            emitter.emit_detail("passive", api_pct, 100, &format!("Probing API path {}/{}", api_i + 1, total_api_checks), path);
            let context =
                RequestContext::from_scan_config(HttpMethod::Get, &test_url, config)
                    .with_label("api_exposure");
            if let Ok(response) = runtime
                .execute_request(context.into_builder(runtime.client()))
                .await
            {
                if response.status().is_success() {
                    let fingerprint = FindingFingerprint::for_endpoint(
                        format!("api-exposure:{}", path),
                        severity.clone(),
                        HttpMethod::Get,
                        &test_url,
                    )
                    .as_dedup_key();
                    all_api_exposures.push(ApiExposure {
                        fingerprint,
                        endpoint: test_url,
                        method: "GET".to_string(),
                        description: format!("API endpoint discovered: {}", path),
                        severity: severity.clone(),
                    });
                }
            }
        }

        emitter.emit("passive", 58, 100, "Checking for data exposure...");
        for (de_i, endpoint) in inventory.endpoints.iter().enumerate() {
            emitter.emit_detail("passive", 58, 100, &format!("Scanning response body {}/{}", de_i + 1, endpoint_count), &shorten_url(&endpoint.url));
            ensure_not_cancelled()?;
            if let Some((_, _, body)) = response_cache.get(&endpoint.url) {
                let findings = super::rules::data_exposure::scan_body(body, config);
                for finding in findings {
                    let fingerprint = format!(
                        "data:{}:{}:{}",
                        finding.pattern_name,
                        finding.data_type,
                        super::domain::normalize_fingerprint_location(&endpoint.url)
                    );
                    all_data_exposures.push(DataExposure {
                        fingerprint,
                        field: finding.pattern_name,
                        data_type: finding.data_type,
                        location: endpoint.url.clone(),
                        severity: finding.severity,
                        confidence: finding.confidence,
                        matched_value: finding.matched_value,
                    });
                }
            }
        }

        if let Some(ref cms) = cms_detected {
            emitter.emit_detail("cms", 62, 100, "Running CMS-specific checks...", &format!("{:?}", cms));
            ensure_not_cancelled()?;
            let cms_vulns = super::cms::run_cms_checks(cms, &request.url, runtime.client()).await;
            all_vulnerabilities.extend(cms_vulns);
        }

        if config.generic_exposure_checks {
            emitter.emit_detail("generic", 65, 100, "Running generic exposure checks...", ".git, .env, debug endpoints");
            ensure_not_cancelled()?;
            let generic_vulns = super::cms::run_generic_checks(&request.url, runtime.client()).await;
            all_vulnerabilities.extend(generic_vulns);
        }

        if config.check_exposed_services {
            emitter.emit_detail("services", 67, 100, "Checking for exposed services...", "Databases, caches, message queues");
            ensure_not_cancelled()?;
            let initial_body = response_cache
                .get(&request.url)
                .map(|(_, _, body)| body.clone())
                .unwrap_or_default();
            let svc_vulns = super::rules::exposed_services::check_exposed_databases(
                &request.url,
                runtime.client(),
                &initial_body,
            )
            .await;
            all_vulnerabilities.extend(svc_vulns);
        }

        if config.check_admin_panels {
            emitter.emit_detail("admin", 68, 100, "Checking for exposed admin panels...", "/admin, /wp-admin, /phpmyadmin");
            ensure_not_cancelled()?;
            let admin_vulns =
                super::rules::exposed_services::check_admin_panels(&request.url, runtime.client())
                    .await;
            all_vulnerabilities.extend(admin_vulns);
        }
    }

    let active_candidate_total = inventory.active_candidates().count() as u32;

    if run_active {
        emitter.emit("active", 70, 100, "Running active vulnerability tests...");
        ensure_not_cancelled()?;
        let active_vulns = super::active::test_inventory(&inventory, &runtime, config, &emitter).await?;
        active_vulnerability_count = active_vulns.len() as u32;
        emitter.add_findings(active_vulnerability_count);
        all_vulnerabilities.extend(active_vulns);
        emitter.emit("active", 90, 100, "Active scan complete");
    }

    all_vulnerabilities
        .retain(|vulnerability| severity_rank(&vulnerability.severity) <= severity_rank(&config.min_severity));
    all_api_exposures
        .retain(|exposure| severity_rank(&exposure.severity) <= severity_rank(&config.min_severity));
    all_data_exposures
        .retain(|exposure| severity_rank(&exposure.severity) <= severity_rank(&config.min_severity));

    emitter.emit("analysis", 92, 100, "Deduplicating findings...");
    let mut deduped = deduplicate_vulnerabilities(all_vulnerabilities);

    emitter.emit_detail("analysis", 95, 100, "Enriching findings with vulnerability database...", "CWE, references, remediation");
    enrich_from_vuln_db(&mut deduped);

    for vulnerability in &mut deduped {
        if vulnerability.rule_id.is_empty() {
            vulnerability.rule_id = vulnerability.id.clone();
        }
        if vulnerability.fingerprint.is_empty() {
            vulnerability.fingerprint = FindingFingerprint::from_vulnerability(vulnerability)
                .as_dedup_key();
        }
    }

    emitter.emit("complete", 100, 100, "Scan complete");

    let security_score =
        calculate_security_score(&deduped, &all_api_exposures, &all_data_exposures, config);
    let metrics = build_metrics(
        &inventory,
        &deduped,
        &all_api_exposures,
        &all_data_exposures,
        runtime.request_count(),
        passive_vulnerability_count,
        active_vulnerability_count,
        active_candidate_total,
        base_request.auth_state().applied,
    );

    Ok(ScanResult {
        url: request.url,
        scan_type: request.scan_type,
        vulnerabilities: deduped,
        api_exposures: dedupe_api_exposures(all_api_exposures),
        data_exposures: dedupe_data_exposures(all_data_exposures),
        security_score,
        scan_duration_ms: 0,
        cms_detected,
        target_info: Some(target_info),
        auth_state: finalize_auth_state(base_request.auth_state(), auth_validated, auth_failed),
        inventory: inventory
            .endpoints
            .iter()
            .map(|endpoint| endpoint.to_summary())
            .collect(),
        metrics,
    })
}

fn deduplicate_vulnerabilities(vulns: Vec<Vulnerability>) -> Vec<Vulnerability> {
    let mut groups: HashMap<String, Vulnerability> = HashMap::new();

    for mut vuln in vulns {
        if vuln.rule_id.is_empty() {
            vuln.rule_id = vuln.id.clone();
        }
        let key = if vuln.fingerprint.is_empty() {
            FindingFingerprint::from_vulnerability(&vuln).as_dedup_key()
        } else {
            vuln.fingerprint.clone()
        };
        groups
            .entry(key.clone())
            .and_modify(|existing| {
                for endpoint in &vuln.affected_endpoints {
                    if !existing.affected_endpoints.contains(endpoint) {
                        existing.affected_endpoints.push(endpoint.clone());
                    }
                }
                if vuln.evidence.len() > existing.evidence.len() {
                    existing.evidence = vuln.evidence.clone();
                    existing.evidence_items = vuln.evidence_items.clone();
                }
            })
            .or_insert_with(|| {
                vuln.fingerprint = key;
                vuln
            });
    }

    let mut result: Vec<Vulnerability> = groups.into_values().collect();
    result.sort_by(|a, b| severity_rank(&a.severity).cmp(&severity_rank(&b.severity)));

    for vuln in &mut result {
        let count = vuln.affected_endpoints.len();
        if count > 1 {
            vuln.description = format!("{} (found on {} endpoints)", vuln.description, count);
        }
    }

    result
}

fn dedupe_api_exposures(exposures: Vec<ApiExposure>) -> Vec<ApiExposure> {
    let mut seen = HashMap::new();
    for exposure in exposures {
        let key = if exposure.fingerprint.is_empty() {
            format!("{}|{}", exposure.endpoint, exposure.method)
        } else {
            exposure.fingerprint.clone()
        };
        seen.entry(key).or_insert(exposure);
    }
    seen.into_values().collect()
}

fn dedupe_data_exposures(exposures: Vec<DataExposure>) -> Vec<DataExposure> {
    let mut seen = HashMap::new();
    for exposure in exposures {
        let key = if exposure.fingerprint.is_empty() {
            format!("{}|{}|{}", exposure.location, exposure.field, exposure.data_type)
        } else {
            exposure.fingerprint.clone()
        };
        seen.entry(key).or_insert(exposure);
    }
    seen.into_values().collect()
}

fn severity_rank(s: &Severity) -> u8 {
    match s {
        Severity::Critical => 0,
        Severity::High => 1,
        Severity::Medium => 2,
        Severity::Low => 3,
        Severity::Info => 4,
    }
}

fn finalize_auth_state(mut auth_state: AuthState, validated: bool, failed: bool) -> AuthState {
    if !auth_state.applied {
        auth_state.status = "anonymous".to_string();
        return auth_state;
    }

    auth_state.status = if validated {
        "validated".to_string()
    } else if failed {
        "failed".to_string()
    } else {
        "unverified".to_string()
    };
    auth_state
}

fn build_metrics(
    inventory: &super::domain::EndpointInventory,
    vulnerabilities: &[Vulnerability],
    api_exposures: &[ApiExposure],
    data_exposures: &[DataExposure],
    request_count: u64,
    passive_vulnerability_count: u32,
    active_vulnerability_count: u32,
    active_candidate_total: u32,
    auth_applied: bool,
) -> ScanMetrics {
    let confirmed_findings = vulnerabilities
        .iter()
        .filter(|item| matches!(item.confidence, crate::Confidence::Confirmed))
        .count() as u32;
    let tentative_findings = vulnerabilities
        .iter()
        .filter(|item| matches!(item.confidence, crate::Confidence::Tentative))
        .count() as u32;

    ScanMetrics {
        request_count,
        endpoint_total: inventory.endpoints.len() as u32,
        active_candidate_total,
        passive_vulnerability_count,
        active_vulnerability_count,
        api_exposure_count: api_exposures.len() as u32,
        data_exposure_count: data_exposures.len() as u32,
        artifact_seed_count: inventory.artifact_seed_count as u32,
        authenticated_request_count: if auth_applied {
            request_count.min(u64::from(u32::MAX)) as u32
        } else {
            0
        },
        confirmed_finding_count: confirmed_findings,
        tentative_finding_count: tentative_findings,
    }
}

fn calculate_security_score(
    vulnerabilities: &[Vulnerability],
    api_exposures: &[ApiExposure],
    data_exposures: &[DataExposure],
    config: &ScanConfig,
) -> u32 {
    let mut crit_deduct: i32 = 0;
    let mut high_deduct: i32 = 0;
    let mut med_deduct: i32 = 0;
    let mut low_deduct: i32 = 0;

    for vuln in vulnerabilities {
        match vuln.severity {
            Severity::Critical => crit_deduct += config.score_critical_weight,
            Severity::High => high_deduct += config.score_high_weight,
            Severity::Medium => med_deduct += config.score_medium_weight,
            Severity::Low => low_deduct += config.score_low_weight,
            Severity::Info => {}
        }
    }

    for exp in api_exposures {
        match exp.severity {
            Severity::Critical => crit_deduct += config.score_critical_weight * 2 / 3,
            Severity::High => high_deduct += config.score_high_weight * 7 / 10,
            Severity::Medium => med_deduct += config.score_medium_weight * 3 / 5,
            Severity::Low => low_deduct += 1,
            Severity::Info => {}
        }
    }

    for exp in data_exposures {
        match exp.severity {
            Severity::Critical => crit_deduct += config.score_critical_weight * 4 / 5,
            Severity::High => high_deduct += config.score_high_weight * 4 / 5,
            Severity::Medium => med_deduct += config.score_medium_weight * 4 / 5,
            Severity::Low => low_deduct += 1,
            Severity::Info => {}
        }
    }

    let crit_capped = crit_deduct.min(config.score_critical_cap);
    let high_capped = high_deduct.min(config.score_high_cap);
    let med_capped = med_deduct.min(config.score_medium_cap);
    let low_capped = low_deduct.min(config.score_low_cap);

    let total_deduction = crit_capped + high_capped + med_capped + low_capped;
    let score = (100 - total_deduction).max(0);

    score as u32
}

fn shorten_url(url: &str) -> String {
    if let Ok(parsed) = url::Url::parse(url) {
        let path = parsed.path();
        if path.len() > 60 {
            format!("...{}", &path[path.len() - 57..])
        } else {
            path.to_string()
        }
    } else {
        url.to_string()
    }
}

fn enrich_from_vuln_db(vulns: &mut [Vulnerability]) {
    for vuln in vulns.iter_mut() {
        if let Some(entry) = super::rules::vuln_db::get_vuln_info(&vuln.id) {
            if vuln.references.is_empty() {
                vuln.references = entry.references.iter().map(|r| r.to_string()).collect();
            }
            if vuln.cwe.is_empty() {
                vuln.cwe = entry.cwe.to_string();
            }
        }
    }
}
