use crate::{
    ApiExposure, DataExposure, ScanConfig, ScanProgress, ScanRequest, ScanResult, ScanType,
    Severity, Vulnerability,
};
use std::collections::HashMap;
use tauri::Emitter;
use tracing::info;

pub async fn run_scan(
    request: ScanRequest,
    app_handle: Option<tauri::AppHandle>,
) -> Result<ScanResult, Box<dyn std::error::Error + Send + Sync>> {
    let config = &request.config;
    info!(
        "Initializing scanner engine for URL: {} with type: {:?}",
        request.url, request.scan_type
    );

    let emit = |phase: &str, current: u32, total: u32, message: &str| {
        if let Some(app) = &app_handle {
            let _ = app.emit(
                "scan-progress",
                ScanProgress {
                    phase: phase.to_string(),
                    current,
                    total,
                    message: message.to_string(),
                },
            );
        }
    };

    emit("crawling", 0, 100, "Discovering endpoints...");

    let endpoints = super::crawler::crawl(&request.url, config).await?;
    let endpoint_count = endpoints.len().max(1) as u32;

    emit(
        "crawling",
        15,
        100,
        &format!("Found {} endpoints to scan", endpoint_count),
    );

    let mut all_vulnerabilities = Vec::new();
    let mut all_api_exposures = Vec::new();
    let mut all_data_exposures = Vec::new();

    let mut client_builder = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(config.http_timeout_secs));
    if config.accept_invalid_certs {
        client_builder = client_builder.danger_accept_invalid_certs(true);
    }
    if !config.custom_user_agent.is_empty() {
        client_builder = client_builder.user_agent(&config.custom_user_agent);
    }
    let client = client_builder.build()?;

    // Collect target intelligence (recon)
    emit("recon", 16, 100, "Collecting target intelligence...");
    let target_info = super::recon::collect_target_info(&request.url, &client).await;
    info!("Target info collected: {} IPs, {} technologies, server: {}",
        target_info.ip_addresses.len(), target_info.technologies.len(), target_info.server);

    let run_passive = matches!(request.scan_type, ScanType::Passive | ScanType::Full);
    let run_active = matches!(request.scan_type, ScanType::Active | ScanType::Full);

    // CMS fingerprinting
    let cms_detected = if config.cms_detection {
        emit("fingerprint", 18, 100, "Detecting CMS...");
        match client.get(&request.url).send().await {
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
        emit(
            "fingerprint",
            20,
            100,
            &format!("Detected CMS: {:?}", cms),
        );
    } else {
        emit("fingerprint", 20, 100, "No CMS detected");
    }

    if run_passive {
        emit("passive", 22, 100, "Running passive analysis...");
        for (i, url) in endpoints.iter().enumerate() {
            let pct = 22 + (i as u32 * 28 / endpoint_count);
            emit("passive", pct, 100, &format!("Analyzing {}", url));

            match client.get(url).send().await {
                Ok(response) => {
                    let status = response.status().as_u16();
                    let headers = response.headers().clone();
                    let body = response.text().await.unwrap_or_default();

                    let vulns =
                        super::passive::analyze_response(url, status, &headers, &body, config);
                    all_vulnerabilities.extend(vulns);
                }
                Err(_) => {}
            }
        }

        emit("passive", 52, 100, "Checking API exposures...");
        let mut api_checks = super::rules::api_exposure::get_api_exposure_checks();
        for custom_path in &config.custom_api_paths {
            let trimmed = custom_path.trim();
            if !trimmed.is_empty() {
                api_checks.push((trimmed, Severity::Medium));
            }
        }
        let base_url = request.url.trim_end_matches('/');
        for (path, severity) in &api_checks {
            let test_url = format!("{}{}", base_url, path);
            if let Ok(response) = client.get(&test_url).send().await {
                if response.status().is_success() {
                    all_api_exposures.push(ApiExposure {
                        endpoint: test_url,
                        method: "GET".to_string(),
                        description: format!("API endpoint discovered: {}", path),
                        severity: severity.clone(),
                    });
                }
            }
        }

        emit("passive", 58, 100, "Checking for data exposure...");
        for url in &endpoints {
            if let Ok(response) = client.get(url).send().await {
                if let Ok(body) = response.text().await {
                    let findings = super::rules::data_exposure::scan_body(&body, config);
                    for finding in findings {
                        all_data_exposures.push(DataExposure {
                            field: finding.pattern_name,
                            data_type: finding.data_type,
                            location: url.to_string(),
                            severity: finding.severity,
                            confidence: finding.confidence,
                        });
                    }
                }
            }
        }

        // CMS-specific checks
        if let Some(ref cms) = cms_detected {
            emit("cms", 62, 100, "Running CMS-specific checks...");
            let cms_vulns = super::cms::run_cms_checks(cms, &request.url, &client).await;
            all_vulnerabilities.extend(cms_vulns);
        }

        // Generic checks (git, env, robots)
        if config.generic_exposure_checks {
            emit("generic", 65, 100, "Running generic exposure checks...");
            let generic_vulns = super::cms::run_generic_checks(&request.url, &client).await;
            all_vulnerabilities.extend(generic_vulns);
        }

        // Exposed database services
        if config.check_exposed_services {
            emit("services", 67, 100, "Checking for exposed database services...");
            let initial_body = match client.get(&request.url).send().await {
                Ok(resp) => resp.text().await.unwrap_or_default(),
                Err(_) => String::new(),
            };
            let svc_vulns = super::rules::exposed_services::check_exposed_databases(
                &request.url, &client, &initial_body
            ).await;
            all_vulnerabilities.extend(svc_vulns);
        }

        // Exposed admin panels
        if config.check_admin_panels {
            emit("admin", 68, 100, "Checking for exposed admin panels...");
            let admin_vulns = super::rules::exposed_services::check_admin_panels(
                &request.url, &client
            ).await;
            all_vulnerabilities.extend(admin_vulns);
        }
    }

    if run_active {
        emit("active", 70, 100, "Running active vulnerability tests...");
        let active_vulns =
            super::active::test_vulnerabilities(&request.url, config).await?;
        all_vulnerabilities.extend(active_vulns);
        emit("active", 90, 100, "Active scan complete");
    }

    // Filter by minimum severity
    all_vulnerabilities.retain(|v| severity_rank(&v.severity) <= severity_rank(&config.min_severity));
    all_api_exposures.retain(|e| severity_rank(&e.severity) <= severity_rank(&config.min_severity));
    all_data_exposures.retain(|e| severity_rank(&e.severity) <= severity_rank(&config.min_severity));

    // Deduplicate findings
    emit("analysis", 92, 100, "Deduplicating findings...");
    let mut deduped = deduplicate_vulnerabilities(all_vulnerabilities);

    // Enrich with vulnerability database metadata
    emit("analysis", 95, 100, "Enriching findings with vulnerability database...");
    enrich_from_vuln_db(&mut deduped);

    emit("complete", 100, 100, "Scan complete");

    let security_score =
        calculate_security_score(&deduped, &all_api_exposures, &all_data_exposures, config);

    Ok(ScanResult {
        url: request.url,
        scan_type: request.scan_type,
        vulnerabilities: deduped,
        api_exposures: all_api_exposures,
        data_exposures: all_data_exposures,
        security_score,
        scan_duration_ms: 0,
        cms_detected,
        target_info: Some(target_info),
    })
}

fn deduplicate_vulnerabilities(vulns: Vec<Vulnerability>) -> Vec<Vulnerability> {
    let mut groups: HashMap<String, Vulnerability> = HashMap::new();

    for vuln in vulns {
        let key = format!("{}|{:?}", vuln.id, vuln.severity);
        groups
            .entry(key)
            .and_modify(|existing| {
                for ep in &vuln.affected_endpoints {
                    if !existing.affected_endpoints.contains(ep) {
                        existing.affected_endpoints.push(ep.clone());
                    }
                }
                if vuln.evidence.len() > existing.evidence.len() {
                    existing.evidence = vuln.evidence.clone();
                }
            })
            .or_insert(vuln);
    }

    let mut result: Vec<Vulnerability> = groups.into_values().collect();
    result.sort_by(|a, b| severity_rank(&a.severity).cmp(&severity_rank(&b.severity)));

    for vuln in &mut result {
        let count = vuln.affected_endpoints.len();
        if count > 1 {
            vuln.description = format!(
                "{} (found on {} endpoints)",
                vuln.description, count
            );
        }
    }

    result
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
