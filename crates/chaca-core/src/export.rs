//! Report export formats.
//!
//! These mirror the formats the previous web front end produced, so exported
//! reports stay compatible with existing tooling.

use crate::{ScanResult, Severity};
use serde_json::{json, Value};

/// Formats a scan result can be exported to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExportFormat {
    Json,
    Csv,
    Sarif,
}

impl ExportFormat {
    pub fn as_str(&self) -> &'static str {
        match self {
            ExportFormat::Json => "json",
            ExportFormat::Csv => "csv",
            ExportFormat::Sarif => "sarif",
        }
    }

    pub fn file_extension(&self) -> &'static str {
        self.as_str()
    }
}

/// The file name to use for an exported report.
pub fn export_basename(result: &ScanResult, format: ExportFormat) -> String {
    let host = result
        .url
        .trim_start_matches("https://")
        .trim_start_matches("http://")
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
        .collect::<String>();
    let host = host.trim_matches('-').to_lowercase();
    let host = if host.is_empty() { "scan" } else { &host };
    format!(
        "chaca-{}-{}.{}",
        host,
        crate::today_utc_date(),
        format.file_extension()
    )
}

/// Renders the scan result in the requested format.
pub fn export(result: &ScanResult, format: ExportFormat) -> String {
    match format {
        ExportFormat::Json => export_json(result),
        ExportFormat::Csv => export_csv(result),
        ExportFormat::Sarif => export_sarif(result),
    }
}

pub fn export_json(result: &ScanResult) -> String {
    serde_json::to_string_pretty(result).unwrap_or_else(|_| "{}".to_string())
}

fn escape_csv(value: &str) -> String {
    if value.contains(',') || value.contains('"') || value.contains('\n') {
        format!("\"{}\"", value.replace('"', "\"\""))
    } else {
        value.to_string()
    }
}

pub fn export_csv(result: &ScanResult) -> String {
    let mut rows: Vec<String> = Vec::new();
    let headers = [
        "id",
        "fingerprint",
        "title",
        "severity",
        "confidence",
        "category",
        "location",
        "description",
        "evidence",
        "impact",
        "remediation",
        "affected_endpoints",
    ];
    rows.push(headers.join(","));

    for vuln in &result.vulnerabilities {
        rows.push(
            [
                escape_csv(&vuln.id),
                escape_csv(&vuln.fingerprint),
                escape_csv(&vuln.title),
                escape_csv(vuln.severity.as_str()),
                escape_csv(vuln.confidence.as_str()),
                escape_csv(&vuln.category),
                escape_csv(&vuln.location),
                escape_csv(&vuln.description),
                escape_csv(&vuln.evidence),
                escape_csv(&vuln.impact),
                escape_csv(&vuln.remediation),
                escape_csv(&vuln.affected_endpoints.len().to_string()),
            ]
            .join(","),
        );
    }

    for exp in &result.api_exposures {
        rows.push(
            [
                escape_csv(&format!("api-{}", exp.endpoint)),
                escape_csv(&exp.fingerprint),
                escape_csv(&format!("API Exposure: {}", exp.endpoint)),
                escape_csv(exp.severity.as_str()),
                escape_csv("firm"),
                escape_csv("API Exposure"),
                escape_csv(&exp.endpoint),
                escape_csv(&exp.description),
                escape_csv(""),
                escape_csv(""),
                escape_csv(""),
                escape_csv(""),
            ]
            .join(","),
        );
    }

    for exp in &result.data_exposures {
        let description = if exp.matched_value.is_empty() {
            format!("Field: {}", exp.field)
        } else {
            format!("Field: {}; Match: {}", exp.field, exp.matched_value)
        };
        rows.push(
            [
                escape_csv(&format!("data-{}", exp.field)),
                escape_csv(&exp.fingerprint),
                escape_csv(&format!("Data Exposure: {}", exp.data_type)),
                escape_csv(exp.severity.as_str()),
                escape_csv(exp.confidence.as_str()),
                escape_csv("Data Exposure"),
                escape_csv(&exp.location),
                escape_csv(&description),
                escape_csv(""),
                escape_csv(""),
                escape_csv(""),
                escape_csv(""),
            ]
            .join(","),
        );
    }

    rows.join("\n")
}

fn severity_level(severity: &Severity) -> &'static str {
    match severity {
        Severity::Critical | Severity::High => "error",
        Severity::Medium => "warning",
        _ => "note",
    }
}

fn confidence_rank(confidence: &crate::Confidence) -> &'static str {
    match confidence {
        crate::Confidence::Confirmed => "high",
        crate::Confidence::Firm => "medium",
        crate::Confidence::Tentative => "low",
    }
}

pub fn export_sarif(result: &ScanResult) -> String {
    let mut rules: Vec<Value> = Vec::new();
    let mut results: Vec<Value> = Vec::new();

    for vuln in &result.vulnerabilities {
        let rule_id = if vuln.rule_id.is_empty() {
            vuln.id.clone()
        } else {
            vuln.rule_id.clone()
        };
        rules.push(json!({
            "id": rule_id,
            "name": vuln.title,
            "shortDescription": { "text": vuln.title },
            "fullDescription": { "text": vuln.description },
            "help": { "text": if vuln.remediation.is_empty() { &vuln.impact } else { &vuln.remediation } },
            "properties": {
                "tags": [vuln.category, format!("confidence:{}", vuln.confidence.as_str())],
                "precision": confidence_rank(&vuln.confidence),
            },
        }));

        let mut properties = json!({
            "severity": vuln.severity.as_str(),
            "confidence": vuln.confidence.as_str(),
            "category": vuln.category,
            "evidence": vuln.evidence,
        });
        if !vuln.fingerprint.is_empty() {
            properties
                .as_object_mut()
                .expect("object")
                .insert("fingerprint".to_string(), json!(vuln.fingerprint));
        }

        results.push(json!({
            "ruleId": rule_id,
            "level": severity_level(&vuln.severity),
            "message": { "text": format!("{}: {}", vuln.title, vuln.description) },
            "properties": properties,
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": if vuln.location.is_empty() { &result.url } else { &vuln.location },
                    },
                },
            }],
        }));
    }

    for exp in &result.api_exposures {
        let rule_id = format!("api-exposure:{}", exp.endpoint);
        rules.push(json!({
            "id": rule_id,
            "name": format!("API Exposure: {}", exp.endpoint),
            "shortDescription": { "text": exp.description },
            "fullDescription": { "text": exp.description },
            "help": { "text": "Review why this endpoint is publicly reachable and whether it should require auth or be hidden from discovery." },
            "properties": {
                "tags": ["api-exposure"],
                "precision": "medium",
            },
        }));

        let mut properties = json!({
            "severity": exp.severity.as_str(),
            "category": "api-exposure",
        });
        if !exp.fingerprint.is_empty() {
            properties
                .as_object_mut()
                .expect("object")
                .insert("fingerprint".to_string(), json!(exp.fingerprint));
        }

        results.push(json!({
            "ruleId": rule_id,
            "level": severity_level(&exp.severity),
            "message": { "text": exp.description },
            "properties": properties,
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": { "uri": exp.endpoint },
                },
            }],
        }));
    }

    for exp in &result.data_exposures {
        let rule_id = format!("data-exposure:{}:{}", exp.field, exp.location);
        rules.push(json!({
            "id": rule_id,
            "name": format!("Data Exposure: {}", exp.data_type),
            "shortDescription": { "text": format!("{} exposed at {}", exp.field, exp.location) },
            "fullDescription": { "text": format!("{} matched in a response body.", exp.data_type) },
            "help": { "text": "Remove sensitive data from public responses or enforce field-level authorization." },
            "properties": {
                "tags": ["data-exposure", format!("confidence:{}", exp.confidence.as_str())],
                "precision": confidence_rank(&exp.confidence),
            },
        }));

        let mut properties = json!({
            "severity": exp.severity.as_str(),
            "confidence": exp.confidence.as_str(),
            "category": "data-exposure",
            "matched_value": exp.matched_value,
        });
        if !exp.fingerprint.is_empty() {
            properties
                .as_object_mut()
                .expect("object")
                .insert("fingerprint".to_string(), json!(exp.fingerprint));
        }

        results.push(json!({
            "ruleId": rule_id,
            "level": severity_level(&exp.severity),
            "message": { "text": format!("{}: {} at {}", exp.data_type, exp.field, exp.location) },
            "properties": properties,
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": { "uri": exp.location },
                },
            }],
        }));
    }

    let sarif = json!({
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "Chaca",
                    "version": env!("CARGO_PKG_VERSION"),
                    "informationUri": "https://github.com/madebyaris",
                    "rules": rules,
                },
            },
            "results": results,
        }],
    });

    serde_json::to_string_pretty(&sarif).unwrap_or_else(|_| "{}".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Confidence, ScanResult, ScanType, Severity, Vulnerability};

    fn sample_result() -> ScanResult {
        ScanResult {
            url: "https://example.com".to_string(),
            scan_type: ScanType::Full,
            vulnerabilities: vec![Vulnerability {
                id: "vuln-1".to_string(),
                rule_id: "rule-1".to_string(),
                fingerprint: "fp-1".to_string(),
                title: "Exposed admin panel".to_string(),
                description: "Admin panel is reachable".to_string(),
                severity: Severity::High,
                confidence: Confidence::Confirmed,
                category: "exposed-service".to_string(),
                location: "https://example.com/admin".to_string(),
                evidence: "HTTP 200".to_string(),
                impact: "Full admin access".to_string(),
                remediation: "Restrict access".to_string(),
                affected_endpoints: vec!["https://example.com/admin".to_string()],
                evidence_items: vec![],
                references: vec![],
                cwe: String::new(),
            }],
            ..Default::default()
        }
    }

    #[test]
    fn csv_has_header_and_one_row_per_finding() {
        let csv = export_csv(&sample_result());
        let lines: Vec<&str> = csv.lines().collect();
        assert_eq!(lines.len(), 2);
        assert!(lines[0].starts_with("id,fingerprint,title"));
        assert!(lines[1].contains("vuln-1"));
        assert!(lines[1].contains("Exposed admin panel"));
    }

    #[test]
    fn csv_escapes_embedded_quotes_and_commas() {
        let mut result = sample_result();
        result.vulnerabilities[0].title = "A \"quoted\", title".to_string();
        let csv = export_csv(&result);
        assert!(csv.contains("\"A \"\"quoted\"\", title\""));
    }

    #[test]
    fn sarif_is_valid_json_with_matching_rule_ids() {
        let sarif = export_sarif(&sample_result());
        let parsed: Value = serde_json::from_str(&sarif).expect("valid json");
        assert_eq!(parsed["version"], "2.1.0");
        let rules = parsed["runs"][0]["tool"]["driver"]["rules"].as_array().unwrap();
        let results = parsed["runs"][0]["results"].as_array().unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(results.len(), 1);
        assert_eq!(rules[0]["id"], results[0]["ruleId"]);
        assert_eq!(results[0]["level"], "error");
    }

    #[test]
    fn json_round_trips() {
        let result = sample_result();
        let json = export_json(&result);
        let parsed: ScanResult = serde_json::from_str(&json).expect("round trip");
        assert_eq!(parsed.vulnerabilities.len(), 1);
        assert_eq!(parsed.vulnerabilities[0].severity, Severity::High);
    }

    #[test]
    fn basename_uses_host_and_extension() {
        let name = export_basename(&sample_result(), ExportFormat::Sarif);
        assert!(name.starts_with("chaca-example-com-"));
        assert!(name.ends_with(".sarif"));
    }
}
