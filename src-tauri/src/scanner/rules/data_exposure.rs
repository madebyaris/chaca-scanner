use crate::{Confidence, ScanConfig, Severity};
use regex::Regex;
use std::collections::HashMap;

pub struct DataFinding {
    pub pattern_name: String,
    pub data_type: String,
    pub severity: Severity,
    pub confidence: Confidence,
    pub matched_value: String,
}

fn shannon_entropy(s: &str) -> f64 {
    if s.is_empty() {
        return 0.0;
    }
    let mut freq: HashMap<char, usize> = HashMap::new();
    for c in s.chars() {
        *freq.entry(c).or_insert(0) += 1;
    }
    let len = s.len() as f64;
    freq.values().fold(0.0, |acc, &count| {
        let p = count as f64 / len;
        acc - p * p.log2()
    })
}

fn is_html_context(body: &str, match_start: usize) -> bool {
    let prefix_start = match_start.saturating_sub(100);
    let prefix = &body[prefix_start..match_start].to_lowercase();
    prefix.contains("<input") || prefix.contains("<label") || prefix.contains("<option")
        || prefix.contains("placeholder") || prefix.contains("aria-label")
        || prefix.contains("type=\"password\"") || prefix.contains("type='password'")
        || prefix.contains("<title") || prefix.contains("<meta")
}

pub fn scan_body(body: &str, config: &ScanConfig) -> Vec<DataFinding> {
    let mut findings = Vec::new();
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();

    if config.tier1_secrets {
        scan_tier1_secrets(body, &mut findings, &mut seen);
    }
    if config.tier2_entropy {
        scan_tier2_field_values(body, &mut findings, &mut seen, config.entropy_threshold);
    }
    if config.tier3_pii {
        scan_tier3_pii(body, &mut findings, &mut seen, config.max_pii_matches);
    }

    findings
}

fn scan_tier1_secrets(
    body: &str,
    findings: &mut Vec<DataFinding>,
    seen: &mut std::collections::HashSet<String>,
) {
    let patterns: Vec<(&str, &str, &str)> = vec![
        (r"(?:AKIA|ASIA)[A-Z0-9]{16}", "AWS Access Key", "aws-key"),
        (r"ghp_[a-zA-Z0-9]{36}", "GitHub PAT", "github-pat"),
        (r"gho_[a-zA-Z0-9]{36}", "GitHub OAuth Token", "github-oauth"),
        (r"github_pat_[a-zA-Z0-9_]{82}", "GitHub Fine-Grained PAT", "github-fg-pat"),
        (r"sk-[a-zA-Z0-9]{20}T3BlbkFJ[a-zA-Z0-9]{20}", "OpenAI API Key", "openai-key"),
        (r"sk-(?:proj-)?[a-zA-Z0-9\-_]{40,}", "OpenAI API Key", "openai-key-v2"),
        (r"xox[boaprs]-[a-zA-Z0-9\-]{10,}", "Slack Token", "slack-token"),
        (r"-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----", "Private Key", "private-key"),
        (r"eyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}", "JWT Token", "jwt"),
        (r"AIza[a-zA-Z0-9_\-]{35}", "Google API Key", "google-api-key"),
        (r"sk_live_[a-zA-Z0-9]{24,}", "Stripe Secret Key", "stripe-sk"),
        (r"pk_live_[a-zA-Z0-9]{24,}", "Stripe Publishable Key", "stripe-pk"),
        (r"sq0atp-[a-zA-Z0-9\-_]{22}", "Square Access Token", "square-token"),
        (r"SG\.[a-zA-Z0-9_\-]{22}\.[a-zA-Z0-9_\-]{43}", "SendGrid API Key", "sendgrid-key"),
        (r#"(?:mongodb(?:\+srv)?://)[^\s"'<>]+:[^\s"'<>]+@[^\s"'<>]+"#, "MongoDB Connection String", "mongodb-uri"),
        (r#"(?:postgres|mysql|mssql)://[^\s"'<>]+:[^\s"'<>]+@[^\s"'<>]+"#, "Database Connection String", "db-uri"),
    ];

    for (pattern, data_type, name) in patterns {
        if let Ok(re) = Regex::new(pattern) {
            for mat in re.find_iter(body) {
                let val = mat.as_str().to_string();
                let key = format!("t1-{}-{}", name, &val[..val.len().min(20)]);
                if seen.contains(&key) {
                    continue;
                }
                seen.insert(key);
                findings.push(DataFinding {
                    pattern_name: name.to_string(),
                    data_type: data_type.to_string(),
                    severity: Severity::Critical,
                    confidence: Confidence::Confirmed,
                    matched_value: truncate(&val, 80),
                });
            }
        }
    }
}

fn scan_tier2_field_values(
    body: &str,
    findings: &mut Vec<DataFinding>,
    seen: &mut std::collections::HashSet<String>,
    entropy_threshold: f64,
) {
    let field_re = Regex::new(
        r#"["'](?:api[_\-]?key|secret[_\-]?key|access[_\-]?token|refresh[_\-]?token|auth[_\-]?token|password|passwd|private[_\-]?key|client[_\-]?secret|bearer|authorization)["']\s*[:=]\s*["']([^"']{8,})["']"#
    ).unwrap();

    for cap in field_re.captures_iter(body) {
        if let Some(val_match) = cap.get(1) {
            let val = val_match.as_str();
            let entropy = shannon_entropy(val);
            if entropy < entropy_threshold {
                continue;
            }
            let lower = val.to_lowercase();
            if lower.contains("example") || lower.contains("placeholder")
                || lower.contains("your_") || lower.contains("xxx")
                || lower.contains("test") || lower == "null" || lower == "undefined"
            {
                continue;
            }
            let key = format!("t2-field-{}", &val[..val.len().min(20)]);
            if seen.contains(&key) {
                continue;
            }
            seen.insert(key);
            findings.push(DataFinding {
                pattern_name: "high-entropy-secret".to_string(),
                data_type: "Secret Value in Field".to_string(),
                severity: Severity::High,
                confidence: Confidence::Firm,
                matched_value: truncate(val, 80),
            });
        }
    }
}

fn scan_tier3_pii(
    body: &str,
    findings: &mut Vec<DataFinding>,
    seen: &mut std::collections::HashSet<String>,
    max_matches: usize,
) {
    let pii_patterns: Vec<(&str, &str, &str, Severity)> = vec![
        (
            r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b",
            "Email Address",
            "email",
            Severity::Medium,
        ),
        (
            r"\b\d{3}-\d{2}-\d{4}\b",
            "Social Security Number",
            "ssn",
            Severity::Critical,
        ),
        (
            r"\b(?:4\d{3}|5[1-5]\d{2}|3[47]\d{2}|6(?:011|5\d{2}))[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b",
            "Credit Card Number",
            "credit-card",
            Severity::Critical,
        ),
    ];

    for (pattern, data_type, name, severity) in pii_patterns {
        if let Ok(re) = Regex::new(pattern) {
            let mut count = 0;
            for mat in re.find_iter(body) {
                if count >= max_matches {
                    break;
                }
                let val = mat.as_str();

                if name == "email" {
                    let lower = val.to_lowercase();
                    if lower.ends_with("@example.com") || lower.ends_with("@test.com")
                        || lower.ends_with("@localhost") || lower.contains("noreply")
                        || lower.contains("no-reply")
                    {
                        continue;
                    }
                    if is_html_context(body, mat.start()) {
                        continue;
                    }
                }

                if name == "credit-card" && !luhn_check(val) {
                    continue;
                }

                let key = format!("t3-{}-{}", name, val);
                if seen.contains(&key) {
                    continue;
                }
                seen.insert(key);
                count += 1;
                findings.push(DataFinding {
                    pattern_name: name.to_string(),
                    data_type: data_type.to_string(),
                    severity: severity.clone(),
                    confidence: Confidence::Tentative,
                    matched_value: truncate(val, 80),
                });
            }
        }
    }
}

fn luhn_check(number: &str) -> bool {
    let digits: Vec<u32> = number
        .chars()
        .filter(|c| c.is_ascii_digit())
        .filter_map(|c| c.to_digit(10))
        .collect();
    if digits.len() < 13 || digits.len() > 19 {
        return false;
    }
    let mut sum = 0u32;
    let mut double = false;
    for &d in digits.iter().rev() {
        let mut val = d;
        if double {
            val *= 2;
            if val > 9 {
                val -= 9;
            }
        }
        sum += val;
        double = !double;
    }
    sum % 10 == 0
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        format!("{}...", &s[..max])
    }
}
