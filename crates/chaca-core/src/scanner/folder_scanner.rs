//! Local folder scanning MVP: secrets, config exposure, endpoint inventory.
//! All scanning is local-only; no content leaves the machine.

use crate::{
    ApiExposure, Confidence, DataExposure, ScanMetrics, ScanResult, ScanType, Severity,
    Vulnerability,
};
use regex::Regex;
use std::collections::HashSet;
use std::fs;
use std::path::Path;
use std::time::Instant;
use tracing::info;
use walkdir::WalkDir;

const MAX_FILE_SIZE_BYTES: u64 = 512 * 1024; // 512KB
const DEFAULT_EXCLUDES: &[&str] = &[
    ".git",
    "node_modules",
    "dist",
    "build",
    ".next",
    "target",
    "__pycache__",
    ".venv",
    "venv",
    ".cache",
    "vendor",
    ".idea",
    ".vscode",
    "*.min.js",
    "*.min.css",
    "*.map",
];

/// Check if path should be excluded from scanning
fn is_excluded(path: &Path) -> bool {
    for component in path.components() {
        let s = component.as_os_str().to_string_lossy();
        for excl in DEFAULT_EXCLUDES {
            if excl.starts_with('*') {
                if s.ends_with(&excl[1..]) {
                    return true;
                }
            } else if s == *excl || s.starts_with(&format!("{}.", excl)) {
                return true;
            }
        }
    }
    false
}

/// Known secret patterns (provider-format regexes)
fn secret_patterns() -> Vec<(&'static str, &'static str, Severity)> {
    vec![
        (
            "aws_secret",
            r#"(?i)aws_secret_access_key\s*=\s*["']?([A-Za-z0-9/+=]{40})["']?"#,
            Severity::Critical,
        ),
        (
            "aws_key",
            r#"(?i)aws_access_key_id\s*=\s*["']?([A-Za-z0-9]{20})["']?"#,
            Severity::High,
        ),
        (
            "github_token",
            r"(?i)(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,}",
            Severity::Critical,
        ),
        (
            "slack_token",
            r"(?i)xox[baprs]-[0-9a-zA-Z-]{10,}",
            Severity::High,
        ),
        (
            "stripe_key",
            r"(?i)(?:sk|pk)_(?:live|test)_[0-9a-zA-Z]{24,}",
            Severity::Critical,
        ),
        (
            "generic_api_key",
            r#"(?i)(?:api[_-]?key|apikey)\s*[:=]\s*["']?([a-zA-Z0-9_\-]{20,})["']?"#,
            Severity::High,
        ),
        (
            "private_key",
            r"-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----",
            Severity::Critical,
        ),
        (
            "password",
            r#"(?i)password\s*[:=]\s*["']?([^\s"']{8,})["']?"#,
            Severity::High,
        ),
    ]
}

/// Config exposure: sensitive file patterns
fn config_file_patterns() -> Vec<(&'static str, &'static str, Severity)> {
    vec![
        (".env", r"\.env$", Severity::High),
        (
            "config_secrets",
            r"(?:config|settings).*\.(?:json|yaml|yml|toml)$",
            Severity::Medium,
        ),
        (
            "ci_secrets",
            r"\.(?:github|gitlab)/workflows/.*\.ya?ml$",
            Severity::Medium,
        ),
        ("dockerfile", r"Dockerfile", Severity::Low),
        ("k8s_secret", r".*secret.*\.ya?ml$", Severity::High),
        ("terraform", r"\.tf$", Severity::Low),
    ]
}

/// Endpoint extraction patterns (pattern, capture_group 1 = path)
fn endpoint_patterns() -> Vec<(&'static str, &'static str)> {
    vec![
        (
            "express_route",
            r#"(?:app|router)\.(?:get|post|put|delete|patch)\s*\(\s*['"]([^'"]+)['"]"#,
        ),
        ("nextjs_route", r#"(?:api|app)/([a-zA-Z0-9/_\-{}]+)"#),
        (
            "fastapi",
            r#"(?:app|router)\.(?:get|post|put|delete)\s*\(\s*['"]([^'"]+)['"]"#,
        ),
        ("graphql", r#"(?:graphql|gql)\s*\(\s*['"]([^'"]+)['"]"#),
        ("url_string", r#"['"](https?://[^'"]+)['"]"#),
    ]
}

/// Code smell patterns (rule, regex, severity, CWE label)
fn code_smell_patterns() -> Vec<(&'static str, &'static str, Severity, &'static str)> {
    vec![
        (
            "folder-weak-crypto",
            r#"\bmd5\(|\bsha1\(|createHash\(['"]md5|hashlib\.(?:md5|sha1)\b"#,
            Severity::Medium,
            "CWE-328 - Use of Weak Hash",
        ),
        (
            "folder-insecure-random",
            r"Math\.random\(\)|\bmt_rand\(|random\.random\(\)",
            Severity::Medium,
            "CWE-330 - Use of Insufficiently Random Values",
        ),
        (
            "folder-xss-sink",
            r"innerHTML|dangerouslySetInnerHTML|\beval\(",
            Severity::Medium,
            "CWE-79 - Cross-site Scripting (XSS)",
        ),
        (
            "folder-plain-http",
            r#"http://[^\s'"()]{3,}"#,
            Severity::Info,
            "CWE-319 - Cleartext Transmission of Sensitive Information",
        ),
        (
            "folder-security-todo",
            r"(?i)\b(?:TODO|FIXME|XXX|HACK)\b[^\n]{0,80}\b(?:secur|auth|csrf|secret|token|password|sso|oauth|2fa|tls|cookie)\b",
            Severity::Info,
            "Maintainability",
        ),
    ]
}

/// Extensions eligible for each code smell rule
fn smell_extensions(rule_id: &str) -> Option<&'static [&'static str]> {
    match rule_id {
        "folder-xss-sink" => Some(&[
            "js", "ts", "jsx", "tsx", "mjs", "cjs", "html", "vue", "svelte",
        ]),
        "folder-insecure-random" => Some(&["js", "ts", "jsx", "tsx", "mjs", "cjs", "php", "py"]),
        _ => None,
    }
}

fn is_lockfile(name: &str) -> bool {
    matches!(
        name,
        "package-lock.json"
            | "yarn.lock"
            | "pnpm-lock.yaml"
            | "Cargo.lock"
            | "go.sum"
            | "composer.lock"
            | "Gemfile.lock"
            | "poetry.lock"
    )
}

fn redact_value(value: &str) -> String {
    if value.len() <= 4 {
        return "***".to_string();
    }
    let head: String = value.chars().take(4).collect();
    format!("{}… ({} chars redacted)", head, value.len())
}

fn shannon_entropy(s: &str) -> f64 {
    let mut freq = [0u64; 256];
    for b in s.bytes() {
        freq[b as usize] += 1;
    }
    let len = s.len() as f64;
    if len == 0.0 {
        return 0.0;
    }
    let mut entropy = 0.0;
    for &c in freq.iter().filter(|&&c| c > 0) {
        let p = c as f64 / len;
        entropy -= p * p.log2();
    }
    entropy
}

pub fn scan_folder(path: &str) -> Result<ScanResult, String> {
    let start = Instant::now();
    let root = Path::new(path);
    if !root.is_dir() {
        return Err(format!("Not a directory: {}", path));
    }

    let mut vulnerabilities: Vec<Vulnerability> = Vec::new();
    let mut data_exposures: Vec<DataExposure> = Vec::new();
    let mut api_exposures: Vec<ApiExposure> = Vec::new();
    let mut seen_endpoints: HashSet<String> = HashSet::new();

    let secret_regexes: Vec<_> = secret_patterns()
        .into_iter()
        .map(|(id, pat, sev)| (id, Regex::new(pat).unwrap(), sev))
        .collect();

    let config_regexes: Vec<_> = config_file_patterns()
        .into_iter()
        .map(|(id, pat, sev)| (id, Regex::new(pat).unwrap(), sev))
        .collect();

    let endpoint_regexes: Vec<_> = endpoint_patterns()
        .into_iter()
        .map(|(id, pat)| (id, Regex::new(pat).unwrap()))
        .collect();

    let smell_regexes: Vec<_> = code_smell_patterns()
        .into_iter()
        .map(|(id, pat, severity, cwe)| (id, Regex::new(pat).unwrap(), severity, cwe))
        .collect();

    let mut files_scanned = 0u32;

    // Git repository origin (leaks internal repo host / project name)
    let git_config_path = root.join(".git").join("config");
    if git_config_path.is_file() {
        if let Ok(git_config) = fs::read_to_string(&git_config_path) {
            for line in git_config.lines() {
                let trimmed = line.trim();
                if !trimmed.starts_with("url") {
                    continue;
                }
                if let Some(url) = trimmed
                    .strip_prefix("url")
                    .and_then(|rest| rest.trim_start().strip_prefix('='))
                    .map(|url| url.trim().to_string())
                    .filter(|url| !url.is_empty())
                {
                    vulnerabilities.push(Vulnerability {
                        id: "folder-git-origin".to_string(),
                        rule_id: "folder-git-origin".to_string(),
                        fingerprint: "folder-git-origin".to_string(),
                        title: "Git Origin Remote Detected".to_string(),
                        description: format!("Repository origin remote: {}", url),
                        severity: Severity::Info,
                        confidence: Confidence::Confirmed,
                        category: "Information Disclosure".to_string(),
                        location: "file://.git/config".to_string(),
                        evidence: url,
                        impact: "Internal repository hosts and project names can leak into build artifacts and error pages."
                            .to_string(),
                        remediation: "Keep the .git directory out of distributed builds and artifacts."
                            .to_string(),
                        affected_endpoints: vec![],
                        evidence_items: vec![],
                        references: vec![],
                        cwe: "CWE-200".to_string(),
                    });
                    break;
                }
            }
        }
    }

    for entry in WalkDir::new(root)
        .follow_links(false)
        .max_depth(20)
        .into_iter()
        .filter_entry(|e| !is_excluded(e.path()))
        .filter_map(|e| e.ok())
    {
        let p = entry.path();
        if !p.is_file() {
            continue;
        }

        let meta = match fs::metadata(p) {
            Ok(m) => m,
            Err(_) => continue,
        };
        if meta.len() > MAX_FILE_SIZE_BYTES {
            continue;
        }

        let ext = p.extension().and_then(|e| e.to_str()).unwrap_or("");
        let is_text = matches!(
            ext,
            "js" | "ts"
                | "jsx"
                | "tsx"
                | "py"
                | "rb"
                | "go"
                | "java"
                | "kt"
                | "json"
                | "yaml"
                | "yml"
                | "toml"
                | "env"
                | "properties"
                | "cfg"
                | "ini"
                | "tf"
                | "dockerfile"
                | "Dockerfile"
                | "graphql"
                | "gql"
                | "html"
                | "vue"
                | "svelte"
                | "php"
                | "cs"
                | "rs"
                | "sh"
        ) || p
            .file_name()
            .map(|n| n.to_string_lossy().starts_with('.'))
            .unwrap_or(false);

        if !is_text {
            continue;
        }

        let content = match fs::read_to_string(p) {
            Ok(c) => c,
            Err(_) => continue,
        };

        files_scanned += 1;
        let rel_path = p.strip_prefix(root).unwrap_or(p).to_string_lossy();

        // Secrets scan
        for (rule_id, re, severity) in &secret_regexes {
            for cap in re.captures_iter(&content) {
                let matched = cap
                    .get(1)
                    .map(|m| m.as_str())
                    .unwrap_or_else(|| cap.get(0).map(|m| m.as_str()).unwrap_or(""));
                let confidence = if matched.len() > 20 && shannon_entropy(matched) > 4.0 {
                    Confidence::Firm
                } else {
                    Confidence::Tentative
                };
                vulnerabilities.push(Vulnerability {
                    id: format!("folder-secret-{}-{}", rule_id, files_scanned),
                    rule_id: (*rule_id).to_string(),
                    fingerprint: format!(
                        "{}:{}",
                        rel_path,
                        cap.get(0).map(|m| m.as_str()).unwrap_or("")
                    ),
                    title: format!("Potential secret: {}", rule_id.replace('_', " ")),
                    description: format!("Possible {} detected in {}", rule_id, rel_path),
                    severity: severity.clone(),
                    confidence,
                    category: "secret-exposure".to_string(),
                    location: format!("file://{}", rel_path),
                    evidence: "[REDACTED]".to_string(),
                    impact: "Secret may be exposed in source control or build artifacts."
                        .to_string(),
                    remediation:
                        "Remove the secret and use environment variables or a secrets manager."
                            .to_string(),
                    affected_endpoints: vec![],
                    evidence_items: vec![],
                    references: vec![],
                    cwe: "CWE-798".to_string(),
                });
            }
        }

        // Code smell scan (one finding per rule per file)
        let file_name = p.file_name().and_then(|n| n.to_str()).unwrap_or("");
        if !is_lockfile(file_name) {
            let mut seen_smells: HashSet<&str> = HashSet::new();
            for (rule_id, re, severity, cwe) in &smell_regexes {
                if seen_smells.contains(rule_id) {
                    continue;
                }
                if let Some(allowed_exts) = smell_extensions(rule_id) {
                    if !allowed_exts.contains(&ext) {
                        continue;
                    }
                }
                let Some(cap) = re.captures(&content) else {
                    continue;
                };
                let evidence = cap.get(0).map(|m| m.as_str()).unwrap_or("");

                // Plain-HTTP rule: skip localhost / private-network targets
                if *rule_id == "folder-plain-http" {
                    let host = evidence
                        .strip_prefix("http://")
                        .and_then(|rest| rest.split(['/', '?', '#']).next())
                        .unwrap_or("");
                    let host_lower = host.to_lowercase();
                    let private = [
                        "localhost",
                        "127.0.0.1",
                        "0.0.0.0",
                        "192.168.",
                        "10.",
                        "169.254.",
                    ]
                    .iter()
                    .any(|prefix| host_lower.starts_with(prefix));
                    if private {
                        continue;
                    }
                }

                seen_smells.insert(rule_id);
                let (title, description, impact, remediation) = match *rule_id {
                    "folder-weak-crypto" => (
                        "Weak Hash Function Usage",
                        format!("Weak hash (md5/sha1) usage found in {}", rel_path),
                        "Weak hashes are vulnerable to collision and preimage attacks when used for security purposes.",
                        "Use a strong hash (SHA-256 or better) or a keyed digest (HMAC).",
                    ),
                    "folder-insecure-random" => (
                        "Insecure Pseudo-Random Usage",
                        format!("Non-cryptographic random source found in {}", rel_path),
                        "Pseudo-random values are predictable and unsafe for tokens, passwords, or nonces.",
                        "Use a CSPRNG (e.g., crypto.getRandomValues, secure_random).",
                    ),
                    "folder-xss-sink" => (
                        "Client-Side XSS Sink",
                        format!("DOM injection sink (innerHTML/eval/dangerouslySetInnerHTML) in {}", rel_path),
                        "Direct DOM insertion can execute attacker-controlled markup as script.",
                        "Prefer textContent or escape untrusted values before insertion.",
                    ),
                    "folder-plain-http" => (
                        "Unencrypted http:// URL in Source",
                        format!("Plain HTTP URL referenced in {}", rel_path),
                        "Data sent over plain HTTP can be observed or modified in transit.",
                        "Use HTTPS endpoints for any request that carries sensitive data.",
                    ),
                    _ => (
                        "Security-Related TODO Comment",
                        format!("Security-related TODO/FIXME comment in {}", rel_path),
                        "Unresolved security TODOs indicate known or suspected gaps.",
                        "Track the item to closure or convert it into an issue.",
                    ),
                };
                let snippet: String = evidence.chars().take(80).collect();
                vulnerabilities.push(Vulnerability {
                    id: format!("{}-{}", rule_id, files_scanned),
                    rule_id: (*rule_id).to_string(),
                    fingerprint: format!("{}:{}", rel_path, rule_id),
                    title: title.to_string(),
                    description: description.to_string(),
                    severity: severity.clone(),
                    confidence: Confidence::Tentative,
                    category: "code-quality".to_string(),
                    location: format!("file://{}", rel_path),
                    evidence: format!("{}…", snippet.trim()),
                    impact: impact.to_string(),
                    remediation: remediation.to_string(),
                    affected_endpoints: vec![],
                    evidence_items: vec![],
                    references: vec![],
                    cwe: (*cwe).to_string(),
                });
            }
        }

        // .env files: extract KEY=VALUE entries as data exposure
        if file_name.starts_with(".env") || file_name.ends_with(".env") {
            for line in content.lines() {
                let line = line.trim().trim_start_matches("export ").trim();
                if line.is_empty() || line.starts_with('#') || !line.contains('=') {
                    continue;
                }
                let (key, value) = line.split_once('=').unwrap_or_default();
                let key = key.trim();
                let value = value.trim().trim_matches(|c| c == '"' || c == '\'');
                if key.is_empty() || value.is_empty() {
                    continue;
                }
                let lower_key = key.to_lowercase();
                let sensitive = [
                    "secret",
                    "key",
                    "token",
                    "pass",
                    "credential",
                    "jwt",
                    "signing",
                ]
                .iter()
                .any(|needle| lower_key.contains(needle));
                data_exposures.push(DataExposure {
                    fingerprint: format!("{}:{}", rel_path, key),
                    field: key.to_string(),
                    data_type: "env-value".to_string(),
                    location: format!("file://{}", rel_path),
                    severity: if sensitive {
                        Severity::High
                    } else {
                        Severity::Medium
                    },
                    confidence: Confidence::Firm,
                    matched_value: redact_value(value),
                });
            }
        }

        // Config exposure (by filename)
        let path_str = p.to_string_lossy().replace('\\', "/");
        for (rule_id, re, severity) in &config_regexes {
            if re.is_match(&path_str) {
                data_exposures.push(DataExposure {
                    fingerprint: format!("{}:{}", rel_path, rule_id),
                    field: rule_id.to_string(),
                    data_type: "config-file".to_string(),
                    location: format!("file://{}", rel_path),
                    severity: severity.clone(),
                    confidence: Confidence::Firm,
                    matched_value: "[REDACTED]".to_string(),
                });
            }
        }

        // Endpoint inventory
        for (source, re) in &endpoint_regexes {
            for cap in re.captures_iter(&content) {
                let endpoint = cap
                    .get(1)
                    .map(|m| m.as_str())
                    .unwrap_or_else(|| cap.get(0).map(|m| m.as_str()).unwrap_or(""));
                let ep = endpoint.trim().to_string();
                if !ep.is_empty() && ep.len() < 500 && !seen_endpoints.contains(&ep) {
                    let display = if ep.starts_with("http") {
                        ep.clone()
                    } else {
                        format!("/{}", ep.trim_start_matches('/'))
                    };
                    seen_endpoints.insert(ep.clone());
                    api_exposures.push(ApiExposure {
                        fingerprint: format!("{}:{}", rel_path, ep),
                        endpoint: display,
                        method: "GET".to_string(),
                        description: format!("Endpoint extracted from {} in {}", source, rel_path),
                        severity: Severity::Info,
                    });
                }
            }
        }
    }

    let critical = vulnerabilities
        .iter()
        .filter(|v| matches!(v.severity, Severity::Critical))
        .count();
    let high = vulnerabilities
        .iter()
        .filter(|v| matches!(v.severity, Severity::High))
        .count();
    let medium = vulnerabilities
        .iter()
        .filter(|v| matches!(v.severity, Severity::Medium))
        .count();
    let low = vulnerabilities
        .iter()
        .filter(|v| matches!(v.severity, Severity::Low))
        .count();
    let info_count = vulnerabilities
        .iter()
        .filter(|v| matches!(v.severity, Severity::Info))
        .count()
        + api_exposures.len()
        + data_exposures.len();

    let security_score = 100i32
        - (critical as i32 * 15)
        - (high as i32 * 10)
        - (medium as i32 * 5)
        - (low as i32 * 2)
        - (info_count as i32);
    let security_score = security_score.clamp(0, 100) as u32;

    let vuln_len = vulnerabilities.len();
    let api_len = api_exposures.len();
    let data_len = data_exposures.len();
    let duration_ms = start.elapsed().as_millis() as u64;

    info!(
        "Folder scan completed: {} files, {} vulns, {} config, {} endpoints in {}ms",
        files_scanned, vuln_len, data_len, api_len, duration_ms
    );

    Ok(ScanResult {
        url: format!("file://{}", path),
        scan_type: ScanType::Passive,
        vulnerabilities,
        api_exposures,
        data_exposures,
        security_score,
        scan_duration_ms: duration_ms,
        cms_detected: None,
        target_info: None,
        auth_state: Default::default(),
        inventory: vec![],
        metrics: ScanMetrics {
            request_count: 0,
            endpoint_total: api_len as u32,
            active_candidate_total: 0,
            passive_vulnerability_count: vuln_len as u32,
            active_vulnerability_count: 0,
            api_exposure_count: api_len as u32,
            data_exposure_count: data_len as u32,
            artifact_seed_count: 0,
            authenticated_request_count: 0,
            confirmed_finding_count: 0,
            tentative_finding_count: vuln_len as u32,
        },
    })
}
