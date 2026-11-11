//! Curated version advisories.
//!
//! A fingerprint such as `nginx/1.24.0` is compared with published affected
//! ranges. A match becomes a finding that names the advisory and the upgrade.
//! This module does not send payloads.
//!
//! nginx ranges come from <https://nginx.org/en/security_advisories.html>.
//! A version inside a published vulnerable span is still clean when it sits on
//! a branch the same advisory marks fixed, such as `1.30.6` while `1.31.2`
//! is still affected. OpenSSL entries are end-of-life branches from the
//! project's release roadmap, not individual CVEs.

use crate::{Confidence, Severity, TargetInfo, Vulnerability};
use regex::Regex;
use std::cmp::Ordering;
use std::sync::LazyLock;

const NGINX_REFERENCE: &str = "https://nginx.org/en/security_advisories.html";
const OPENSSL_REFERENCE: &str = "https://openssl-library.org/roadmap/";

struct NginxAdvisory {
    id: &'static str,
    title: &'static str,
    severity: Severity,
    /// Inclusive ranges, comma-separated. A single version has no dash.
    vulnerable: &'static str,
    /// Versions marked fixed, each with a trailing `+`.
    fixed: &'static str,
    windows_only: bool,
}

struct OpensslEol {
    id: &'static str,
    series: &'static str,
    from: &'static str,
    below: &'static str,
    ended: &'static str,
}

macro_rules! nginx {
    ($id:literal, $title:literal, $severity:expr, $vulnerable:literal, $fixed:literal) => {
        NginxAdvisory {
            id: $id,
            title: $title,
            severity: $severity,
            vulnerable: $vulnerable,
            fixed: $fixed,
            windows_only: false,
        }
    };
    ($id:literal, $title:literal, $severity:expr, $vulnerable:literal, $fixed:literal, windows) => {
        NginxAdvisory {
            id: $id,
            title: $title,
            severity: $severity,
            vulnerable: $vulnerable,
            fixed: $fixed,
            windows_only: true,
        }
    };
}

/// Advisories listed on nginx.org, newest first. Severity is nginx's own label:
/// major maps to high, minor maps to low.
const NGINX: &[NginxAdvisory] = &[
    nginx!(
        "CVE-2026-15176",
        "Buffer overflow when using alias with rewrite",
        Severity::Medium,
        "0.1.29-1.31.6",
        "1.31.7+, 1.30.6+"
    ),
    nginx!(
        "CVE-2026-93479",
        "Buffer overflow in script evaluation",
        Severity::Medium,
        "1.31.2-1.31.6, 1.30.0-1.30.5",
        "1.31.7+, 1.30.6+"
    ),
    nginx!(
        "CVE-2026-95101",
        "Request body injection in HTTP/3",
        Severity::Medium,
        "1.25.0-1.31.6",
        "1.31.7+, 1.30.6+"
    ),
    nginx!(
        "CVE-2026-97629",
        "Session forgery when using TLS session tickets",
        Severity::Medium,
        "1.23.2-1.31.6",
        "1.31.7+, 1.30.6+"
    ),
    nginx!(
        "CVE-2026-97205",
        "Use-after-free when using asynchronous file I/O (AIO)",
        Severity::Medium,
        "0.8.11-1.31.6",
        "1.31.7+, 1.30.6+"
    ),
    nginx!(
        "CVE-2026-90439",
        "Buffer overflow when using ngx_http_v3_module",
        Severity::Medium,
        "1.29.2-1.31.5",
        "1.31.6+, 1.30.5+"
    ),
    nginx!(
        "CVE-2026-42533",
        "Buffer overflow when using map and regex",
        Severity::High,
        "0.9.6-1.31.2",
        "1.31.3+, 1.30.4+"
    ),
    nginx!(
        "CVE-2026-60005",
        "Memory disclosure when using ngx_http_slice_module",
        Severity::Medium,
        "1.15.8-1.31.2",
        "1.31.3+, 1.30.4+"
    ),
    nginx!(
        "CVE-2026-56434",
        "Use-after-free when using ngx_http_ssi_module",
        Severity::Medium,
        "0.8.11-1.31.2",
        "1.31.3+, 1.30.4+"
    ),
    nginx!(
        "CVE-2026-42530",
        "Use-after-free in HTTP/3",
        Severity::High,
        "1.31.0-1.31.1",
        "1.31.2+"
    ),
    nginx!(
        "CVE-2026-42055",
        "Buffer overflow in the ngx_http_proxy_v2_module and ngx_http_grpc_module",
        Severity::Medium,
        "1.13.10-1.31.1",
        "1.31.2+, 1.30.3+"
    ),
    nginx!(
        "CVE-2026-48142",
        "Buffer overread in the ngx_http_charset_module",
        Severity::Low,
        "0.3.50-1.31.1",
        "1.31.2+, 1.30.3+"
    ),
    nginx!(
        "CVE-2026-9256",
        "Buffer overflow in the ngx_http_rewrite_module",
        Severity::Medium,
        "0.1.17-1.31.0",
        "1.31.1+, 1.30.2+"
    ),
    nginx!(
        "CVE-2026-42926",
        "HTTP/2 request injection in the ngx_http_proxy_module",
        Severity::Medium,
        "1.29.4-1.30.0",
        "1.31.0+, 1.30.1+"
    ),
    nginx!(
        "CVE-2026-42945",
        "Buffer overflow in the ngx_http_rewrite_module",
        Severity::Medium,
        "0.6.27-1.30.0",
        "1.31.0+, 1.30.1+"
    ),
    nginx!(
        "CVE-2026-42946",
        "Buffer overread in the ngx_http_scgi_module and ngx_http_uwsgi_module",
        Severity::Medium,
        "0.8.42-1.30.0",
        "1.31.0+, 1.30.1+"
    ),
    nginx!(
        "CVE-2026-42934",
        "Buffer overread in the ngx_http_charset_module",
        Severity::Low,
        "0.3.50-1.30.0",
        "1.31.0+, 1.30.1+"
    ),
    nginx!(
        "CVE-2026-40460",
        "HTTP/3 address spoofing",
        Severity::Medium,
        "1.25.0-1.30.0",
        "1.31.0+, 1.30.1+"
    ),
    nginx!(
        "CVE-2026-40701",
        "resolver use-after-free in OCSP",
        Severity::Medium,
        "1.19.0-1.30.0",
        "1.31.0+, 1.30.1+"
    ),
    nginx!(
        "CVE-2026-27654",
        "Buffer overflow in ngx_http_dav_module",
        Severity::Medium,
        "0.5.13-1.29.6",
        "1.29.7+, 1.28.3+"
    ),
    nginx!(
        "CVE-2026-27784",
        "Buffer overflow in the ngx_http_mp4_module",
        Severity::Medium,
        "1.1.19-1.29.6",
        "1.29.7+, 1.28.3+"
    ),
    nginx!(
        "CVE-2026-32647",
        "Buffer overflow in the ngx_http_mp4_module",
        Severity::Medium,
        "1.1.19-1.29.6",
        "1.29.7+, 1.28.3+"
    ),
    nginx!(
        "CVE-2026-27651",
        "NULL pointer dereference while using CRAM-MD5 or APOP",
        Severity::Low,
        "0.5.15-1.29.6",
        "1.29.7+, 1.28.3+"
    ),
    nginx!(
        "CVE-2026-28753",
        "Injection in auth_http and XCLIENT",
        Severity::Medium,
        "0.6.27-1.29.6",
        "1.29.7+, 1.28.3+"
    ),
    nginx!(
        "CVE-2026-28755",
        "OCSP result bypass in stream",
        Severity::Medium,
        "1.27.2-1.29.6",
        "1.29.7+, 1.28.3+"
    ),
    nginx!(
        "CVE-2026-1642",
        "SSL upstream injection",
        Severity::Medium,
        "1.3.0-1.29.4",
        "1.29.5+, 1.28.2+"
    ),
    nginx!(
        "CVE-2025-53859",
        "Buffer overread in the ngx_mail_smtp_module",
        Severity::Low,
        "0.7.22-1.29.0",
        "1.29.1+"
    ),
    nginx!(
        "CVE-2025-23419",
        "SSL session reuse vulnerability",
        Severity::Medium,
        "1.11.4-1.27.3",
        "1.27.4+, 1.26.3+"
    ),
    nginx!(
        "CVE-2024-7347",
        "Buffer overread in the ngx_http_mp4_module",
        Severity::Low,
        "1.5.13-1.27.0",
        "1.27.1+, 1.26.2+"
    ),
    nginx!(
        "CVE-2024-32760",
        "Buffer overwrite in HTTP/3",
        Severity::Medium,
        "1.25.0-1.25.5, 1.26.0",
        "1.27.0+, 1.26.1+"
    ),
    nginx!(
        "CVE-2024-31079",
        "Stack overflow and use-after-free in HTTP/3",
        Severity::Medium,
        "1.25.0-1.25.5, 1.26.0",
        "1.27.0+, 1.26.1+"
    ),
    nginx!(
        "CVE-2024-35200",
        "NULL pointer dereference in HTTP/3",
        Severity::Medium,
        "1.25.0-1.25.5, 1.26.0",
        "1.27.0+, 1.26.1+"
    ),
    nginx!(
        "CVE-2024-34161",
        "Memory disclosure in HTTP/3",
        Severity::Medium,
        "1.25.0-1.25.5, 1.26.0",
        "1.27.0+, 1.26.1+"
    ),
    nginx!(
        "CVE-2024-24989",
        "NULL pointer dereference in HTTP/3",
        Severity::High,
        "1.25.3",
        "1.25.4+"
    ),
    nginx!(
        "CVE-2024-24990",
        "Use-after-free in HTTP/3",
        Severity::High,
        "1.25.0-1.25.3",
        "1.25.4+"
    ),
    nginx!(
        "CVE-2022-41741",
        "Memory corruption in the ngx_http_mp4_module",
        Severity::Medium,
        "1.1.3-1.23.1, 1.0.7-1.0.15",
        "1.23.2+, 1.22.1+"
    ),
    nginx!(
        "CVE-2022-41742",
        "Memory disclosure in the ngx_http_mp4_module",
        Severity::Medium,
        "1.1.3-1.23.1, 1.0.7-1.0.15",
        "1.23.2+, 1.22.1+"
    ),
    nginx!(
        "CVE-2021-23017",
        "1-byte memory overwrite in resolver",
        Severity::Medium,
        "0.6.18-1.20.0",
        "1.21.0+, 1.20.1+"
    ),
    nginx!(
        "CVE-2019-9511",
        "Excessive CPU usage in HTTP/2 with small window updates",
        Severity::Medium,
        "1.9.5-1.17.2",
        "1.17.3+, 1.16.1+"
    ),
    nginx!(
        "CVE-2019-9513",
        "Excessive CPU usage in HTTP/2 with priority changes",
        Severity::Low,
        "1.9.5-1.17.2",
        "1.17.3+, 1.16.1+"
    ),
    nginx!(
        "CVE-2019-9516",
        "Excessive memory usage in HTTP/2 with zero length headers",
        Severity::Low,
        "1.9.5-1.17.2",
        "1.17.3+, 1.16.1+"
    ),
    nginx!(
        "CVE-2018-16843",
        "Excessive memory usage in HTTP/2",
        Severity::Low,
        "1.9.5-1.15.5",
        "1.15.6+, 1.14.1+"
    ),
    nginx!(
        "CVE-2018-16844",
        "Excessive CPU usage in HTTP/2",
        Severity::Low,
        "1.9.5-1.15.5",
        "1.15.6+, 1.14.1+"
    ),
    nginx!(
        "CVE-2018-16845",
        "Memory disclosure in the ngx_http_mp4_module",
        Severity::Medium,
        "1.1.3-1.15.5, 1.0.7-1.0.15",
        "1.15.6+, 1.14.1+"
    ),
    nginx!(
        "CVE-2017-7529",
        "Integer overflow in the range filter",
        Severity::Medium,
        "0.5.6-1.13.2",
        "1.13.3+, 1.12.1+"
    ),
    nginx!(
        "CVE-2016-4450",
        "NULL pointer dereference while writing client request body",
        Severity::Medium,
        "1.3.9-1.11.0",
        "1.11.1+, 1.10.1+"
    ),
    nginx!(
        "CVE-2016-0742",
        "Invalid pointer dereference in resolver",
        Severity::Medium,
        "0.6.18-1.9.9",
        "1.9.10+, 1.8.1+"
    ),
    nginx!(
        "CVE-2016-0746",
        "Use-after-free during CNAME response processing in resolver",
        Severity::Medium,
        "0.6.18-1.9.9",
        "1.9.10+, 1.8.1+"
    ),
    nginx!(
        "CVE-2016-0747",
        "Insufficient limits of CNAME resolution in resolver",
        Severity::Medium,
        "0.6.18-1.9.9",
        "1.9.10+, 1.8.1+"
    ),
    nginx!(
        "CVE-2014-3616",
        "SSL session reuse vulnerability",
        Severity::Medium,
        "0.5.6-1.7.4",
        "1.7.5+, 1.6.2+"
    ),
    nginx!(
        "CVE-2014-3556",
        "STARTTLS command injection",
        Severity::Medium,
        "1.5.6-1.7.3",
        "1.7.4+, 1.6.1+"
    ),
    nginx!(
        "CVE-2014-0133",
        "SPDY heap buffer overflow",
        Severity::High,
        "1.3.15-1.5.11",
        "1.5.12+, 1.4.7+"
    ),
    nginx!(
        "CVE-2014-0088",
        "SPDY memory corruption",
        Severity::High,
        "1.5.10",
        "1.5.11+"
    ),
    nginx!(
        "CVE-2013-4547",
        "Request line parsing vulnerability",
        Severity::Medium,
        "0.8.41-1.5.6",
        "1.5.7+, 1.4.4+"
    ),
    nginx!(
        "CVE-2013-2070",
        "Memory disclosure with specially crafted HTTP backend responses",
        Severity::Medium,
        "1.1.4-1.2.8, 1.3.9-1.4.0",
        "1.5.0+, 1.4.1+, 1.2.9+"
    ),
    nginx!(
        "CVE-2013-2028",
        "Stack-based buffer overflow with specially crafted request",
        Severity::High,
        "1.3.9-1.4.0",
        "1.5.0+, 1.4.1+"
    ),
    nginx!(
        "CVE-2011-4963",
        "Vulnerabilities with Windows directory aliases",
        Severity::Medium,
        "0.7.52-1.3.0",
        "1.3.1+, 1.2.1+",
        windows
    ),
    nginx!(
        "CVE-2012-2089",
        "Buffer overflow in the ngx_http_mp4_module",
        Severity::High,
        "1.1.3-1.1.18, 1.0.7-1.0.14",
        "1.1.19+, 1.0.15+"
    ),
    nginx!(
        "CVE-2012-1180",
        "Memory disclosure with specially crafted backend responses",
        Severity::High,
        "0.1.0-1.1.16",
        "1.1.17+, 1.0.14+"
    ),
    nginx!(
        "CVE-2011-4315",
        "Buffer overflow in resolver",
        Severity::Medium,
        "0.6.18-1.1.7",
        "1.1.8+, 1.0.10+"
    ),
    nginx!(
        "CVE-2010-2266",
        "Vulnerabilities with invalid UTF-8 sequence on Windows",
        Severity::High,
        "0.7.52-0.8.40",
        "0.8.41+, 0.7.67+",
        windows
    ),
    nginx!(
        "CVE-2010-2263",
        "Vulnerabilities with Windows file default stream",
        Severity::High,
        "0.7.52-0.8.39",
        "0.8.40+, 0.7.66+",
        windows
    ),
    nginx!(
        "CORE-2010-0121",
        "Vulnerabilities with Windows 8.3 filename pseudonyms",
        Severity::High,
        "0.7.52-0.8.32",
        "0.8.33+, 0.7.65+",
        windows
    ),
    nginx!(
        "CVE-2009-3555",
        "The renegotiation vulnerability in SSL protocol",
        Severity::High,
        "0.1.0-0.8.22",
        "0.8.23+, 0.7.64+"
    ),
    nginx!(
        "CVE-2009-3898",
        "Directory traversal vulnerability",
        Severity::Low,
        "0.1.0-0.8.16",
        "0.8.17+, 0.7.63+"
    ),
    nginx!(
        "CVE-2009-2629",
        "Buffer underflow vulnerability",
        Severity::High,
        "0.1.0-0.8.14",
        "0.8.15+, 0.7.62+, 0.6.39+, 0.5.38+"
    ),
    nginx!(
        "CVE-2009-3896",
        "Null pointer dereference vulnerability",
        Severity::High,
        "0.1.0-0.8.13",
        "0.8.14+, 0.7.62+, 0.6.39+, 0.5.38+"
    ),
];

/// Public support has ended for these series. 3.5, 4.0, and 4.1 stay off the list.
const OPENSSL_EOL: &[OpensslEol] = &[
    OpensslEol {
        id: "openssl-0.9.8-eol",
        series: "0.9.8",
        from: "0.9.8",
        below: "0.9.9",
        ended: "",
    },
    OpensslEol {
        id: "openssl-1.0.0-eol",
        series: "1.0.0",
        from: "1.0.0",
        below: "1.0.1",
        ended: "",
    },
    OpensslEol {
        id: "openssl-1.0.1-eol",
        series: "1.0.1",
        from: "1.0.1",
        below: "1.0.2",
        ended: "",
    },
    OpensslEol {
        id: "openssl-1.0.2-eol",
        series: "1.0.2",
        from: "1.0.2",
        below: "1.0.3",
        ended: "31 December 2019",
    },
    OpensslEol {
        id: "openssl-1.1.0-eol",
        series: "1.1.0",
        from: "1.1.0",
        below: "1.1.1",
        ended: "11 September 2019",
    },
    OpensslEol {
        id: "openssl-1.1.1-eol",
        series: "1.1.1",
        from: "1.1.1",
        below: "1.1.2",
        ended: "11 September 2023",
    },
    OpensslEol {
        id: "openssl-3.0-eol",
        series: "3.0",
        from: "3.0.0",
        below: "3.1.0",
        ended: "7 September 2026",
    },
    OpensslEol {
        id: "openssl-3.1-eol",
        series: "3.1",
        from: "3.1.0",
        below: "3.2.0",
        ended: "14 March 2025",
    },
    OpensslEol {
        id: "openssl-3.2-eol",
        series: "3.2",
        from: "3.2.0",
        below: "3.3.0",
        ended: "23 November 2025",
    },
    OpensslEol {
        id: "openssl-3.3-eol",
        series: "3.3",
        from: "3.3.0",
        below: "3.4.0",
        ended: "9 April 2026",
    },
    OpensslEol {
        id: "openssl-3.4-eol",
        series: "3.4",
        from: "3.4.0",
        below: "3.5.0",
        ended: "22 October 2026",
    },
    OpensslEol {
        id: "openssl-3.6-eol",
        series: "3.6",
        from: "3.6.0",
        below: "3.7.0",
        ended: "1 November 2026",
    },
];

static PRODUCT_VERSION: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)\b(nginx|openssl)[/ ]+v?(\d+(?:\.\d+){1,3})").unwrap());

/// Findings for product versions named on this target.
pub fn match_target(info: &TargetInfo, location: &str) -> Vec<Vulnerability> {
    let mut blobs = Vec::new();
    blobs.push(info.server.clone());
    blobs.push(info.powered_by.clone());
    blobs.push(info.meta_generator.clone());
    blobs.extend(info.technologies.iter().cloned());
    blobs.extend(
        info.response_headers
            .iter()
            .map(|header| header.value.clone()),
    );

    let mut findings = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for blob in blobs {
        let windows = blob.to_ascii_lowercase().contains("win");
        for (product, version) in extract_products(&blob) {
            if product == "nginx" {
                if version_below(&version, "1.30.0") && seen.insert("nginx-unmaintained-branch") {
                    findings.push(unmaintained_nginx(&version, location));
                }
                for advisory in NGINX {
                    if advisory.windows_only && !windows {
                        continue;
                    }
                    if !version_affected(&version, advisory.vulnerable, advisory.fixed) {
                        continue;
                    }
                    if !seen.insert(advisory.id) {
                        continue;
                    }
                    findings.push(nginx_finding(advisory, &version, location));
                }
            } else if product == "openssl" {
                for eol in OPENSSL_EOL {
                    if !version_in_half_open(&version, eol.from, eol.below) {
                        continue;
                    }
                    if !seen.insert(eol.id) {
                        continue;
                    }
                    findings.push(openssl_finding(eol, &version, location));
                }
            }
        }
    }
    findings
}

fn version_affected(version: &str, vulnerable: &str, fixed: &str) -> bool {
    let Some(version) = parse_version(version) else {
        return false;
    };
    let ranges = parse_ranges(vulnerable);
    if !ranges.iter().any(|(from, to)| {
        cmp_version(&version, from) != Ordering::Less
            && cmp_version(&version, to) != Ordering::Greater
    }) {
        return false;
    }
    !covered_by_fix(&version, &parse_fixes(fixed))
}

fn version_below(version: &str, below: &str) -> bool {
    match (parse_version(version), parse_version(below)) {
        (Some(version), Some(below)) => cmp_version(&version, &below) == Ordering::Less,
        _ => false,
    }
}

fn version_in_half_open(version: &str, from: &str, below: &str) -> bool {
    let Some(version) = parse_version(version) else {
        return false;
    };
    let (Some(from), Some(below)) = (parse_version(from), parse_version(below)) else {
        return false;
    };
    cmp_version(&version, &from) != Ordering::Less
        && cmp_version(&version, &below) == Ordering::Less
}

fn covered_by_fix(version: &[u64], fixes: &[Vec<u64>]) -> bool {
    if fixes.is_empty() {
        return false;
    }
    let mut fixes = fixes.to_vec();
    fixes.sort_by(|left, right| cmp_version(left, right));
    let latest = fixes.last().expect("fixes is non-empty");
    if cmp_version(version, latest) != Ordering::Less {
        return true;
    }
    for fix in &fixes[..fixes.len() - 1] {
        if fix.len() < 2 {
            continue;
        }
        let mut ceiling = fix.clone();
        ceiling[1] = ceiling[1].saturating_add(1);
        ceiling.truncate(2);
        if cmp_version(version, fix) != Ordering::Less
            && cmp_version(version, &ceiling) == Ordering::Less
        {
            return true;
        }
    }
    false
}

fn parse_ranges(spec: &str) -> Vec<(Vec<u64>, Vec<u64>)> {
    let mut ranges = Vec::new();
    for part in spec.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        let (from, to) = part.split_once('-').unwrap_or((part, part));
        if let (Some(from), Some(to)) = (parse_version(from.trim()), parse_version(to.trim())) {
            ranges.push((from, to));
        }
    }
    ranges
}

fn parse_fixes(spec: &str) -> Vec<Vec<u64>> {
    spec.split(',')
        .filter_map(|part| {
            let part = part.trim().trim_end_matches('+').trim();
            if part.is_empty() || part.eq_ignore_ascii_case("none") {
                None
            } else {
                parse_version(part)
            }
        })
        .collect()
}

fn nginx_finding(advisory: &NginxAdvisory, version: &str, location: &str) -> Vulnerability {
    let mut references = vec![NGINX_REFERENCE.to_string()];
    if advisory.id.starts_with("CVE-") {
        references.push(format!("https://www.cve.org/CVERecord?id={}", advisory.id));
    }
    Vulnerability {
        id: advisory.id.to_string(),
        rule_id: advisory.id.to_string(),
        title: format!("nginx {}", advisory.title),
        description: format!(
            "Detected nginx {version}. Upstream advisory: {}. Affected: {}. Fixed in: {}.",
            advisory.title, advisory.vulnerable, advisory.fixed
        ),
        severity: advisory.severity.clone(),
        confidence: Confidence::Firm,
        category: "Known vulnerability".to_string(),
        location: location.to_string(),
        evidence: format!("nginx {version}"),
        impact: "The installed version is inside the range nginx published for this advisory."
            .to_string(),
        remediation: format!(
            "Upgrade nginx. Upstream marks these versions fixed: {}.",
            advisory.fixed
        ),
        affected_endpoints: vec![location.to_string()],
        references,
        cwe: cwe_for_title(advisory.title).to_string(),
        ..Default::default()
    }
}

fn unmaintained_nginx(version: &str, location: &str) -> Vulnerability {
    Vulnerability {
        id: "nginx-unmaintained-branch".to_string(),
        rule_id: "nginx-unmaintained-branch".to_string(),
        title: "nginx branch no longer receives upstream fixes".to_string(),
        description: format!(
            "Detected nginx {version}. Current nginx security fixes are published for the 1.30 and 1.31 branches."
        ),
        severity: Severity::Medium,
        confidence: Confidence::Firm,
        category: "Known vulnerability".to_string(),
        location: location.to_string(),
        evidence: format!("nginx {version}"),
        impact: "Flaws fixed only on 1.30 and 1.31 stay unpatched on this install.".to_string(),
        remediation: "Move to nginx 1.30.6 or later, or 1.31.7 or later.".to_string(),
        affected_endpoints: vec![location.to_string()],
        references: vec![NGINX_REFERENCE.to_string()],
        cwe: "CWE-1104".to_string(),
        ..Default::default()
    }
}

fn openssl_finding(eol: &OpensslEol, version: &str, location: &str) -> Vulnerability {
    let ended = if eol.ended.is_empty() {
        "OpenSSL no longer supports this series.".to_string()
    } else {
        format!("Public support ended on {}.", eol.ended)
    };
    Vulnerability {
        id: eol.id.to_string(),
        rule_id: eol.id.to_string(),
        title: format!("OpenSSL {} is end of life", eol.series),
        description: format!("Detected OpenSSL {version}. {ended}"),
        severity: Severity::Medium,
        confidence: Confidence::Firm,
        category: "Known vulnerability".to_string(),
        location: location.to_string(),
        evidence: format!("OpenSSL {version}"),
        impact: "Flaws disclosed after public support ended stay unpatched on this library."
            .to_string(),
        remediation: "Upgrade to OpenSSL 3.5 LTS (public fixes through 8 April 2030) or OpenSSL 4.1 (through 23 November 2027).".to_string(),
        affected_endpoints: vec![location.to_string()],
        references: vec![OPENSSL_REFERENCE.to_string()],
        cwe: "CWE-1104".to_string(),
        ..Default::default()
    }
}

fn cwe_for_title(title: &str) -> &'static str {
    let title = title.to_ascii_lowercase();
    if title.contains("use-after-free") {
        "CWE-416"
    } else if title.contains("null pointer") {
        "CWE-476"
    } else if title.contains("integer overflow") {
        "CWE-190"
    } else if title.contains("stack-based buffer overflow") || title.contains("stack overflow") {
        "CWE-121"
    } else if title.contains("heap buffer") {
        "CWE-122"
    } else if title.contains("overread") || title.contains("underflow") {
        "CWE-125"
    } else if title.contains("buffer overflow")
        || title.contains("buffer overwrite")
        || title.contains("memory overwrite")
    {
        "CWE-787"
    } else if title.contains("memory disclosure") {
        "CWE-200"
    } else if title.contains("directory traversal") {
        "CWE-22"
    } else if title.contains("injection") {
        "CWE-74"
    } else if title.contains("excessive cpu")
        || title.contains("excessive memory")
        || title.contains("insufficient limits")
    {
        "CWE-400"
    } else {
        ""
    }
}

fn extract_products(blob: &str) -> Vec<(String, String)> {
    PRODUCT_VERSION
        .captures_iter(blob)
        .filter_map(|captures| {
            Some((
                captures.get(1)?.as_str().to_ascii_lowercase(),
                captures.get(2)?.as_str().to_string(),
            ))
        })
        .collect()
}

fn parse_version(raw: &str) -> Option<Vec<u64>> {
    let numbers: Vec<u64> = raw
        .split('.')
        .map(|part| part.parse().ok())
        .collect::<Option<_>>()?;
    if numbers.is_empty() {
        None
    } else {
        Some(numbers)
    }
}

fn cmp_version(left: &[u64], right: &[u64]) -> Ordering {
    let len = left.len().max(right.len());
    for index in 0..len {
        let a = left.get(index).copied().unwrap_or(0);
        let b = right.get(index).copied().unwrap_or(0);
        match a.cmp(&b) {
            Ordering::Equal => {}
            other => return other,
        }
    }
    Ordering::Equal
}

#[cfg(test)]
mod tests {
    use super::*;

    fn info_with_server(server: &str) -> TargetInfo {
        TargetInfo {
            server: server.to_string(),
            ..Default::default()
        }
    }

    fn ids(server: &str) -> Vec<String> {
        match_target(&info_with_server(server), "https://example.test/")
            .into_iter()
            .map(|finding| finding.id)
            .collect()
    }

    fn has(server: &str, id: &str) -> bool {
        ids(server).iter().any(|found| found == id)
    }

    #[test]
    fn every_nginx_advisory_parses() {
        for advisory in NGINX {
            assert!(
                !parse_ranges(advisory.vulnerable).is_empty(),
                "{} vulnerable spec did not parse",
                advisory.id
            );
            assert!(
                !parse_fixes(advisory.fixed).is_empty(),
                "{} fixed spec did not parse",
                advisory.id
            );
        }
    }

    #[test]
    fn old_nginx_matches_published_advisories_and_not_the_fixed_release() {
        assert!(has("nginx/1.24.0", "CVE-2026-15176"));
        assert!(has("nginx/1.24.0", "CVE-2026-42945"));
        assert!(has("nginx/1.24.0", "nginx-unmaintained-branch"));

        assert_eq!(ids("nginx/1.30.6"), Vec::<String>::new());
        assert_eq!(ids("nginx/1.31.7"), Vec::<String>::new());

        assert!(has("nginx/1.31.2", "CVE-2026-15176"));
        assert!(!has("nginx/1.31.2", "CVE-2026-42945"));
        assert!(!has("nginx/1.31.2", "nginx-unmaintained-branch"));
        assert!(!has("nginx/1.31.7", "CVE-2026-15176"));
    }

    #[test]
    fn stable_backports_are_not_flagged_when_mainline_still_is() {
        assert!(has("nginx/1.28.0", "CVE-2026-27654"));
        assert!(!has("nginx/1.28.3", "CVE-2026-27654"));
        assert!(has("nginx/1.28.3", "nginx-unmaintained-branch"));

        assert!(has("nginx/1.26.0", "CVE-2024-32760"));
        assert!(!has("nginx/1.26.1", "CVE-2024-32760"));

        assert!(has("nginx/1.30.4", "CVE-2026-90439"));
        assert!(!has("nginx/1.30.6", "CVE-2026-90439"));

        assert!(has("nginx/1.2.8", "CVE-2013-2070"));
        assert!(!has("nginx/1.2.9", "CVE-2013-2070"));
        assert!(has("nginx/1.4.0", "CVE-2013-2070"));
        assert!(!has("nginx/1.4.1", "CVE-2013-2070"));
    }

    #[test]
    fn windows_only_advisories_need_a_windows_fingerprint() {
        assert!(!has("nginx/0.8.20", "CVE-2010-2266"));
        assert!(has("nginx/0.8.20 (Windows)", "CVE-2010-2266"));
        assert!(!has("nginx/0.8.41 (Windows)", "CVE-2010-2266"));
    }

    #[test]
    fn openssl_end_of_life_branches_match() {
        assert!(has("OpenSSL/1.1.1w", "openssl-1.1.1-eol"));
        assert!(has("OpenSSL/3.0.15", "openssl-3.0-eol"));
        assert!(has("OpenSSL/3.4.8", "openssl-3.4-eol"));
        assert!(has("OpenSSL/3.6.1", "openssl-3.6-eol"));
        assert_eq!(ids("OpenSSL/3.5.8"), Vec::<String>::new());
        assert_eq!(ids("OpenSSL/4.0.3"), Vec::<String>::new());
        assert_eq!(ids("OpenSSL/4.1.0"), Vec::<String>::new());
    }
}
