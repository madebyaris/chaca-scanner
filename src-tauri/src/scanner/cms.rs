use crate::{CmsType, Confidence, Severity, Vulnerability};
use tracing::info;

pub fn fingerprint_cms(
    headers: &reqwest::header::HeaderMap,
    body: &str,
) -> Option<CmsType> {
    let body_lower = body.to_lowercase();

    // WordPress signals
    if body_lower.contains("/wp-content/")
        || body_lower.contains("/wp-includes/")
        || body_lower.contains("wp-json")
        || body_lower.contains("<meta name=\"generator\" content=\"wordpress")
    {
        return Some(CmsType::WordPress);
    }
    if let Some(link) = headers.get("link") {
        if let Ok(link_str) = link.to_str() {
            if link_str.contains("wp-json") {
                return Some(CmsType::WordPress);
            }
        }
    }
    for cookie in headers.get_all("set-cookie").iter() {
        if let Ok(c) = cookie.to_str() {
            if c.contains("wp-settings") || c.contains("wordpress_logged_in") {
                return Some(CmsType::WordPress);
            }
        }
    }

    // Drupal signals
    if body_lower.contains("drupal.settings")
        || body_lower.contains("/core/misc/drupal.js")
        || body_lower.contains("<meta name=\"generator\" content=\"drupal")
    {
        return Some(CmsType::Drupal);
    }
    for cookie in headers.get_all("set-cookie").iter() {
        if let Ok(c) = cookie.to_str() {
            if c.starts_with("SESS") || c.contains("Drupal") {
                return Some(CmsType::Drupal);
            }
        }
    }

    // Joomla signals
    if body_lower.contains("<meta name=\"generator\" content=\"joomla")
        || body_lower.contains("/administrator/")
        || body_lower.contains("/media/jui/")
    {
        return Some(CmsType::Joomla);
    }

    // Shopify signals
    if body_lower.contains("cdn.shopify.com")
        || body_lower.contains("shopify.theme")
        || body_lower.contains("shopifyanalytics")
    {
        return Some(CmsType::Shopify);
    }

    // Magento signals
    if body_lower.contains("/skin/frontend/")
        || body_lower.contains("mage.cookies")
        || body_lower.contains("magento")
    {
        return Some(CmsType::Magento);
    }

    None
}

pub async fn run_cms_checks(
    cms: &CmsType,
    base_url: &str,
    client: &reqwest::Client,
) -> Vec<Vulnerability> {
    let base = base_url.trim_end_matches('/');
    match cms {
        CmsType::WordPress => check_wordpress(base, client).await,
        CmsType::Drupal => check_drupal(base, client).await,
        CmsType::Joomla => check_joomla(base, client).await,
        _ => Vec::new(),
    }
}

pub async fn run_generic_checks(
    base_url: &str,
    client: &reqwest::Client,
) -> Vec<Vulnerability> {
    let base = base_url.trim_end_matches('/');
    let mut vulns = Vec::new();

    // .git/HEAD exposure
    if let Ok(resp) = client.get(&format!("{}/.git/HEAD", base)).send().await {
        if resp.status().is_success() {
            let body = resp.text().await.unwrap_or_default();
            if body.starts_with("ref:") || body.contains("refs/heads/") {
                vulns.push(Vulnerability {
                    id: "generic-git-exposed".to_string(),
                    title: "Git Repository Exposed".to_string(),
                    description: ".git/HEAD is publicly accessible".to_string(),
                    severity: Severity::Critical,
                    confidence: Confidence::Confirmed,
                    category: "API8:2023 - Security Misconfiguration".to_string(),
                    location: format!("{}/.git/HEAD", base),
                    evidence: format!("Content: {}", &body[..body.len().min(100)]),
                    impact: "Full source code, credentials, and commit history may be downloadable"
                        .to_string(),
                    remediation: "Block access to .git directory in web server configuration"
                        .to_string(),
                    affected_endpoints: vec![format!("{}/.git/HEAD", base)],
                        ..Default::default()
                });
            }
        }
    }

    // .env exposure
    if let Ok(resp) = client.get(&format!("{}/.env", base)).send().await {
        if resp.status().is_success() {
            let body = resp.text().await.unwrap_or_default();
            if body.contains('=') && (body.contains("DB_") || body.contains("APP_") || body.contains("SECRET") || body.contains("KEY")) {
                vulns.push(Vulnerability {
                    id: "generic-env-exposed".to_string(),
                    title: "Environment File Exposed".to_string(),
                    description: ".env file is publicly accessible with configuration data"
                        .to_string(),
                    severity: Severity::Critical,
                    confidence: Confidence::Confirmed,
                    category: "API8:2023 - Security Misconfiguration".to_string(),
                    location: format!("{}/.env", base),
                    evidence: "Environment file contains key=value configuration".to_string(),
                    impact: "Database credentials, API keys, and secrets may be exposed".to_string(),
                    remediation: "Block access to .env files in web server configuration"
                        .to_string(),
                    affected_endpoints: vec![format!("{}/.env", base)],
                        ..Default::default()
                });
            }
        }
    }

    // robots.txt with sensitive paths
    if let Ok(resp) = client.get(&format!("{}/robots.txt", base)).send().await {
        if resp.status().is_success() {
            let body = resp.text().await.unwrap_or_default();
            let sensitive_paths = [
                "/admin", "/backup", "/config", "/database", "/debug",
                "/internal", "/private", "/secret", "/staging",
            ];
            let body_lower = body.to_lowercase();
            let found: Vec<&str> = sensitive_paths
                .iter()
                .filter(|p| body_lower.contains(*p))
                .copied()
                .collect();
            if !found.is_empty() {
                vulns.push(Vulnerability {
                    id: "generic-robots-sensitive".to_string(),
                    title: "Sensitive Paths in robots.txt".to_string(),
                    description: format!(
                        "robots.txt reveals sensitive paths: {}",
                        found.join(", ")
                    ),
                    severity: Severity::Low,
                    confidence: Confidence::Confirmed,
                    category: "API9:2023 - Improper Inventory Management".to_string(),
                    location: format!("{}/robots.txt", base),
                    evidence: format!("Sensitive paths found: {}", found.join(", ")),
                    impact: "Attackers can discover hidden administrative or sensitive endpoints"
                        .to_string(),
                    remediation: "Avoid listing sensitive paths in robots.txt".to_string(),
                    affected_endpoints: vec![format!("{}/robots.txt", base)],
                        ..Default::default()
                });
            }
        }
    }

    vulns
}

async fn check_wordpress(base: &str, client: &reqwest::Client) -> Vec<Vulnerability> {
    let mut vulns = Vec::new();
    info!("Running WordPress-specific checks for: {}", base);

    // wp-config backup exposure
    let config_paths = [
        "wp-config.php.bak",
        "wp-config.php~",
        "wp-config.php.old",
        "wp-config-backup.txt",
        "wp-config.php.save",
    ];
    for path in config_paths {
        if let Ok(resp) = client.get(&format!("{}/{}", base, path)).send().await {
            if resp.status().is_success() {
                let body = resp.text().await.unwrap_or_default();
                if body.contains("DB_NAME") || body.contains("DB_PASSWORD") || body.contains("<?php") {
                    vulns.push(Vulnerability {
                        id: format!("wp-config-{}", path.replace('.', "_")),
                        title: "WordPress Configuration Backup Exposed".to_string(),
                        description: format!("{} is publicly accessible with database credentials", path),
                        severity: Severity::Critical,
                        confidence: Confidence::Confirmed,
                        category: "API8:2023 - Security Misconfiguration".to_string(),
                        location: format!("{}/{}", base, path),
                        evidence: format!("{} contains PHP/database configuration", path),
                        impact: "Database credentials and secret keys are exposed".to_string(),
                        remediation: "Remove backup files from web root; block access to .bak/.old files".to_string(),
                        affected_endpoints: vec![format!("{}/{}", base, path)],
                        ..Default::default()
                    });
                    break;
                }
            }
        }
    }

    // User enumeration via REST API
    if let Ok(resp) = client.get(&format!("{}/wp-json/wp/v2/users", base)).send().await {
        if resp.status().is_success() {
            let body = resp.text().await.unwrap_or_default();
            if body.contains("\"slug\"") && body.contains("\"name\"") {
                vulns.push(Vulnerability {
                    id: "wp-user-enum".to_string(),
                    title: "WordPress User Enumeration via REST API".to_string(),
                    description: "/wp-json/wp/v2/users exposes user information".to_string(),
                    severity: Severity::Medium,
                    confidence: Confidence::Confirmed,
                    category: "API1:2023 - Broken Object Level Authorization".to_string(),
                    location: format!("{}/wp-json/wp/v2/users", base),
                    evidence: "User list with slugs and names returned".to_string(),
                    impact: "Usernames can be used for brute-force attacks".to_string(),
                    remediation: "Disable REST API user endpoint or require authentication".to_string(),
                    affected_endpoints: vec![format!("{}/wp-json/wp/v2/users", base)],
                        ..Default::default()
                });
            }
        }
    }

    // XML-RPC enabled
    if let Ok(resp) = client.get(&format!("{}/xmlrpc.php", base)).send().await {
        if resp.status().is_success() {
            let body = resp.text().await.unwrap_or_default();
            if body.contains("XML-RPC server") || body.contains("xmlrpc") {
                vulns.push(Vulnerability {
                    id: "wp-xmlrpc".to_string(),
                    title: "WordPress XML-RPC Enabled".to_string(),
                    description: "xmlrpc.php is accessible and may allow brute-force attacks".to_string(),
                    severity: Severity::Medium,
                    confidence: Confidence::Confirmed,
                    category: "API2:2023 - Broken Authentication".to_string(),
                    location: format!("{}/xmlrpc.php", base),
                    evidence: "XML-RPC endpoint is active".to_string(),
                    impact: "Enables brute-force via system.multicall and DDoS amplification".to_string(),
                    remediation: "Disable XML-RPC or restrict access via .htaccess/firewall".to_string(),
                    affected_endpoints: vec![format!("{}/xmlrpc.php", base)],
                        ..Default::default()
                });
            }
        }
    }

    // Debug log exposed
    if let Ok(resp) = client.get(&format!("{}/wp-content/debug.log", base)).send().await {
        if resp.status().is_success() {
            let body = resp.text().await.unwrap_or_default();
            if body.contains("PHP") || body.contains("Warning") || body.contains("Error") {
                vulns.push(Vulnerability {
                    id: "wp-debug-log".to_string(),
                    title: "WordPress Debug Log Exposed".to_string(),
                    description: "wp-content/debug.log is publicly accessible".to_string(),
                    severity: Severity::Medium,
                    confidence: Confidence::Confirmed,
                    category: "API8:2023 - Security Misconfiguration".to_string(),
                    location: format!("{}/wp-content/debug.log", base),
                    evidence: "Debug log contains PHP errors and warnings".to_string(),
                    impact: "Internal paths, database queries, and errors may be exposed".to_string(),
                    remediation: "Disable WP_DEBUG_LOG in production or restrict access".to_string(),
                    affected_endpoints: vec![format!("{}/wp-content/debug.log", base)],
                        ..Default::default()
                });
            }
        }
    }

    // Directory listing on uploads
    if let Ok(resp) = client.get(&format!("{}/wp-content/uploads/", base)).send().await {
        if resp.status().is_success() {
            let body = resp.text().await.unwrap_or_default();
            if body.contains("Index of") || body.contains("Directory listing") {
                vulns.push(Vulnerability {
                    id: "wp-uploads-listing".to_string(),
                    title: "WordPress Uploads Directory Listing".to_string(),
                    description: "wp-content/uploads/ allows directory browsing".to_string(),
                    severity: Severity::Medium,
                    confidence: Confidence::Confirmed,
                    category: "API8:2023 - Security Misconfiguration".to_string(),
                    location: format!("{}/wp-content/uploads/", base),
                    evidence: "Directory listing is enabled".to_string(),
                    impact: "All uploaded files are browsable by anyone".to_string(),
                    remediation: "Disable directory listing in web server configuration".to_string(),
                    affected_endpoints: vec![format!("{}/wp-content/uploads/", base)],
                        ..Default::default()
                });
            }
        }
    }

    // Version disclosure via readme.html
    if let Ok(resp) = client.get(&format!("{}/readme.html", base)).send().await {
        if resp.status().is_success() {
            let body = resp.text().await.unwrap_or_default();
            if body.to_lowercase().contains("wordpress") {
                vulns.push(Vulnerability {
                    id: "wp-readme".to_string(),
                    title: "WordPress Version Disclosure".to_string(),
                    description: "readme.html reveals WordPress installation".to_string(),
                    severity: Severity::Low,
                    confidence: Confidence::Confirmed,
                    category: "API9:2023 - Improper Inventory Management".to_string(),
                    location: format!("{}/readme.html", base),
                    evidence: "WordPress readme.html is accessible".to_string(),
                    impact: "WordPress version may help attackers target known vulnerabilities".to_string(),
                    remediation: "Remove readme.html from production".to_string(),
                    affected_endpoints: vec![format!("{}/readme.html", base)],
                        ..Default::default()
                });
            }
        }
    }

    vulns
}

async fn check_drupal(base: &str, client: &reqwest::Client) -> Vec<Vulnerability> {
    let mut vulns = Vec::new();
    info!("Running Drupal-specific checks for: {}", base);

    // CHANGELOG.txt version disclosure
    let changelog_paths = ["CHANGELOG.txt", "core/CHANGELOG.txt"];
    for path in changelog_paths {
        if let Ok(resp) = client.get(&format!("{}/{}", base, path)).send().await {
            if resp.status().is_success() {
                let body = resp.text().await.unwrap_or_default();
                if body.contains("Drupal") {
                    vulns.push(Vulnerability {
                        id: format!("drupal-changelog-{}", path.replace('/', "_")),
                        title: "Drupal Version Disclosure".to_string(),
                        description: format!("{} reveals Drupal version", path),
                        severity: Severity::Low,
                        confidence: Confidence::Confirmed,
                        category: "API9:2023 - Improper Inventory Management".to_string(),
                        location: format!("{}/{}", base, path),
                        evidence: format!("{} contains Drupal changelog", path),
                        impact: "Drupal version helps attackers target known CVEs".to_string(),
                        remediation: "Remove CHANGELOG.txt from production".to_string(),
                        affected_endpoints: vec![format!("{}/{}", base, path)],
                        ..Default::default()
                    });
                    break;
                }
            }
        }
    }

    // update.php exposed
    if let Ok(resp) = client.get(&format!("{}/update.php", base)).send().await {
        if resp.status().is_success() {
            vulns.push(Vulnerability {
                id: "drupal-update-php".to_string(),
                title: "Drupal update.php Exposed".to_string(),
                description: "update.php is publicly accessible".to_string(),
                severity: Severity::Medium,
                confidence: Confidence::Confirmed,
                category: "API8:2023 - Security Misconfiguration".to_string(),
                location: format!("{}/update.php", base),
                evidence: "update.php returned 200 OK".to_string(),
                impact: "May reveal version info or allow unauthorized updates".to_string(),
                remediation: "Restrict access to update.php via web server rules".to_string(),
                affected_endpoints: vec![format!("{}/update.php", base)],
                        ..Default::default()
            });
        }
    }

    vulns
}

async fn check_joomla(base: &str, client: &reqwest::Client) -> Vec<Vulnerability> {
    let mut vulns = Vec::new();
    info!("Running Joomla-specific checks for: {}", base);

    // configuration.php backup
    let config_paths = [
        "configuration.php.bak",
        "configuration.php.old",
        "configuration.php~",
    ];
    for path in config_paths {
        if let Ok(resp) = client.get(&format!("{}/{}", base, path)).send().await {
            if resp.status().is_success() {
                let body = resp.text().await.unwrap_or_default();
                if body.contains("JConfig") || body.contains("$host") || body.contains("<?php") {
                    vulns.push(Vulnerability {
                        id: format!("joomla-config-{}", path.replace('.', "_")),
                        title: "Joomla Configuration Backup Exposed".to_string(),
                        description: format!("{} is publicly accessible", path),
                        severity: Severity::Critical,
                        confidence: Confidence::Confirmed,
                        category: "API8:2023 - Security Misconfiguration".to_string(),
                        location: format!("{}/{}", base, path),
                        evidence: format!("{} contains Joomla configuration", path),
                        impact: "Database credentials and secret keys are exposed".to_string(),
                        remediation: "Remove backup files from web root".to_string(),
                        affected_endpoints: vec![format!("{}/{}", base, path)],
                        ..Default::default()
                    });
                    break;
                }
            }
        }
    }

    // Version disclosure
    if let Ok(resp) = client
        .get(&format!(
            "{}/administrator/manifests/files/joomla.xml",
            base
        ))
        .send()
        .await
    {
        if resp.status().is_success() {
            let body = resp.text().await.unwrap_or_default();
            if body.contains("<version>") {
                vulns.push(Vulnerability {
                    id: "joomla-version".to_string(),
                    title: "Joomla Version Disclosure".to_string(),
                    description: "joomla.xml manifest reveals version".to_string(),
                    severity: Severity::Low,
                    confidence: Confidence::Confirmed,
                    category: "API9:2023 - Improper Inventory Management".to_string(),
                    location: format!(
                        "{}/administrator/manifests/files/joomla.xml",
                        base
                    ),
                    evidence: "Joomla version manifest is accessible".to_string(),
                    impact: "Version helps attackers target known CVEs".to_string(),
                    remediation: "Restrict access to manifest files".to_string(),
                    affected_endpoints: vec![format!(
                        "{}/administrator/manifests/files/joomla.xml",
                        base
                    )],
                        ..Default::default()
                });
            }
        }
    }

    vulns
}
