use crate::{CookieInfo, HeaderPair, ScanConfig, TargetInfo};
use base64::Engine;
use std::net::ToSocketAddrs;
use tracing::info;

use super::domain::{HttpMethod, RequestContext, ScanRuntime};

pub async fn collect_target_info(
    url: &str,
    runtime: &ScanRuntime,
    config: &ScanConfig,
) -> TargetInfo {
    let mut info = TargetInfo::default();
    let start = std::time::Instant::now();

    let parsed = match url::Url::parse(url) {
        Ok(u) => u,
        Err(_) => return info,
    };

    let host = parsed.host_str().unwrap_or("").to_string();
    let port = parsed.port_or_known_default().unwrap_or(443);

    // DNS resolution
    info!("Resolving DNS for {}", host);
    if let Ok(addrs) = format!("{}:{}", host, port).to_socket_addrs() {
        let ips: Vec<String> = addrs.map(|a| a.ip().to_string()).collect();
        let unique: Vec<String> = ips
            .into_iter()
            .collect::<std::collections::HashSet<_>>()
            .into_iter()
            .collect();
        info.ip_addresses = unique;
    }

    // Typed DNS records (A/AAAA/CNAME/MX/NS/SOA/TXT) via the local resolver
    if !host.is_empty() && host.parse::<std::net::IpAddr>().is_err() {
        let dns = collect_dns_records(&host).await;
        info.dns_records = dns.records;
        if info.ip_addresses.is_empty() {
            info.ip_addresses = dns.ips;
        }
    }
    if info.dns_records.is_empty() {
        info.dns_records = info
            .ip_addresses
            .iter()
            .map(|ip| format!("A: {ip}"))
            .collect();
    }

    // TLS certificate probe (protocol, issuer, SAN, expiry)
    if parsed.scheme() == "https" {
        let tls_host = host.clone();
        let tls_port = parsed.port().unwrap_or(443);
        let accept_invalid_certs = config.accept_invalid_certs;
        let tls = super::tls_probe::probe(&tls_host, tls_port, accept_invalid_certs).await;
        if let Some(probe) = tls {
            info.tls_protocol = probe.protocol;
            info.tls_issuer = probe.issuer;
            info.tls_san = probe.san;
            info.tls_not_after = probe.not_after;
            info.tls_days_to_expiry = probe.days_to_expiry;
        }
    }

    // Build a no-redirect client to capture redirect chain
    let redir_client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(std::time::Duration::from_secs(15))
        .danger_accept_invalid_certs(config.accept_invalid_certs)
        .build()
        .unwrap_or_else(|_| runtime.client().clone());

    let mut current_url = url.to_string();
    let mut chain = vec![current_url.clone()];
    for _ in 0..10 {
        match RequestContext::from_scan_config(HttpMethod::Get, &current_url, config)
            .into_builder(&redir_client)
            .send()
            .await
        {
            Ok(resp) => {
                if resp.status().is_redirection() {
                    if let Some(loc) = resp.headers().get("location") {
                        if let Ok(loc_str) = loc.to_str() {
                            let next = if loc_str.starts_with("http") {
                                loc_str.to_string()
                            } else if loc_str.starts_with('/') {
                                format!("{}://{}{}", parsed.scheme(), host, loc_str)
                            } else {
                                break;
                            };
                            chain.push(next.clone());
                            current_url = next;
                            continue;
                        }
                    }
                }
                break;
            }
            Err(_) => break,
        }
    }
    if chain.len() > 1 {
        info.redirect_chain = chain;
    }

    // Main request for header analysis
    info!("Collecting target intelligence for {}", url);
    let response = match runtime
        .execute_request(
            RequestContext::from_scan_config(HttpMethod::Get, url, config)
                .with_label("recon")
                .into_builder(runtime.client()),
        )
        .await
    {
        Ok(r) => r,
        Err(_) => {
            info.response_time_ms = start.elapsed().as_millis() as u64;
            return info;
        }
    };

    info.status_code = response.status().as_u16();
    info.http_version = format!("{:?}", response.version());

    let headers = response.headers().clone();

    // Server header
    if let Some(server) = headers.get("server") {
        info.server = server.to_str().unwrap_or("").to_string();
    }

    // X-Powered-By
    if let Some(xpb) = headers.get("x-powered-by") {
        info.powered_by = xpb.to_str().unwrap_or("").to_string();
    }

    // Content-Type
    if let Some(ct) = headers.get("content-type") {
        info.content_type = ct.to_str().unwrap_or("").to_string();
    }

    // All response headers
    for (name, value) in headers.iter() {
        if let Ok(val_str) = value.to_str() {
            info.response_headers.push(HeaderPair {
                key: name.to_string(),
                value: val_str.to_string(),
            });
        }
    }

    // Cookies
    for cookie_header in headers.get_all("set-cookie").iter() {
        if let Ok(cookie_str) = cookie_header.to_str() {
            info.cookies.push(parse_cookie(cookie_str));
        }
    }

    // Technology detection from headers
    detect_technologies_from_headers(&headers, &mut info);

    // CDN / WAF detection
    detect_cdn_waf(&headers, &mut info);

    // OS hint from Server header
    let server_clone = info.server.clone();
    detect_os_hint(&server_clone, &mut info);

    let body = response.text().await.unwrap_or_default();

    // Technology detection from body
    detect_technologies_from_body(&body, &mut info);

    // Meta generator tag
    if let Some(gen) = extract_meta_generator(&body) {
        info.meta_generator = gen;
    }

    // Check well-known files
    info!("Checking well-known files for {}", url);
    let base = url.trim_end_matches('/');

    if let Ok(resp) = runtime
        .execute_request(
            RequestContext::from_scan_config(
                HttpMethod::Get,
                format!("{}/robots.txt", base),
                config,
            )
            .with_label("robots")
            .into_builder(runtime.client()),
        )
        .await
    {
        info.robots_txt_exists = resp.status().is_success();
    }
    if let Ok(resp) = runtime
        .execute_request(
            RequestContext::from_scan_config(
                HttpMethod::Get,
                format!("{}/sitemap.xml", base),
                config,
            )
            .with_label("sitemap")
            .into_builder(runtime.client()),
        )
        .await
    {
        info.sitemap_exists = resp.status().is_success();
    }
    if let Ok(resp) = runtime
        .execute_request(
            RequestContext::from_scan_config(
                HttpMethod::Get,
                format!("{}/.well-known/security.txt", base),
                config,
            )
            .with_label("security_txt")
            .into_builder(runtime.client()),
        )
        .await
    {
        info.security_txt_exists = resp.status().is_success();
    }

    if let Ok(resp) = runtime
        .execute_request(
            RequestContext::from_scan_config(
                HttpMethod::Get,
                format!("{}/favicon.ico", base),
                config,
            )
            .with_label("favicon")
            .into_builder(runtime.client()),
        )
        .await
    {
        if let Ok(bytes) = resp.bytes().await {
            let sample = &bytes[..bytes.len().min(24)];
            info.favicon_hash = format!(
                "{}-{}",
                bytes.len(),
                base64::engine::general_purpose::STANDARD.encode(sample)
            );
        }
    }

    info.response_time_ms = start.elapsed().as_millis() as u64;

    info
}

#[derive(Debug, Clone)]
pub(crate) struct DnsCollection {
    pub records: Vec<String>,
    pub ips: Vec<String>,
}

pub(crate) async fn collect_dns_records(host: &str) -> DnsCollection {
    let host = host.to_string();
    let fut = tokio::task::spawn_blocking(move || blocking_dns_lookup(&host));
    tokio::time::timeout(std::time::Duration::from_secs(20), fut)
        .await
        .ok()
        .and_then(|result| result.ok())
        .unwrap_or(DnsCollection {
            records: Vec::new(),
            ips: Vec::new(),
        })
}

fn blocking_dns_lookup(host: &str) -> DnsCollection {
    use std::time::Duration;
    use trust_dns_resolver::system_conf::read_system_conf;
    use trust_dns_resolver::Resolver;

    let empty = || DnsCollection {
        records: Vec::new(),
        ips: Vec::new(),
    };
    let Ok((config, mut opts)) = read_system_conf() else {
        return empty();
    };
    opts.timeout = Duration::from_secs(2);
    opts.attempts = 2;
    let Ok(resolver) = Resolver::new(config, opts) else {
        return empty();
    };

    let mut records = Vec::new();
    let mut ips = Vec::new();

    if let Ok(a) = resolver.ipv4_lookup(host) {
        for r in a {
            ips.push(r.0.to_string());
            records.push(format!("A: {}", r.0));
        }
    }
    if let Ok(aaaa) = resolver.ipv6_lookup(host) {
        for r in aaaa {
            ips.push(r.0.to_string());
            records.push(format!("AAAA: {}", r.0));
        }
    }
    if let Ok(mx) = resolver.mx_lookup(host) {
        for r in mx.into_iter().take(5) {
            let exchange = r.exchange().to_string().trim_end_matches('.').to_string();
            if exchange.is_empty() {
                continue;
            }
            records.push(format!("MX ({}): {}", r.preference(), exchange));
        }
    }
    if let Ok(ns) = resolver.ns_lookup(host) {
        for r in ns.into_iter().take(4) {
            records.push(format!("NS: {}", r.to_string().trim_end_matches('.')));
        }
    }
    if let Ok(soa) = resolver.soa_lookup(host) {
        if let Some(r) = soa.iter().next() {
            records.push(format!(
                "SOA: {} ({})",
                r.mname().to_string().trim_end_matches('.'),
                r.rname().to_string().trim_end_matches('.')
            ));
        }
    }
    if let Ok(txt) = resolver.txt_lookup(host) {
        for r in txt.into_iter().take(2) {
            let data: Vec<String> = r
                .txt_data()
                .iter()
                .map(|chunk| String::from_utf8_lossy(chunk).into_owned())
                .collect();
            let data = data.join(" ");
            if data.len() > 120 {
                records.push(format!(
                    "TXT: {}…",
                    data.chars().take(120).collect::<String>()
                ));
            } else {
                records.push(format!("TXT: {data}"));
            }
        }
    }
    DnsCollection { records, ips }
}

fn parse_cookie(raw: &str) -> CookieInfo {
    let lower = raw.to_lowercase();
    let parts: Vec<&str> = raw.splitn(2, ';').collect();
    let name_val = parts.first().unwrap_or(&"");
    let name = name_val
        .splitn(2, '=')
        .next()
        .unwrap_or("")
        .trim()
        .to_string();

    let mut cookie = CookieInfo {
        name,
        ..Default::default()
    };

    cookie.secure = lower.contains("secure");
    cookie.http_only = lower.contains("httponly");

    if lower.contains("samesite=strict") {
        cookie.same_site = "Strict".to_string();
    } else if lower.contains("samesite=lax") {
        cookie.same_site = "Lax".to_string();
    } else if lower.contains("samesite=none") {
        cookie.same_site = "None".to_string();
    }

    if let Some(domain_part) = lower.split(';').find(|p| p.trim().starts_with("domain=")) {
        cookie.domain = domain_part
            .trim()
            .strip_prefix("domain=")
            .unwrap_or("")
            .to_string();
    }

    if let Some(path_part) = lower.split(';').find(|p| p.trim().starts_with("path=")) {
        cookie.path = path_part
            .trim()
            .strip_prefix("path=")
            .unwrap_or("")
            .to_string();
    }

    cookie
}

fn detect_technologies_from_headers(headers: &reqwest::header::HeaderMap, info: &mut TargetInfo) {
    if let Some(xpb) = headers.get("x-powered-by") {
        if let Ok(val) = xpb.to_str() {
            let val_lower = val.to_lowercase();
            if val_lower.contains("php") {
                info.language = "PHP".to_string();
                info.technologies.push(format!("PHP ({})", val));
            } else if val_lower.contains("asp.net") {
                info.language = "C# / ASP.NET".to_string();
                info.framework = "ASP.NET".to_string();
                info.technologies.push(format!("ASP.NET ({})", val));
            } else if val_lower.contains("express") {
                info.language = "JavaScript / Node.js".to_string();
                info.framework = "Express.js".to_string();
                info.technologies.push("Express.js".to_string());
            } else if val_lower.contains("next.js") {
                info.framework = "Next.js".to_string();
                info.technologies.push("Next.js".to_string());
            } else {
                info.technologies.push(val.to_string());
            }
        }
    }

    if let Some(server) = headers.get("server") {
        if let Ok(val) = server.to_str() {
            let val_lower = val.to_lowercase();
            if val_lower.contains("nginx") {
                info.technologies.push(format!("Nginx ({})", val));
            } else if val_lower.contains("jetty") {
                info.technologies.push("Jetty".to_string());
            } else if val_lower.contains("coyote") || val_lower.contains("tomcat") {
                info.technologies.push("Tomcat".to_string());
            } else if val_lower.contains("apache") {
                info.technologies.push(format!("Apache ({})", val));
            } else if val_lower.contains("cloudflare") {
                info.technologies.push("Cloudflare".to_string());
            } else if val_lower.contains("vercel") {
                info.technologies.push("Vercel".to_string());
                info.hosting_provider = "Vercel".to_string();
            } else if val_lower.contains("netlify") {
                info.technologies.push("Netlify".to_string());
                info.hosting_provider = "Netlify".to_string();
            } else if val_lower.contains("iis") || val_lower.contains("microsoft") {
                info.technologies.push(format!("Microsoft IIS ({})", val));
            } else if val_lower.contains("gunicorn") {
                info.technologies.push("Gunicorn".to_string());
                info.language = "Python".to_string();
            } else if val_lower.contains("uvicorn") {
                info.technologies.push("Uvicorn".to_string());
                info.language = "Python".to_string();
            } else if val_lower.contains("caddy") {
                info.technologies.push("Caddy".to_string());
            } else if val_lower.contains("litespeed") {
                info.technologies.push(format!("LiteSpeed ({})", val));
            } else if !val.is_empty() {
                info.technologies.push(val.to_string());
            }
        }
    }

    if headers.get("x-drupal-cache").is_some() || headers.get("x-drupal-dynamic-cache").is_some() {
        info.technologies.push("Drupal".to_string());
    }
    if headers.get("x-shopify-stage").is_some() {
        info.technologies.push("Shopify".to_string());
        info.hosting_provider = "Shopify".to_string();
    }
    if headers.get("x-wp-nonce").is_some() || headers.get("x-wp-total").is_some() {
        info.technologies.push("WordPress".to_string());
    }
    if headers.get("x-aspnet-version").is_some() || headers.get("x-aspnetmvc-version").is_some() {
        if !info.technologies.iter().any(|t| t.contains("ASP.NET")) {
            info.technologies.push("ASP.NET".to_string());
        }
    }
    if info
        .cookies
        .iter()
        .any(|cookie| cookie.name.eq_ignore_ascii_case("laravel_session"))
    {
        push_tech(info, "Laravel");
        if info.language.is_empty() {
            info.language = "PHP".to_string();
        }
        if info.framework.is_empty() {
            info.framework = "Laravel".to_string();
        }
    }
    if headers.get("x-application-context").is_some() {
        push_tech(info, "Spring");
        if info.language.is_empty() {
            info.language = "Java".to_string();
        }
        if info.framework.is_empty() {
            info.framework = "Spring".to_string();
        }
    }
    if headers.get("x-debug-token").is_some() || headers.get("x-debug-token-link").is_some() {
        push_tech(info, "Symfony");
        if info.language.is_empty() {
            info.language = "PHP".to_string();
        }
        if info.framework.is_empty() {
            info.framework = "Symfony".to_string();
        }
    }
    // X-Runtime alone is used by more than Rails. Require a Rails session cookie too.
    let rails_cookie = info.cookies.iter().any(|cookie| {
        let name = cookie.name.to_ascii_lowercase();
        (name.ends_with("_session") || name == "_session_id") && !name.contains("laravel")
    });
    if headers.get("x-runtime").is_some() && rails_cookie {
        push_tech(info, "Ruby on Rails");
        if info.language.is_empty() {
            info.language = "Ruby".to_string();
        }
        if info.framework.is_empty() {
            info.framework = "Ruby on Rails".to_string();
        }
    }
}

fn push_tech(info: &mut TargetInfo, name: &str) {
    if !info.technologies.iter().any(|tech| tech == name) {
        info.technologies.push(name.to_string());
    }
}

fn detect_cdn_waf(headers: &reqwest::header::HeaderMap, info: &mut TargetInfo) {
    if headers.get("cf-ray").is_some() || headers.get("cf-cache-status").is_some() {
        info.cdn_provider = "Cloudflare".to_string();
    } else if headers.get("x-amz-cf-id").is_some() || headers.get("x-amz-cf-pop").is_some() {
        info.cdn_provider = "Amazon CloudFront".to_string();
    } else if headers.get("x-cache").is_some() {
        if let Some(via) = headers.get("via") {
            if let Ok(via_str) = via.to_str() {
                let via_lower = via_str.to_lowercase();
                if via_lower.contains("cloudfront") {
                    info.cdn_provider = "Amazon CloudFront".to_string();
                } else if via_lower.contains("varnish") {
                    info.cdn_provider = "Varnish / Fastly".to_string();
                } else if via_lower.contains("akamai") {
                    info.cdn_provider = "Akamai".to_string();
                }
            }
        }
    }
    if headers.get("x-sucuri-id").is_some() {
        info.waf_detected = "Sucuri WAF".to_string();
    } else if headers.get("x-cdn").is_some() {
        if let Some(val) = headers.get("x-cdn") {
            if let Ok(v) = val.to_str() {
                if v.to_lowercase().contains("incapsula") {
                    info.waf_detected = "Imperva Incapsula".to_string();
                }
            }
        }
    }
    if info.cdn_provider == "Cloudflare" && info.waf_detected.is_empty() {
        info.waf_detected = "Cloudflare WAF".to_string();
    }

    // Hosting hints from headers
    if headers.get("x-vercel-id").is_some() || headers.get("x-vercel-cache").is_some() {
        info.hosting_provider = "Vercel".to_string();
    } else if headers.get("x-netlify-request-id").is_some() {
        info.hosting_provider = "Netlify".to_string();
    } else if headers.get("x-amz-request-id").is_some() {
        info.hosting_provider = "AWS".to_string();
    } else if headers.get("x-goog-generation").is_some()
        || headers.get("x-guploader-uploadid").is_some()
    {
        info.hosting_provider = "Google Cloud".to_string();
    } else if headers.get("x-azure-ref").is_some() {
        info.hosting_provider = "Microsoft Azure".to_string();
    } else if headers.get("fly-request-id").is_some() {
        info.hosting_provider = "Fly.io".to_string();
    } else if headers.get("x-render-origin-server").is_some() {
        info.hosting_provider = "Render".to_string();
    }
}

fn detect_os_hint(server: &str, info: &mut TargetInfo) {
    let lower = server.to_lowercase();
    if lower.contains("ubuntu") || lower.contains("debian") {
        info.os_hint = "Linux (Ubuntu/Debian)".to_string();
    } else if lower.contains("centos") || lower.contains("red hat") || lower.contains("rhel") {
        info.os_hint = "Linux (CentOS/RHEL)".to_string();
    } else if lower.contains("win") || lower.contains("iis") {
        info.os_hint = "Windows Server".to_string();
    } else if lower.contains("unix") || lower.contains("freebsd") {
        info.os_hint = "Unix/FreeBSD".to_string();
    }
}

fn detect_technologies_from_body(body: &str, info: &mut TargetInfo) {
    let body_lower = body.to_lowercase();

    // Markers are specific tokens. A bare word such as "react", "spring",
    // "laravel", "remix", or "astro" also appears inside unrelated words.
    let tech_signatures: &[(&str, &str, &str, &str)] = &[
        ("__next", "Next.js", "JavaScript", "Next.js"),
        ("/_next/static", "Next.js", "JavaScript", "Next.js"),
        ("__nuxt", "Nuxt.js", "JavaScript", "Nuxt.js"),
        ("/_nuxt/", "Nuxt.js", "JavaScript", "Nuxt.js"),
        ("__remixcontext", "Remix", "JavaScript", "Remix"),
        ("remix-run", "Remix", "JavaScript", "Remix"),
        ("__svelte", "SvelteKit", "JavaScript", "SvelteKit"),
        ("sveltekit", "SvelteKit", "JavaScript", "SvelteKit"),
        ("astro-island", "Astro", "JavaScript", "Astro"),
        ("data-astro-", "Astro", "JavaScript", "Astro"),
        ("___gatsby", "Gatsby", "JavaScript", "Gatsby"),
        ("ng-version", "Angular", "TypeScript", "Angular"),
        ("angular.min.js", "Angular", "TypeScript", "Angular"),
        ("angular.js", "Angular", "TypeScript", "Angular"),
        ("vue.js", "Vue.js", "JavaScript", "Vue.js"),
        ("__vue__", "Vue.js", "JavaScript", "Vue.js"),
        ("data-reactroot", "React", "JavaScript", "React"),
        ("data-reactid", "React", "JavaScript", "React"),
        ("react-dom", "React", "JavaScript", "React"),
        ("__react", "React", "JavaScript", "React"),
        ("jquery", "jQuery", "", ""),
        ("bootstrap", "Bootstrap", "", ""),
        ("tailwindcss", "Tailwind CSS", "", ""),
        ("wp-content", "WordPress", "PHP", "WordPress"),
        ("wp-includes", "WordPress", "PHP", "WordPress"),
        ("drupal.js", "Drupal", "PHP", "Drupal"),
        ("/media/jui/", "Joomla", "PHP", "Joomla"),
        ("joomla-script-options", "Joomla", "PHP", "Joomla"),
        ("/vendor/laravel", "Laravel", "PHP", "Laravel"),
        ("laravel-vite-plugin", "Laravel", "PHP", "Laravel"),
        ("sf-toolbar", "Symfony", "PHP", "Symfony"),
        ("csrfmiddlewaretoken", "Django", "Python", "Django"),
        ("django.contrib", "Django", "Python", "Django"),
        ("werkzeug", "Flask", "Python", "Flask"),
        ("fastapi", "FastAPI", "Python", "FastAPI"),
        ("starlette", "Starlette", "Python", "Starlette"),
        ("springframework", "Spring", "Java", "Spring"),
        ("whitelabel error page", "Spring", "Java", "Spring"),
        ("/skin/frontend/", "Magento", "PHP", "Magento"),
        ("mage.cookies", "Magento", "PHP", "Magento"),
        ("text/x-magento-init", "Magento", "PHP", "Magento"),
        ("/static/version", "Magento", "PHP", "Magento"),
    ];

    for (pattern, tech_name, lang, fw) in tech_signatures {
        if body_lower.contains(pattern) {
            push_tech(info, tech_name);
            if !lang.is_empty() && info.language.is_empty() {
                info.language = lang.to_string();
            }
            if !fw.is_empty() && info.framework.is_empty() {
                info.framework = fw.to_string();
            }
        }
    }

    // Google Analytics / Tag Manager
    if body_lower.contains("google-analytics")
        || body_lower.contains("gtag(")
        || body_lower.contains("ga(")
    {
        info.technologies.push("Google Analytics".to_string());
    }
    if body_lower.contains("googletagmanager") {
        info.technologies.push("Google Tag Manager".to_string());
    }
    if body_lower.contains("hotjar") {
        info.technologies.push("Hotjar".to_string());
    }
    if body_lower.contains("sentry") {
        info.technologies.push("Sentry".to_string());
    }

    // Dedup technologies
    info.technologies.sort();
    info.technologies.dedup();
}

fn extract_meta_generator(body: &str) -> Option<String> {
    let lower = body.to_lowercase();
    if let Some(pos) = lower.find("name=\"generator\"") {
        let slice = &body[pos..];
        if let Some(content_pos) = slice.to_lowercase().find("content=\"") {
            let after = &slice[content_pos + 9..];
            if let Some(end) = after.find('"') {
                return Some(after[..end].to_string());
            }
        }
    }
    if let Some(pos) = lower.find("name='generator'") {
        let slice = &body[pos..];
        if let Some(content_pos) = slice.to_lowercase().find("content='") {
            let after = &slice[content_pos + 9..];
            if let Some(end) = after.find('\'') {
                return Some(after[..end].to_string());
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{CookieInfo, TargetInfo};
    use reqwest::header::{HeaderMap, HeaderValue};

    fn techs(body: &str) -> Vec<String> {
        let mut info = TargetInfo::default();
        detect_technologies_from_body(body, &mut info);
        info.technologies
    }

    #[test]
    fn body_words_do_not_identify_a_framework() {
        assert!(
            !techs("This reaction is an offspring of a remix about astronomy.")
                .contains(&"React".to_string())
        );
        assert!(
            !techs("This reaction is an offspring of a remix about astronomy.")
                .contains(&"Spring".to_string())
        );
        assert!(
            !techs("This reaction is an offspring of a remix about astronomy.")
                .contains(&"Remix".to_string())
        );
        assert!(
            !techs("This reaction is an offspring of a remix about astronomy.")
                .contains(&"Astro".to_string())
        );
        assert!(!techs("We use laravel and django and flask.").contains(&"Laravel".to_string()));
        assert!(techs(r#"<div id="__NEXT_DATA__"></div>"#).contains(&"Next.js".to_string()));
        assert!(techs(r#"window.__remixContext = {}"#).contains(&"Remix".to_string()));
        assert!(techs(r#"<astro-island></astro-island>"#).contains(&"Astro".to_string()));
        assert!(techs("org.springframework.web").contains(&"Spring".to_string()));
        assert!(
            techs(r#"<script src="/vendor/laravel/framework.js"></script>"#)
                .contains(&"Laravel".to_string())
        );
    }

    #[test]
    fn server_and_cookie_fingerprints_stay_specific() {
        let mut headers = HeaderMap::new();
        headers.insert("server", HeaderValue::from_static("Apache-Coyote/1.1"));
        let mut info = TargetInfo::default();
        detect_technologies_from_headers(&headers, &mut info);
        assert_eq!(info.technologies, vec!["Tomcat".to_string()]);

        let mut headers = HeaderMap::new();
        headers.insert("server", HeaderValue::from_static("Apache/2.4.70 (Unix)"));
        headers.insert("x-runtime", HeaderValue::from_static("0.012"));
        let mut info = TargetInfo::default();
        detect_technologies_from_headers(&headers, &mut info);
        assert!(info.technologies.iter().any(|tech| tech.contains("Apache")));
        assert!(!info.technologies.iter().any(|tech| tech.contains("Rails")));

        let mut headers = HeaderMap::new();
        headers.insert("x-runtime", HeaderValue::from_static("0.012"));
        let mut info = TargetInfo {
            cookies: vec![CookieInfo {
                name: "_app_session".to_string(),
                ..Default::default()
            }],
            ..Default::default()
        };
        detect_technologies_from_headers(&headers, &mut info);
        assert!(info.technologies.iter().any(|tech| tech == "Ruby on Rails"));
    }
}
