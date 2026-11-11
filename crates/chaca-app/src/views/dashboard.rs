use crate::{
    theme::*,
    views::{button, detail, dot_bar, label, muted, panel, stat_cell},
    Chaca, Page,
};
use chaca_core::{Severity, TargetInfo};
use gpui::{div, prelude::*, px, rgb, Context};

/// The score card, mirroring the Tauri `ReportCard` score panel.
fn score_card(score: u32, vulnerabilities: usize) -> impl IntoElement {
    div()
        .flex()
        .flex_col()
        .gap_3()
        .w(px(310.))
        .flex_none()
        .p_5()
        .border_1()
        .border_color(rgb(LINE))
        .rounded(px(12.))
        .bg(rgb(CARD))
        .child(label("Security score"))
        .child(
            div()
                .text_size(px(40.))
                .font_weight(gpui::FontWeight::BOLD)
                .text_color(score_color(score))
                .child(format!("{score}")),
        )
        .child(muted("out of 100"))
        .child(dot_bar(score as f32 / 100.0, 16))
        .child(muted(format!("{vulnerabilities} vulnerabilities observed")))
}

/// One cell of the 2x2 statistics grid.
fn grid_cell(name: &str, value: impl ToString, color: gpui::Rgba) -> impl IntoElement {
    div()
        .w(px(140.))
        .p_4()
        .border_b_1()
        .border_r_1()
        .border_color(rgb(LINE))
        .child(stat_cell(name, value, color))
}

/// The target intelligence panel, restyled with the shared tokens.
fn target_intelligence(info: &TargetInfo) -> impl IntoElement {
    let rows = [
        ("IP ADDRESSES", info.ip_addresses.join(", ")),
        (
            "HTTP",
            format!(
                "{} · {} · {}ms",
                info.status_code, info.http_version, info.response_time_ms
            ),
        ),
        ("SERVER", info.server.clone()),
        (
            "FRAMEWORK / LANGUAGE",
            format!("{} / {}", info.framework, info.language),
        ),
        ("TECHNOLOGIES", info.technologies.join(", ")),
        ("TLS ISSUER", info.tls_issuer.clone()),
        ("TLS PROTOCOL", info.tls_protocol.clone()),
        ("TLS EXPIRY", info.tls_not_after.clone()),
        ("TLS SAN", info.tls_san.join(", ")),
        (
            "CDN / WAF",
            format!("{} / {}", info.cdn_provider, info.waf_detected),
        ),
        ("HOSTING", info.hosting_provider.clone()),
        ("DNS", info.dns_records.join(", ")),
        ("REDIRECT CHAIN", info.redirect_chain.join(" → ")),
        (
            "SECURITY POSTURE",
            format!(
                "robots.txt: {} · sitemap: {} · security.txt: {}",
                info.robots_txt_exists, info.sitemap_exists, info.security_txt_exists
            ),
        ),
    ];
    panel("Target intelligence")
        .children(
            rows.into_iter()
                .filter(|(_, value)| !value.is_empty())
                .map(|(name, value)| detail(name, value)),
        )
        .when(!info.cookies.is_empty(), |panel| {
            panel
                .child(label("COOKIES"))
                .children(info.cookies.iter().map(|cookie| {
                    muted(format!(
                        "{} · Secure: {} · HttpOnly: {} · SameSite: {}",
                        cookie.name, cookie.secure, cookie.http_only, cookie.same_site
                    ))
                }))
        })
        .when(!info.response_headers.is_empty(), |panel| {
            panel.child(label("RESPONSE HEADERS")).children(
                info.response_headers
                    .iter()
                    .map(|header| muted(format!("{}: {}", header.key, header.value))),
            )
        })
}

impl Chaca {
    /// The scan dashboard.
    ///
    /// The layout mirrors the Tauri dashboard: the score card beside a
    /// 2x2 statistics grid, severity counts, metrics and target intelligence.
    pub fn dashboard(&self, cx: &mut Context<Self>) -> impl IntoElement {
        let Some(result) = self.result.as_ref() else {
            return panel("No scan results")
                .child(muted("Start a scan to see your security dashboard."))
                .into_any_element();
        };
        let metrics = &result.metrics;
        let duration = result.scan_duration_ms;
        let duration_text = if duration >= 1000 {
            format!("{:.1}s", duration as f64 / 1000.)
        } else {
            format!("{duration}ms")
        };
        let worst = result
            .vulnerabilities
            .iter()
            .map(|finding| finding.severity.clone())
            .min_by_key(|severity| match severity {
                Severity::Critical => 0,
                Severity::High => 1,
                Severity::Medium => 2,
                Severity::Low => 3,
                Severity::Info => 4,
            });
        let vuln_color = match &worst {
            Some(severity) => severity_color(severity),
            None => rgb(GREEN),
        };

        div()
            .flex()
            .flex_col()
            .gap_4()
            // The score card and the statistics grid sit side by side, the way
            // the Tauri dashboard lays them out.
            .child(
                div()
                    .flex()
                    .gap_4()
                    .child(score_card(
                        result.security_score,
                        result.vulnerabilities.len(),
                    ))
                    .child(
                        div()
                            .w(px(280.))
                            .flex_none()
                            .flex()
                            .flex_col()
                            .gap_0()
                            .child(
                                div()
                                    .flex()
                                    .flex_wrap()
                                    .child(grid_cell(
                                        "Vulnerabilities",
                                        result.vulnerabilities.len(),
                                        vuln_color,
                                    ))
                                    .child(grid_cell(
                                        "API Exposures",
                                        result.api_exposures.len(),
                                        rgb(INK),
                                    ))
                                    .child(grid_cell("Endpoints", metrics.endpoint_total, rgb(INK)))
                                    .child(grid_cell("Scan Duration", duration_text, rgb(INK))),
                            )
                            .child(
                                div()
                                    .flex()
                                    .flex_col()
                                    .gap_2()
                                    .p_4()
                                    .rounded(px(12.))
                                    .border_1()
                                    .border_color(rgb(LINE))
                                    .bg(rgb(CARD))
                                    .child(label("Export"))
                                    .child(self.export_actions(cx)),
                            ),
                    ),
            )
            .child(
                panel("Findings by severity")
                    .child(
                        div().flex().flex_wrap().gap_2().children(
                            [
                                Severity::Critical,
                                Severity::High,
                                Severity::Medium,
                                Severity::Low,
                                Severity::Info,
                            ]
                            .into_iter()
                            .enumerate()
                            .map(|(index, severity)| {
                                let count = result
                                    .vulnerabilities
                                    .iter()
                                    .filter(|finding| finding.severity == severity)
                                    .count();
                                button(
                                    ("severity-stat", index),
                                    format!("{}  {}", severity_label(&severity), count),
                                    false,
                                )
                                .text_color(severity_color(&severity))
                                .on_click(cx.listener(
                                    move |view, _, _, cx| {
                                        view.severity = Some(severity.clone());
                                        view.findings_limit = crate::PAGE_SIZE;
                                        view.page = Page::Findings;
                                        cx.notify();
                                    },
                                ))
                            }),
                        ),
                    )
                    .child(button("open-report", "VIEW FULL REPORT →", true).on_click(
                        cx.listener(|view, _, _, cx| {
                            view.page = Page::Findings;
                            cx.notify();
                        }),
                    )),
            )
            .child(
                panel("Scan metrics")
                    .child(
                        div().flex().flex_wrap().gap_6().children(
                            [
                                ("Requests", metrics.request_count.to_string()),
                                (
                                    "Active candidates",
                                    metrics.active_candidate_total.to_string(),
                                ),
                                (
                                    "Passive findings",
                                    metrics.passive_vulnerability_count.to_string(),
                                ),
                                (
                                    "Active findings",
                                    metrics.active_vulnerability_count.to_string(),
                                ),
                                ("Confirmed", metrics.confirmed_finding_count.to_string()),
                                ("Tentative", metrics.tentative_finding_count.to_string()),
                                ("Artifact seeds", metrics.artifact_seed_count.to_string()),
                                (
                                    "Authenticated requests",
                                    metrics.authenticated_request_count.to_string(),
                                ),
                                ("API exposures", metrics.api_exposure_count.to_string()),
                                ("Data exposures", metrics.data_exposure_count.to_string()),
                                ("Auth status", result.auth_state.status.clone()),
                                ("Auth mode", result.auth_state.mode.clone()),
                            ]
                            .into_iter()
                            .map(|(name, value)| detail(name, value)),
                        ),
                    )
                    .child(muted(result.auth_state.details.clone())),
            )
            .when_some(result.target_info.as_ref(), |section, info| {
                section.child(target_intelligence(info))
            })
            .child(
                panel("Endpoint inventory")
                    .child(muted(format!(
                        "{} discovered endpoints",
                        result.inventory.len()
                    )))
                    .children(result.inventory.iter().map(|endpoint| {
                        muted(format!(
                            "{} {} · {} · {}",
                            endpoint.method,
                            endpoint.url,
                            endpoint.source,
                            endpoint
                                .last_status
                                .map(|status| status.to_string())
                                .unwrap_or_else(|| "Not requested".into())
                        ))
                    })),
            )
            .into_any_element()
    }
}
