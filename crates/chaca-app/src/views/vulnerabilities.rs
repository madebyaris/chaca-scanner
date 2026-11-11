use crate::{
    theme::*,
    views::{badge, button, detail, label, muted, panel, sub_panel},
    Chaca, PAGE_SIZE,
};
use chaca_core::Severity;
use gpui::{div, prelude::*, px, rgb, Context};

impl Chaca {
    /// The findings report.
    ///
    /// Only the first `findings_limit` rows are built, and the detail block of a
    /// row is constructed only while that row is expanded. Without both limits
    /// a large report would clone every string of every finding on every frame.
    pub fn findings(&self, cx: &mut Context<Self>) -> impl IntoElement {
        let Some(result) = &self.result else {
            return panel("No scan results")
                .child(muted("Start a scan to inspect findings."))
                .into_any_element();
        };
        let matching = result
            .vulnerabilities
            .iter()
            .enumerate()
            .filter(|(_, finding)| {
                self.severity
                    .as_ref()
                    .is_none_or(|severity| *severity == finding.severity)
            })
            .count();
        let limit = self.findings_limit.min(matching);
        let visible = result
            .vulnerabilities
            .iter()
            .enumerate()
            .filter(|(_, finding)| {
                self.severity
                    .as_ref()
                    .is_none_or(|severity| *severity == finding.severity)
            })
            .take(limit)
            .collect::<Vec<_>>();

        div()
            .flex()
            .flex_col()
            .gap_3()
            .child(
                panel("Full report")
                    .child(result.url.clone())
                    .child(self.export_actions(cx))
                    .child(muted(format!(
                        "Showing {} of {} vulnerabilities. Click a finding to inspect its evidence.",
                        visible.len(),
                        matching
                    )))
                    .child(
                        div().flex().flex_wrap().gap_2().children(
                            [None, Some(Severity::Critical), Some(Severity::High), Some(Severity::Medium), Some(Severity::Low), Some(Severity::Info)]
                                .into_iter()
                                .enumerate()
                                .map(|(index, severity)| {
                                    let text = severity
                                        .as_ref()
                                        .map(|severity| severity_label(severity).to_owned())
                                        .unwrap_or_else(|| "ALL".to_owned());
                                    button(("filter", index), text, self.severity == severity)
                                        .on_click(cx.listener(move |view, _, _, cx| {
                                            view.severity = severity.clone();
                                            // A filter change shows a different set, so
                                            // start again from the first page.
                                            view.findings_limit = PAGE_SIZE;
                                            cx.notify();
                                        }))
                                }),
                        ),
                    ),
            )
            .when(visible.is_empty(), |div| {
                div.child(
                    panel("No findings").child(muted("No vulnerabilities match this filter.")),
                )
            })
            .children(visible.into_iter().map(|(index, finding)| {
                let expanded = self.expanded.contains(&index);
                div()
                    .border_1()
                    .border_color(rgb(LINE))
                    .rounded(px(10.))
                    .bg(rgb(CARD))
                    .child(
                        div()
                            .id(("finding", index))
                            .flex()
                            .flex_col()
                            .gap_2()
                            .p_4()
                            .cursor_pointer()
                            .hover(|div| div.bg(rgb(WASH)))
                            .child(
                                div()
                                    .flex()
                                    .gap_3()
                                    .items_center()
                                    .child(label(if expanded { "−" } else { "+" }))
                                    .child(
                                        badge(
                                            severity_label(&finding.severity),
                                            severity_color(&finding.severity),
                                            severity_bg(&finding.severity),
                                            severity_border(&finding.severity),
                                        ),
                                    )
                                    .child(label(finding.title.clone())),
                            )
                            .child(muted(format!(
                                "{} · {} · {}",
                                finding.confidence.as_str().to_uppercase(),
                                finding.category,
                                finding.location
                            )))
                            .on_click(cx.listener(move |view, _, _, cx| {
                                if !view.expanded.remove(&index) {
                                    view.expanded.insert(index);
                                }
                                cx.notify();
                            })),
                    )
                    // The detail block is only built for a row the reader opened.
                    .when(expanded, |row| {
                        row.child(
                            div()
                                .p_4()
                                .flex()
                                .flex_col()
                                .gap_3()
                                .border_t_1()
                                .border_color(rgb(LINE))
                                .child(detail("DESCRIPTION", finding.description.clone()))
                                .child(detail("EVIDENCE", finding.evidence.clone()))
                                .children(finding.evidence_items.iter().map(|item| {
                                    detail(
                                        &format!("{} · {}", item.kind, item.label),
                                        item.value.clone(),
                                    )
                                }))
                                .child(detail("IMPACT", finding.impact.clone()))
                                .child(detail("REMEDIATION", finding.remediation.clone()))
                                .child(detail(
                                    "AFFECTED ENDPOINTS",
                                    finding.affected_endpoints.join("\n"),
                                ))
                                .child(detail(
                                    "RULE / CWE",
                                    format!("{} / {}", finding.rule_id, finding.cwe),
                                ))
                                .child(detail("REFERENCES", finding.references.join("\n"))),
                        )
                    })
            }))
            .when(matching > self.findings_limit, |div| {
                div.child(
                    sub_panel()
                        .flex()
                        .flex_row()
                        .items_center()
                        .justify_between()
                        .child(muted(format!(
                            "SHOWING {} OF {} FINDINGS",
                            self.findings_limit.min(matching),
                            matching
                        )))
                        .child(
                            button("findings-more", "SHOW MORE →", false).on_click(cx.listener(
                                |view, _, _, cx| {
                                    view.findings_limit = view.findings_limit.saturating_add(PAGE_SIZE);
                                    cx.notify();
                                },
                            )),
                        ),
                )
            })
            .into_any_element()
    }

    /// The API and data exposure lists.
    ///
    /// Both lists are capped the same way the findings list is, so a report
    /// with thousands of exposures does not build thousands of rows at once.
    /// `api` and `data` select which list this page builds.
    pub fn exposures(&self, api: bool, data: bool, cx: &mut Context<Self>) -> impl IntoElement {
        let Some(result) = &self.result else {
            return panel("No scan results")
                .child(muted("Start a scan to inspect exposures."))
                .into_any_element();
        };
        let api_total = result.api_exposures.len();
        let data_total = result.data_exposures.len();
        let api_limit = self.exposures_limit.min(api_total);
        let data_limit = self.exposures_limit.min(data_total);
        let title = match (api, data) {
            (true, false) => "API exposure",
            (false, true) => "Data exposure",
            _ => "API and data exposure",
        };

        div()
            .flex()
            .flex_col()
            .gap_4()
            .child(
                panel(title)
                    .child(result.url.clone())
                    .child(self.export_actions(cx)),
            )
            .when(api, |view| {
                view.child(
                    panel(format!("API EXPOSURES ({api_total})"))
                        .when(api_total == 0, |panel| {
                            panel.child(muted("No API exposures found."))
                        })
                        .children(result.api_exposures.iter().take(api_limit).map(|api| {
                            div()
                                .flex()
                                .flex_col()
                                .gap_2()
                                .py_3()
                                .border_t_1()
                                .border_color(rgb(LINE))
                                .child(
                                    div()
                                        .flex()
                                        .gap_2()
                                        .items_center()
                                        .child(badge(
                                            severity_label(&api.severity),
                                            severity_color(&api.severity),
                                            severity_bg(&api.severity),
                                            severity_border(&api.severity),
                                        ))
                                        .child(label(format!("{} {}", api.method, api.endpoint))),
                                )
                                .child(api.description.clone())
                        })),
                )
                .when(api_total > self.exposures_limit, |div| {
                    div.child(
                        sub_panel()
                            .flex()
                            .flex_row()
                            .items_center()
                            .justify_between()
                            .child(muted(format!(
                                "SHOWING {} OF {} API EXPOSURES",
                                api_limit, api_total
                            )))
                            .child(
                                button("api-more", "SHOW MORE →", false).on_click(cx.listener(
                                    |view, _, _, cx| {
                                        view.exposures_limit =
                                            view.exposures_limit.saturating_add(PAGE_SIZE);
                                        cx.notify();
                                    },
                                )),
                            ),
                    )
                })
            })
            .when(data, |view| {
                view.child(
                    panel(format!("DATA EXPOSURES ({data_total})"))
                        .when(data_total == 0, |panel| {
                            panel.child(muted("No data exposures found."))
                        })
                        .children(result.data_exposures.iter().take(data_limit).map(|data| {
                            div()
                                .flex()
                                .flex_col()
                                .gap_2()
                                .py_3()
                                .border_t_1()
                                .border_color(rgb(LINE))
                                .child(
                                    div()
                                        .flex()
                                        .gap_2()
                                        .items_center()
                                        .child(badge(
                                            severity_label(&data.severity),
                                            severity_color(&data.severity),
                                            severity_bg(&data.severity),
                                            severity_border(&data.severity),
                                        ))
                                        .child(label(format!(
                                            "{} · {}",
                                            data.data_type, data.field
                                        ))),
                                )
                                .child(muted(format!(
                                    "{} · {}",
                                    data.confidence.as_str().to_uppercase(),
                                    data.location
                                )))
                        })),
                )
                .when(data_total > self.exposures_limit, |div| {
                    div.child(
                        sub_panel()
                            .flex()
                            .flex_row()
                            .items_center()
                            .justify_between()
                            .child(muted(format!(
                                "SHOWING {} OF {} DATA EXPOSURES",
                                data_limit, data_total
                            )))
                            .child(button("data-more", "SHOW MORE →", false).on_click(
                                cx.listener(|view, _, _, cx| {
                                    view.exposures_limit =
                                        view.exposures_limit.saturating_add(PAGE_SIZE);
                                    cx.notify();
                                }),
                            )),
                    )
                })
            })
            .into_any_element()
    }
}
