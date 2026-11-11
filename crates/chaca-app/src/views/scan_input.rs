use crate::{
    state::{ScanMode, ScanState},
    theme::*,
    views::{badge, button, dot_bar, label, muted, stat_cell},
    Chaca,
};
use chaca_core::Severity;
use gpui::{div, prelude::*, px, rgb, Context};

/// The coverage rows shown in the scan checklist pane, mirroring the Tauri
/// New Scan checklist.
const CHECKLIST: [(&str, &str); 4] = [
    ("OWASP API Top 10", "API exposure and data leak checks"),
    ("API exposure", "57+ sensitive path probes"),
    ("Data leak check", "Secrets, PII and entropy detection"),
    ("Active + passive", "Injection, auth bypass, SSRF, BOLA"),
];

impl Chaca {
    /// The New Scan screen.
    ///
    /// The layout mirrors the Tauri New Scan panel: a checklist pane on the
    /// left, the target form in the middle and a statistics grid on the right.
    pub fn scan_input(&self, cx: &mut Context<Self>) -> impl IntoElement {
        let busy = self.state.busy();
        let target = self.target.read(cx).value().to_owned();
        let has_target = !target.trim().is_empty();

        div()
            .flex()
            .flex_col()
            .gap_4()
            // Panel header: title, ready badge and the platform/version chips.
            .child(
                div()
                    .flex()
                    .flex_col()
                    .bg(rgb(CARD))
                    .border_1()
                    .border_color(rgb(LINE))
                    .rounded(px(12.))
                    .child(
                        div()
                            .flex()
                            .items_center()
                            .justify_between()
                            .px_5()
                            .py_3()
                            .border_b_1()
                            .border_color(rgb(LINE))
                            .child(
                                div()
                                    .flex()
                                    .items_center()
                                    .gap_3()
                                    .child(label("New scan"))
                                    .child(badge(
                                        if busy { "Scanning" } else { "Ready" },
                                        rgb(CARD),
                                        rgb(GREEN),
                                        rgb(GREEN),
                                    )),
                            )
                            .child(
                                div()
                                    .flex()
                                    .items_center()
                                    .gap_2()
                                    .child(
                                        div()
                                            .px_3()
                                            .py_1()
                                            .rounded(px(999.))
                                            .border_1()
                                            .border_color(rgb(LINE))
                                            .text_size(px(11.))
                                            .text_color(rgb(SUBTLE))
                                            .child("Native"),
                                    )
                                    .child(
                                        div()
                                            .px_3()
                                            .py_1()
                                            .rounded(px(999.))
                                            .border_1()
                                            .border_color(rgb(LINE))
                                            .text_size(px(11.))
                                            .text_color(rgb(SUBTLE))
                                            .child(format!("v{}", env!("CARGO_PKG_VERSION"))),
                                    ),
                            ),
                    )
                    // Panel body: three panes.
                    .child(
                        div()
                            .flex()
                            .flex_wrap()
                            .gap_4()
                            .p_5()
                            // Left pane: the scan checklist.
                            .child(
                                div()
                                    .w(px(280.))
                                    .min_w(px(240.))
                                    .flex_none()
                                    .flex()
                                    .flex_col()
                                    .gap_3()
                                    .child(
                                        div()
                                            .flex()
                                            .items_start()
                                            .justify_between()
                                            .child(
                                                div()
                                                    .flex()
                                                    .flex_col()
                                                    .gap_1()
                                                    .child(label("Scan checklist"))
                                                    .child(muted("Coverage before deployment")),
                                            )
                                            .child(
                                                div()
                                                    .px_3()
                                                    .py_1()
                                                    .rounded(px(999.))
                                                    .border_1()
                                                    .border_color(rgb(LINE))
                                                    .text_size(px(10.))
                                                    .text_color(rgb(SUBTLE))
                                                    .child("OWASP"),
                                            ),
                                    )
                                    .children(CHECKLIST.into_iter().map(|(name, detail)| {
                                        div()
                                            .flex()
                                            .flex_col()
                                            .gap_1()
                                            .child(
                                                div()
                                                    .flex()
                                                    .items_center()
                                                    .gap_3()
                                                    .child(
                                                        div()
                                                            .w(px(118.))
                                                            .flex_none()
                                                            .text_size(px(10.))
                                                            .text_color(rgb(SUBTLE))
                                                            .child(name.to_owned()),
                                                    )
                                                    .child(dot_bar(1.0, 12)),
                                            )
                                            .child(muted(detail.to_owned()))
                                    })),
                            )
                            // Center pane: the target form.
                            .child(
                                div()
                                    .flex_1()
                                    .min_w(px(260.))
                                    .flex()
                                    .flex_col()
                                    .gap_3()
                                    .pl_6()
                                    .border_l_1()
                                    .border_color(rgb(LINE))
                                    .child(
                                        div()
                                            .flex()
                                            .items_start()
                                            .justify_between()
                                            .gap_3()
                                            .child(
                                                div()
                                                    .flex()
                                                    .flex_col()
                                                    .gap_1()
                                                    .child(label("Target"))
                                                    .child(muted("Enter URL and choose scan mode")),
                                            )
                                    )
                                    .child(self.mode_selector(cx, busy))
                                    .child(
                                        div()
                                            .text_size(px(12.))
                                            .text_color(rgb(MUTED))
                                            .child("Target URL"),
                                    )
                                    .child(
                                        div()
                                            .border_1()
                                            .border_color(rgb(LINE))
                                            .rounded(px(8.))
                                            .p_2()
                                            .bg(rgb(CARD))
                                            .when(!busy, |div| div.child(self.target.clone()))
                                            .when(busy, |div| {
                                                div.child(self.target.read(cx).value().to_owned())
                                            }),
                                    )
                                    .child(muted(self.mode.description()))
                                    .child(
                                        div()
                                            .flex()
                                            .gap_2()
                                            .mt_2()
                                            .child(
                                                button(
                                                    "start-scan",
                                                    if busy {
                                                        "Scanning…"
                                                    } else {
                                                        "Start scan"
                                                    },
                                                    true,
                                                )
                                                .when(!busy, |button| {
                                                    button.on_click(cx.listener(
                                                        |view, _, window, cx| {
                                                            window.focus(&view.focus);
                                                            view.start(cx);
                                                        },
                                                    ))
                                                })
                                                .when(busy, |button| button.opacity(0.5)),
                                            )
                                            .child(
                                                button(
                                                    "cancel-scan",
                                                    if self.state.cancelling() {
                                                        "Cancelling…"
                                                    } else {
                                                        "Cancel"
                                                    },
                                                    false,
                                                )
                                                .when(busy && !self.state.cancelling(), |button| {
                                                    button.on_click(cx.listener(
                                                        |view, _, _, cx| view.cancel(cx),
                                                    ))
                                                })
                                                .when(!busy || self.state.cancelling(), |button| {
                                                    button.opacity(0.4)
                                                }),
                                            ),
                                    )
                                    .child(muted(
                                        "Scan only targets you own or have permission to test.",
                                    ))
                                    .when_some(
                                        match &self.state {
                                            ScanState::Error(error) => Some(error.clone()),
                                            _ => None,
                                        },
                                        |row, error| {
                                            row.child(
                                                div()
                                                    .p_3()
                                                    .rounded(px(8.))
                                                    .bg(rgb(CRITICAL_BG))
                                                    .border_1()
                                                    .border_color(rgb(CRITICAL_BORDER))
                                                    .text_size(px(11.))
                                                    .text_color(rgb(CRITICAL))
                                                    .child(error),
                                            )
                                        },
                                    )
                                    .when(matches!(self.state, ScanState::Cancelled), |div| {
                                        div.child(muted("SCAN CANCELLED — ready for a new scan."))
                                    })
                                    .when(busy, |div| div.child(self.progress_view(cx))),
                            )
                            // Right pane: the statistics grid.
                            .child(
                                div()
                                    .w_full()
                                    .flex()
                                    .gap_3()
                                    .child(
                                        div()
                                            .flex_1()
                                            .p_4()
                                            .rounded(px(12.))
                                            .border_1()
                                            .border_color(rgb(LINE))
                                            .bg(rgb(CARD))
                                            .child(stat_cell(
                                                "Target",
                                                if has_target { "1" } else { "0" },
                                                rgb(GREEN),
                                            )),
                                    )
                                    .child(
                                        div()
                                            .flex_1()
                                            .p_4()
                                            .rounded(px(12.))
                                            .border_1()
                                            .border_color(rgb(LINE))
                                            .bg(rgb(CARD))
                                            .child(stat_cell(
                                                "Scan type",
                                                self.mode.label(),
                                                rgb(INK),
                                            )),
                                    )
                                    .child(
                                        div()
                                            .flex_1()
                                            .p_4()
                                            .rounded(px(12.))
                                            .border_1()
                                            .border_color(rgb(LINE))
                                            .bg(rgb(CARD))
                                            .child(stat_cell("Profile", "OWASP", rgb(INK))),
                                    )
                                    .child(
                                        div()
                                            .flex_1()
                                            .p_4()
                                            .rounded(px(12.))
                                            .border_1()
                                            .border_color(rgb(LINE))
                                            .bg(rgb(CARD))
                                            .child(stat_cell("Engine", "Rust", rgb(INK))),
                                    )
                                    .when(self.result.is_some(), |column| {
                                        column.child(
                                            div()
                                                .flex()
                                                .flex_col()
                                                .gap_2()
                                                .mt_4()
                                                .child(label("Last result"))
                                                .child(
                                                    div()
                                                        .flex()
                                                        .flex_col()
                                                        .gap_1()
                                                        .child(muted("Vulnerabilities"))
                                                        .child(
                                                            div()
                                                                .text_size(px(24.))
                                                                .font_weight(
                                                                    gpui::FontWeight::BOLD,
                                                                )
                                                                .text_color(
                                                                    self.result
                                                                        .as_ref()
                                                                        .map(|result| {
                                                                            let worst = result
                                                                                .vulnerabilities
                                                                                .iter()
                                                                                .map(|finding| {
                                                                                    finding.severity.clone()
                                                                                })
                                                                                .min_by_key(|severity| {
                                                                                    match *severity {
                                                                                        Severity::Critical => 0,
                                                                                        Severity::High => 1,
                                                                                        Severity::Medium => 2,
                                                                                        Severity::Low => 3,
                                                                                        Severity::Info => 4,
                                                                                    }
                                                                                });
                                                                            match worst {
                                                                                Some(severity) => {
                                                                                    severity_color(&severity)
                                                                                }
                                                                                None => rgb(GREEN),
                                                                            }
                                                                        })
                                                                        .unwrap_or(rgb(GREEN)),
                                                                )
                                                                .child(
                                                                    self.result
                                                                        .as_ref()
                                                                        .map(|result| {
                                                                            result
                                                                                .vulnerabilities
                                                                                .len()
                                                                                .to_string()
                                                                        })
                                                                        .unwrap_or_default(),
                                                                ),
                                                        ),
                                                ),
                                        )
                                    }),
                            ),
                    ),
            )
            // The quick-start cards.
            .child(self.quick_cards(cx))
            .into_any_element()
    }

    /// The segmented PASSIVE / ACTIVE / FULL SCAN selector.
    fn mode_selector(&self, cx: &mut Context<Self>, busy: bool) -> impl IntoElement {
        div()
            .flex()
            .items_center()
            .gap_1()
            .bg(rgb(WASH))
            .border_1()
            .border_color(rgb(LINE))
            .rounded(px(8.))
            .p(px(2.))
            .children(ScanMode::ALL.into_iter().enumerate().map(|(index, mode)| {
                let selected = mode == self.mode;
                div()
                    .id(("scan-mode", index))
                    .px_2()
                    .py_1()
                    .rounded(px(6.))
                    .text_size(px(12.))
                    .font_weight(if selected {
                        gpui::FontWeight::MEDIUM
                    } else {
                        gpui::FontWeight::NORMAL
                    })
                    .text_color(rgb(if selected { INK } else { MUTED }))
                    .bg(rgb(if selected { CARD } else { WASH }))
                    .cursor_pointer()
                    .when(!busy, |element| {
                        element.on_click(cx.listener(move |view, _, _, cx| {
                            view.mode = mode;
                            cx.notify();
                        }))
                    })
                    .when(busy, |element| element.opacity(0.5))
                    .child(mode.label())
            }))
    }

    /// The four quick-start cards below the panel.
    fn quick_cards(&self, _cx: &mut Context<Self>) -> impl IntoElement {
        let cards = [
            (
                "Last scan",
                "Security baseline",
                "Reuse the previous target",
            ),
            (
                "Quick template",
                "Passive only",
                "Fast headers and exposure checks",
            ),
            (
                "Full template",
                "Active + passive",
                "Comprehensive vulnerability audit",
            ),
            (
                "Scan folder",
                "Local project",
                "Secrets, config and endpoint inventory",
            ),
        ];
        div()
            .flex()
            .gap_4()
            .children(
                cards
                    .into_iter()
                    .enumerate()
                    .map(|(index, (kind, title, detail))| {
                        div()
                            .id(("quick-card", index))
                            .flex_1()
                            .flex()
                            .flex_col()
                            .gap_2()
                            .p_4()
                            .rounded(px(12.))
                            .border_1()
                            .border_color(rgb(LINE))
                            .bg(rgb(CARD))
                            .hover(|card| card.bg(rgb(WASH)))
                            .child(muted(kind.to_owned()))
                            .child(label(title.to_owned()))
                            .child(muted(detail.to_owned()))
                    }),
            )
            .child(div().h(px(4.)))
    }
}
