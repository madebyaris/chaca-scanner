//! Chaca's native desktop shell. No Tauri or webview is used by this binary.
mod input;
mod state;
mod theme;
mod views;

use chaca_core::{
    export::{self, ExportFormat},
    InventorySummaryItem, ScanMetrics, ScanProgress, ScanResult, ScanType, Severity, Vulnerability,
};
use gpui::{
    actions, div, prelude::*, px, rgb, size, App, Application, Bounds, Context, Entity,
    FocusHandle, Focusable, KeyBinding, TitlebarOptions, Window, WindowBounds, WindowOptions,
};
use input::TextInput;
use state::{ScanMode, ScanState, WorkerEvent};
use std::{
    collections::HashSet,
    sync::{mpsc, Arc},
    time::{Duration, Instant},
};
use theme::*;
use views::{button, muted, nav_item};

actions!(chaca, [Quit, StartScan, CancelScan]);

/// How many rows a long list shows before the reader asks for more.
pub const PAGE_SIZE: usize = 50;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Page {
    NewScan,
    Dashboard,
    Findings,
    ApiExposure,
    DataExposure,
    History,
    Settings,
    About,
    Documentation,
}
impl Page {
    fn label(self) -> &'static str {
        match self {
            Self::NewScan => "New scan",
            Self::Dashboard => "Dashboard",
            Self::Findings => "Full report",
            Self::ApiExposure => "API exposure",
            Self::DataExposure => "Data exposure",
            Self::History => "History",
            Self::Settings => "Settings",
            Self::About => "About",
            Self::Documentation => "Documentation",
        }
    }

    fn group(self) -> &'static str {
        match self {
            Self::NewScan | Self::History => "Scan",
            Self::Dashboard | Self::Findings | Self::ApiExposure | Self::DataExposure => "Analyze",
            Self::Settings => "Configure",
            Self::About | Self::Documentation => "Help",
        }
    }
}

/// Which settings sub-view a CONFIGURE nav entry opens. All three entries
/// navigate to the Settings page; the tab records which one was chosen.
#[derive(Clone, Copy, PartialEq, Eq)]
enum SettingsTab {
    Network,
    Owasp,
    Export,
}
impl SettingsTab {
    fn label(self) -> &'static str {
        match self {
            Self::Network => "Scan settings",
            Self::Owasp => "OWASP rules",
            Self::Export => "Export settings",
        }
    }
}

struct HistoryEntry {
    result: Arc<ScanResult>,
    completed: String,
}
struct Chaca {
    focus: FocusHandle,
    target: Entity<TextInput>,
    mode: ScanMode,
    state: ScanState,
    progress: Option<ScanProgress>,
    result: Option<Arc<ScanResult>>,
    history: Vec<HistoryEntry>,
    page: Page,
    settings_tab: SettingsTab,
    severity: Option<Severity>,
    expanded: HashSet<usize>,
    notice: Option<String>,
    exporting: bool,
    /// How many findings the report renders before "show more".
    findings_limit: usize,
    /// How many exposures each exposure list renders before "show more".
    exposures_limit: usize,
}
impl Chaca {
    fn new(cx: &mut Context<Self>) -> Self {
        let mut view = Self {
            focus: cx.focus_handle(),
            target: cx.new(|cx| TextInput::new("https://example.com", cx)),
            mode: ScanMode::Passive,
            state: ScanState::Idle,
            progress: None,
            result: None,
            history: vec![],
            page: Page::NewScan,
            settings_tab: SettingsTab::Network,
            severity: None,
            expanded: HashSet::new(),
            notice: None,
            exporting: false,
            findings_limit: PAGE_SIZE,
            exposures_limit: PAGE_SIZE,
        };
        // `CHACA_BENCH_FINDINGS=N` loads a synthetic report and opens Full Report
        // so resident memory can be sampled without driving the GPUI canvas.
        // `CHACA_BENCH_ALL=1` builds every row, which is the pre-pagination path.
        if let Some((report, show_all)) = bench_report() {
            let rows = report.vulnerabilities.len();
            view.result = Some(Arc::new(report));
            view.state = ScanState::Done;
            view.page = Page::Findings;
            if show_all {
                view.findings_limit = rows;
                view.exposures_limit = rows;
                // Expanded rows are what used to be built for every finding.
                view.expanded = (0..rows).collect();
            }
        }
        view
    }

    fn start(&mut self, cx: &mut Context<Self>) {
        if self.state.busy() {
            return;
        }
        let url = match normalize_url(self.target.read(cx).value()) {
            Ok(url) => url,
            Err(error) => {
                self.state = ScanState::Error(error);
                cx.notify();
                return;
            }
        };
        self.target
            .update(cx, |target, cx| target.set_value(url.clone(), cx));
        match state::launch_scan(state::request(url, self.mode)) {
            Ok(receiver) => {
                self.state = ScanState::Scanning {
                    started: Instant::now(),
                    cancelling: false,
                };
                self.progress = None;
                self.notice = None;
                self.page = Page::NewScan;
                // Keep all entity mutations on GPUI's foreground executor. Its timer
                // yields between drains, so neither rendering nor typing is blocked.
                let timer = cx.background_executor().clone();
                cx.spawn(async move |this, cx| loop {
                    timer.timer(Duration::from_millis(50)).await;
                    let keep_polling = this.update(cx, |view, cx| view.drain(&receiver, cx));
                    if !matches!(keep_polling, Ok(true)) {
                        break;
                    }
                })
                .detach();
            }
            Err(error) => self.state = ScanState::Error(error),
        }
        cx.notify();
    }

    fn drain(&mut self, receiver: &mpsc::Receiver<WorkerEvent>, cx: &mut Context<Self>) -> bool {
        // Bound each drain so a busy scanner cannot monopolize an animation frame.
        for _ in 0..256 {
            match receiver.try_recv() {
                Ok(WorkerEvent::Progress(progress)) => self.progress = Some(progress),
                Ok(WorkerEvent::Finished(outcome)) => {
                    if self.state.cancelling() {
                        self.state = ScanState::Cancelled;
                    } else {
                        match outcome {
                            Ok(result) => {
                                let result = Arc::new(result);
                                self.result = Some(result.clone());
                                self.history.push(HistoryEntry {
                                    result,
                                    completed: chrono::Local::now()
                                        .format("%b %d, %H:%M:%S")
                                        .to_string(),
                                });
                                if self.history.len() > 20 {
                                    self.history.remove(0);
                                }
                                self.state = ScanState::Done;
                                self.page = Page::Dashboard;
                                self.severity = None;
                                self.expanded.clear();
                                // A new report starts from the first page again.
                                self.findings_limit = PAGE_SIZE;
                                self.exposures_limit = PAGE_SIZE;
                            }
                            Err(error) => self.state = ScanState::Error(error),
                        }
                    }
                    cx.notify();
                    return false;
                }
                Err(mpsc::TryRecvError::Empty) => break,
                Err(mpsc::TryRecvError::Disconnected) => {
                    self.state = ScanState::Error(
                        "The scanner disconnected before returning a result.".into(),
                    );
                    cx.notify();
                    return false;
                }
            }
        }
        cx.notify();
        true
    }

    fn cancel(&mut self, cx: &mut Context<Self>) {
        if let ScanState::Scanning { cancelling, .. } = &mut self.state {
            *cancelling = true;
            chaca_core::request_scan_cancel();
            cx.notify();
        }
    }

    fn save_report(&mut self, format: ExportFormat, cx: &mut Context<Self>) {
        if self.exporting {
            return;
        }
        let Some(result) = self.result.clone() else {
            return;
        };
        let suggested = export::export_basename(&result, format);
        // The platform owns the save dialog and overwrite confirmation.
        let directory = std::env::current_dir().unwrap_or_default();
        let dialog = cx.prompt_for_new_path(&directory, Some(&suggested));
        self.exporting = true;
        let executor = cx.background_executor().clone();
        cx.spawn(async move |this, cx| {
            let outcome = match dialog.await {
                Ok(Ok(Some(path))) => {
                    executor
                        .spawn(async move {
                            std::fs::write(&path, export::export(&result, format))
                                .map(|_| Some(format!("Saved {}", path.display())))
                                .map_err(|err| format!("Export failed: {err}"))
                        })
                        .await
                }
                Ok(Ok(None)) => Ok(None),
                Ok(Err(err)) => Err(format!("Cannot open save dialog: {err}")),
                Err(err) => Err(format!("Save dialog closed: {err}")),
            };
            let _ = this.update(cx, |view, cx| {
                view.exporting = false;
                view.notice = match outcome {
                    Ok(message) => message,
                    Err(error) => Some(error),
                };
                cx.notify();
            });
        })
        .detach();
        cx.notify();
    }

    fn export_actions(&self, cx: &mut Context<Self>) -> impl IntoElement {
        div()
            .flex()
            .flex_wrap()
            .gap_2()
            .child(muted(if self.exporting {
                "SAVING…"
            } else {
                "EXPORT"
            }))
            .children(
                [ExportFormat::Json, ExportFormat::Csv, ExportFormat::Sarif]
                    .into_iter()
                    .map(|format| {
                        button(format.as_str(), format.as_str().to_uppercase(), false)
                            .when(!self.exporting, |button| {
                                button.on_click(
                                    cx.listener(move |view, _, _, cx| view.save_report(format, cx)),
                                )
                            })
                            .when(self.exporting, |button| button.opacity(0.4))
                    }),
            )
    }

    fn sidebar(&self, cx: &mut Context<Self>) -> impl IntoElement {
        let sections: &[(&str, &[(&str, Page, Option<SettingsTab>)])] = &[
            (
                "Scan",
                &[
                    ("New scan", Page::NewScan, None),
                    ("History", Page::History, None),
                ],
            ),
            (
                "Analyze",
                &[
                    ("Dashboard", Page::Dashboard, None),
                    ("Full report", Page::Findings, None),
                    ("API exposure", Page::ApiExposure, None),
                    ("Data exposure", Page::DataExposure, None),
                ],
            ),
        ];
        let bottom: &[(&str, Page, Option<SettingsTab>)] = &[
            ("Settings", Page::Settings, Some(SettingsTab::Network)),
            ("OWASP rules", Page::Settings, Some(SettingsTab::Owasp)),
            ("Export", Page::Settings, Some(SettingsTab::Export)),
            ("Documentation", Page::Documentation, None),
            ("About", Page::About, None),
        ];
        let target = self
            .result
            .as_ref()
            .map(|result| result.url.clone())
            .unwrap_or_else(|| self.target.read(cx).value().to_owned());
        let target = if target.trim().is_empty() {
            "No target yet".to_owned()
        } else {
            target
        };
        let data_findings = self
            .result
            .as_ref()
            .map(|result| result.data_exposures.len())
            .unwrap_or(0);
        div()
            .w(px(248.))
            .h_full()
            .flex_none()
            .flex()
            .flex_col()
            .bg(rgb(SIDEBAR))
            .border_r_1()
            .border_color(rgb(LINE))
            .child(
                div()
                    .px_3()
                    .pt_3()
                    .pb_2()
                    .flex()
                    .items_center()
                    .gap_2()
                    .child(
                        div()
                            .w(px(22.))
                            .h(px(22.))
                            .rounded(px(6.))
                            .flex_none()
                            .flex()
                            .items_center()
                            .justify_center()
                            .bg(rgb(INK))
                            .text_color(rgb(CARD))
                            .text_size(px(12.))
                            .font_weight(gpui::FontWeight::SEMIBOLD)
                            .child("C"),
                    )
                    .child(
                        div()
                            .text_size(px(14.))
                            .font_weight(gpui::FontWeight::SEMIBOLD)
                            .child("Chaca"),
                    ),
            )
            .child(
                div()
                    .mx_3()
                    .mb_2()
                    .h(px(32.))
                    .px_3()
                    .rounded(px(8.))
                    .border_1()
                    .border_color(rgb(LINE))
                    .flex()
                    .items_center()
                    .child(muted(target)),
            )
            .children(
                sections
                    .iter()
                    .enumerate()
                    .map(|(group_index, (group, items))| {
                        self.nav_block(cx, group_index, group, items, data_findings)
                    }),
            )
            .child(div().flex_1())
            .child(self.nav_block(cx, 8, "", bottom, 0))
            .child(
                div()
                    .mx_3()
                    .mb_3()
                    .mt_2()
                    .px_2()
                    .py_2()
                    .rounded(px(8.))
                    .flex()
                    .items_center()
                    .gap_2()
                    .child(
                        div()
                            .w(px(16.))
                            .h(px(16.))
                            .rounded(px(4.))
                            .flex_none()
                            .bg(rgb(INK)),
                    )
                    .child(
                        div()
                            .flex()
                            .flex_col()
                            .child(
                                div()
                                    .text_size(px(12.))
                                    .font_weight(gpui::FontWeight::MEDIUM)
                                    .child("Chaca"),
                            )
                            .child(muted("Native")),
                    )
                    .child(div().flex_1())
                    .child(muted(format!("v{}", env!("CARGO_PKG_VERSION")))),
            )
    }

    fn nav_block(
        &self,
        cx: &mut Context<Self>,
        group_index: usize,
        title: &str,
        items: &[(&str, Page, Option<SettingsTab>)],
        data_findings: usize,
    ) -> gpui::Div {
        div()
            .flex()
            .flex_col()
            .gap(px(2.))
            .px_2()
            .pb_2()
            .when(!title.is_empty(), |block| {
                block.child(
                    div()
                        .px_2()
                        .pt_3()
                        .pb_1()
                        .text_size(px(12.))
                        .text_color(rgb(MUTED))
                        .child(title.to_owned()),
                )
            })
            .children(items.iter().enumerate().map(|(index, (text, page, tab))| {
                let page = *page;
                let tab = *tab;
                let selected = self.page == page && tab.is_none_or(|tab| self.settings_tab == tab);
                let show_dot = page == Page::DataExposure && data_findings > 0;
                nav_item(
                    ("nav", group_index * 8 + index),
                    (*text).to_owned(),
                    selected,
                )
                .when(show_dot, |row| {
                    row.child(
                        div()
                            .w(px(6.))
                            .h(px(6.))
                            .rounded(px(3.))
                            .flex_none()
                            .bg(rgb(GREEN)),
                    )
                })
                .on_click(cx.listener(move |view, _, window, cx| {
                    view.page = page;
                    if let Some(tab) = tab {
                        view.settings_tab = tab;
                    }
                    window.focus(&view.focus);
                    cx.notify();
                }))
            }))
    }

    /// A slim breadcrumb bar. The page title lives in the cards below it.
    fn header(&self, cx: &mut Context<Self>) -> impl IntoElement {
        div()
            .flex_none()
            .h(px(52.))
            .px_6()
            .flex()
            .items_center()
            .justify_between()
            .gap_4()
            .child(
                div()
                    .flex()
                    .items_center()
                    .gap_2()
                    .text_size(px(13.))
                    .min_w_0()
                    .child(
                        div()
                            .w(px(8.))
                            .h(px(8.))
                            .rounded(px(4.))
                            .flex_none()
                            .bg(rgb(INK)),
                    )
                    .child("Chaca")
                    .child(muted("›"))
                    .child(
                        div()
                            .text_color(rgb(SUBTLE))
                            .child(self.page.group().to_owned()),
                    )
                    .child(muted("›"))
                    .child(self.page.label().to_owned()),
            )
            .child(self.header_actions(cx))
    }

    /// The four action cards on the right of the header.
    fn header_actions(&self, cx: &mut Context<Self>) -> impl IntoElement {
        let has_result = self.result.is_some();
        div()
            .flex()
            .gap_3()
            .flex_none()
            .child(
                button("hdr-new-scan", "New scan", false).on_click(cx.listener(
                    |view, _, window, cx| {
                        view.page = Page::NewScan;
                        window.focus(&view.focus);
                        cx.notify();
                    },
                )),
            )
            .child(
                button("hdr-export", "Export", false).when(has_result, |button| {
                    button.on_click(cx.listener(|view, _, _, cx| {
                        view.save_report(ExportFormat::Json, cx);
                    }))
                }),
            )
            .child(
                button("hdr-history", "History", false).on_click(cx.listener(|view, _, _, cx| {
                    view.page = Page::History;
                    cx.notify();
                })),
            )
    }

    fn history_view(&self, cx: &mut Context<Self>) -> impl IntoElement {
        views::panel("Scan history")
            .child(muted(
                "Last 20 scans in this session. Export a report to keep it.",
            ))
            .when(self.history.is_empty(), |panel| {
                panel.child(muted("No scans yet."))
            })
            .children(self.history.iter().enumerate().rev().map(|(index, entry)| {
                button(
                    ("history", index),
                    format!(
                        "{}   |   {}   |   Score {}/100   |   {} findings",
                        entry.completed,
                        entry.result.url,
                        entry.result.security_score,
                        entry.result.vulnerabilities.len()
                    ),
                    false,
                )
                .on_click(cx.listener(move |view, _, _, cx| {
                    view.result = Some(view.history[index].result.clone());
                    view.severity = None;
                    view.expanded.clear();
                    view.page = Page::Dashboard;
                    cx.notify();
                }))
            }))
            .when(!self.history.is_empty(), |panel| {
                panel.child(
                    button("clear-history", "Clear history", false).on_click(cx.listener(
                        |view, _, _, cx| {
                            view.history.clear();
                            cx.notify();
                        },
                    )),
                )
            })
    }
}

impl Render for Chaca {
    fn render(&mut self, _window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let content = match self.page {
            Page::NewScan => self.scan_input(cx).into_any_element(),
            Page::Dashboard => self.dashboard(cx).into_any_element(),
            Page::Findings => self.findings(cx).into_any_element(),
            Page::ApiExposure => self.exposures(true, false, cx).into_any_element(),
            Page::DataExposure => self.exposures(false, true, cx).into_any_element(),
            Page::History => self.history_view(cx).into_any_element(),
            Page::Settings => views::panel(self.settings_tab.label())
                .child(muted(
                    "Network, OWASP, and export preferences stay on the Tauri shell. Scans here use the engine defaults.",
                ))
                .into_any_element(),
            Page::About => views::panel("About")
                .child(muted(format!(
                    "Chaca native {} · GPUI 0.2.2 · chaca-core {}",
                    env!("CARGO_PKG_VERSION"),
                    env!("CARGO_PKG_VERSION"),
                )))
                .into_any_element(),
            Page::Documentation => views::panel("Documentation")
                .child(muted(
                    "Passive is the default. Active and Full send payloads — scan only targets you are authorized to test. Cmd/Ctrl+Enter starts, Escape cancels.",
                ))
                .into_any_element(),
        };
        div()
            .track_focus(&self.focus)
            .size_full()
            .flex()
            .bg(rgb(BG))
            .text_color(rgb(INK))
            .font_family(FONT)
            .text_size(px(13.))
            .on_action(cx.listener(|view, _: &StartScan, window, cx| {
                window.focus(&view.focus);
                view.start(cx);
            }))
            .on_action(cx.listener(|view, _: &CancelScan, _, cx| view.cancel(cx)))
            .child(self.sidebar(cx))
            .child(
                div()
                    .flex_1()
                    .min_w_0()
                    .h_full()
                    .flex()
                    .flex_col()
                    .child(self.header(cx))
                    .child(
                        div()
                            .id("main-scroll")
                            .flex_1()
                            .min_h_0()
                            .overflow_y_scroll()
                            .bg(rgb(BG))
                            .p_6()
                            .child(
                                div()
                                    .flex()
                                    .flex_col()
                                    .gap_4()
                                    .min_w_0()
                                    .when_some(self.notice.clone(), |div, notice| {
                                        div.child(views::panel("Report export").child(notice))
                                    })
                                    .when(self.state.busy() && self.page != Page::NewScan, |div| {
                                        div.child(self.progress_view(cx))
                                    })
                                    .child(content),
                            ),
                    ),
            )
    }
}

/// Synthetic report for `CHACA_BENCH_FINDINGS`. Each finding carries a few
/// hundred bytes of unique text so the element tree and glyph cache cannot
/// collapse the rows into one shared string.
fn bench_report() -> Option<(ScanResult, bool)> {
    let raw = std::env::var("CHACA_BENCH_FINDINGS").ok()?;
    let count: usize = raw.parse().ok()?;
    let count = count.clamp(1, 5_000);
    let show_all = std::env::var_os("CHACA_BENCH_ALL").is_some();
    let paragraph = "local bench token ";
    let vulnerabilities = (0..count)
        .map(|index| {
            let body = format!("{paragraph}{index} {}", paragraph.repeat(24));
            Vulnerability {
                id: format!("BENCH-{index}"),
                rule_id: "bench".into(),
                title: format!("Bench finding {index}"),
                description: body.clone(),
                severity: match index % 5 {
                    0 => Severity::Critical,
                    1 => Severity::High,
                    2 => Severity::Medium,
                    3 => Severity::Low,
                    _ => Severity::Info,
                },
                category: "bench".into(),
                location: format!("/bench/{index}"),
                evidence: body.clone(),
                impact: body.clone(),
                remediation: body,
                affected_endpoints: vec![format!("http://127.0.0.1/bench/{index}")],
                references: vec!["https://example.invalid/bench".into()],
                cwe: "CWE-000".into(),
                ..Default::default()
            }
        })
        .collect();
    Some((
        ScanResult {
            url: "http://127.0.0.1/bench".into(),
            scan_type: ScanType::Passive,
            vulnerabilities,
            security_score: 42,
            scan_duration_ms: 1_000,
            metrics: ScanMetrics {
                request_count: count as u64,
                endpoint_total: count as u32,
                passive_vulnerability_count: count as u32,
                ..Default::default()
            },
            inventory: (0..count)
                .map(|index| InventorySummaryItem {
                    url: format!("http://127.0.0.1/bench/{index}"),
                    method: "GET".into(),
                    source: "bench".into(),
                    ..Default::default()
                })
                .collect(),
            ..Default::default()
        },
        show_all,
    ))
}

fn normalize_url(value: &str) -> Result<String, String> {
    let value = value.trim();
    if value.is_empty() {
        return Err("Please enter a target URL.".into());
    }
    let value = if value.contains("://") {
        value.to_owned()
    } else {
        format!("https://{value}")
    };
    let url = url::Url::parse(&value)
        .map_err(|_| "Please enter a valid HTTP or HTTPS URL.".to_owned())?;
    if !matches!(url.scheme(), "http" | "https") || url.host_str().is_none() {
        return Err("Only HTTP and HTTPS targets are supported.".into());
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err("Remove credentials from the URL before scanning.".into());
    }
    Ok(url.to_string())
}

fn main() {
    Application::new().run(|cx: &mut App| {
        input::bind_keys(cx);
        cx.bind_keys([
            KeyBinding::new("cmd-q", Quit, None),
            KeyBinding::new("ctrl-q", Quit, None),
            KeyBinding::new("cmd-enter", StartScan, None),
            KeyBinding::new("ctrl-enter", StartScan, None),
            KeyBinding::new("escape", CancelScan, None),
        ]);
        cx.on_action(|_: &Quit, cx| {
            chaca_core::request_scan_cancel();
            cx.quit();
        });
        cx.on_window_closed(|cx| {
            if cx.windows().is_empty() {
                chaca_core::request_scan_cancel();
                cx.quit();
            }
        })
        .detach();
        let bounds = Bounds::centered(None, size(px(1180.), px(820.)), cx);
        match cx.open_window(
            WindowOptions {
                window_bounds: Some(WindowBounds::Windowed(bounds)),
                window_min_size: Some(size(px(900.), px(640.))),
                titlebar: Some(TitlebarOptions {
                    title: Some("Chaca — Web Security Scanner".into()),
                    ..Default::default()
                }),
                app_id: Some("com.chaca.native".into()),
                ..Default::default()
            },
            |window, cx| {
                let view = cx.new(Chaca::new);
                window.focus(&view.read(cx).target.focus_handle(cx));
                view
            },
        ) {
            Ok(_) => cx.activate(true),
            Err(error) => {
                eprintln!("Cannot open Chaca window: {error}");
                cx.quit();
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn urls_are_normalized_and_unsupported_targets_rejected() {
        assert_eq!(
            normalize_url(" example.com ").unwrap(),
            "https://example.com/"
        );
        assert_eq!(
            normalize_url("http://127.0.0.1:3000/test").unwrap(),
            "http://127.0.0.1:3000/test"
        );
        for bad in [
            "",
            "file:///etc/passwd",
            "javascript://alert",
            "https://",
            "not a url",
            "https://user:secret@example.com",
        ] {
            assert!(normalize_url(bad).is_err(), "accepted {bad}");
        }
    }
}
