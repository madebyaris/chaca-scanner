use crate::{
    state::ScanState,
    theme::*,
    views::{button, dot_bar, label, muted, panel},
    Chaca,
};
use gpui::{div, prelude::*, px, rgb, Context};
impl Chaca {
    /// The live scan panel.
    ///
    /// The progress indicator is the same dot bar the Tauri app uses, so both
    /// frontends read the same way while a scan runs.
    pub fn progress_view(&self, cx: &mut Context<Self>) -> impl IntoElement {
        let elapsed = match &self.state {
            ScanState::Scanning { started, .. } => started.elapsed().as_secs(),
            _ => 0,
        };
        let progress = self.progress.as_ref();
        let fraction = progress
            .map(|progress| {
                if progress.total == 0 {
                    0.0
                } else {
                    (progress.current as f32 / progress.total as f32).clamp(0., 1.)
                }
            })
            .unwrap_or(0.);
        let findings = progress
            .map(|progress| progress.findings_so_far)
            .unwrap_or(0);
        let counter = progress
            .map(|progress| format!("{} / {}", progress.current, progress.total))
            .unwrap_or_else(|| "0 / 0".to_owned());
        let phase = progress
            .map(|progress| progress.phase.to_uppercase())
            .unwrap_or_else(|| "INITIALIZING".to_owned());
        let message = progress
            .map(|progress| progress.message.clone())
            .unwrap_or_else(|| "Preparing scan engine…".to_owned());
        let detail = progress
            .map(|progress| progress.detail.clone())
            .unwrap_or_default();

        panel("Scan in progress")
            .child(
                div()
                    .flex()
                    .justify_between()
                    .items_center()
                    .child(label(phase))
                    .child(muted(format!(
                        "{}s elapsed · {}",
                        elapsed,
                        self.state.label()
                    ))),
            )
            // The dot bar matches the Tauri DotProgressBar: 16 dots filling
            // left to right as the phase advances.
            .child(dot_bar(fraction, 16))
            .child(
                div()
                    .flex()
                    .justify_between()
                    .child(muted(counter))
                    .child(muted(format!("{findings} findings so far"))),
            )
            .child(div().h(px(6.)))
            .child(message)
            .when(!detail.is_empty(), |div| div.child(muted(detail)))
            .child(
                button(
                    "progress-cancel",
                    if self.state.cancelling() {
                        "CANCELLING…"
                    } else {
                        "CANCEL SCAN · ESC"
                    },
                    false,
                )
                .when(self.state.busy() && !self.state.cancelling(), |button| {
                    button.on_click(cx.listener(|view, _, _, cx| view.cancel(cx)))
                })
                .when(self.state.cancelling(), |button| button.opacity(0.4)),
            )
            .child(div().h(px(4.)))
            .child(div().bg(rgb(LINE)).h(px(1.)).w_full())
    }
}
