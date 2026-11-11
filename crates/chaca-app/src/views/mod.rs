//! Shared building blocks for the native views.
//!
//! White rounded cards, quiet nav rows, and small outline buttons.
pub mod dashboard;
pub mod progress;
pub mod scan_input;
pub mod vulnerabilities;

use crate::theme::*;
use gpui::{div, prelude::*, px, rgb, Div, ElementId, Rgba, SharedString, Stateful};

/// A white card with a hairline border and a short title.
pub fn panel(title: impl Into<SharedString>) -> Div {
    div()
        .flex()
        .flex_col()
        .gap_3()
        .p_5()
        .bg(rgb(CARD))
        .border_1()
        .border_color(rgb(LINE))
        .rounded(px(12.))
        .child(label(title))
}

/// A card used for the secondary panes of the scan screen.
pub fn sub_panel() -> Div {
    div()
        .flex()
        .flex_col()
        .gap_3()
        .p_4()
        .bg(rgb(CARD))
        .border_1()
        .border_color(rgb(LINE))
        .rounded(px(12.))
}

/// Section heading inside a card.
pub fn label(text: impl Into<SharedString>) -> Div {
    div()
        .text_size(px(13.))
        .font_weight(gpui::FontWeight::SEMIBOLD)
        .child(text.into())
}

/// Secondary copy.
pub fn muted(text: impl Into<SharedString>) -> Div {
    div()
        .text_size(px(12.))
        .text_color(rgb(MUTED))
        .child(text.into())
}

/// A sidebar row. `selected` uses the light wash, not an inverted fill.
pub fn nav_item(
    id: impl Into<ElementId>,
    text: impl Into<SharedString>,
    selected: bool,
) -> Stateful<Div> {
    div()
        .id(id)
        .w_full()
        .px_2()
        .py(px(6.))
        .rounded(px(8.))
        .flex()
        .items_center()
        .justify_between()
        .gap_2()
        .bg(rgb(if selected { WASH } else { CARD }))
        .text_color(rgb(if selected { INK } else { SUBTLE }))
        .text_size(px(13.))
        .font_weight(if selected {
            gpui::FontWeight::MEDIUM
        } else {
            gpui::FontWeight::NORMAL
        })
        .cursor_pointer()
        .hover(|style| style.bg(rgb(WASH)))
        .child(text.into())
}

/// An outline button. `selected` is the filled primary action.
pub fn button(
    id: impl Into<ElementId>,
    text: impl Into<SharedString>,
    selected: bool,
) -> Stateful<Div> {
    div()
        .id(id)
        .px_3()
        .py(px(6.))
        .rounded(px(8.))
        .border_1()
        .border_color(rgb(if selected { INK } else { LINE }))
        .bg(rgb(if selected { INK } else { CARD }))
        .text_color(rgb(if selected { CARD } else { INK }))
        .text_size(px(12.))
        .font_weight(gpui::FontWeight::MEDIUM)
        .cursor_pointer()
        .hover(|style| style.border_color(rgb(if selected { INK } else { SUBTLE })))
        .child(text.into())
}

/// A labelled value pair, stacked the way the report panels show evidence.
pub fn detail(label_text: &str, value: impl Into<SharedString>) -> Div {
    div()
        .flex()
        .flex_col()
        .gap_1()
        .child(muted(label_text.to_owned()))
        .child(div().child(value.into()))
}

/// A small pill badge, used for scan state and severity.
pub fn badge(text: impl Into<SharedString>, fg: Rgba, bg: Rgba, border: Rgba) -> Div {
    div()
        .px_2()
        .py(px(2.))
        .rounded(px(999.))
        .border_1()
        .border_color(border)
        .bg(bg)
        .text_color(fg)
        .text_size(px(9.))
        .font_weight(gpui::FontWeight::BOLD)
        .child(text.into())
}

/// A row of dots that fill left to right as `fraction` advances.
pub fn dot_bar(fraction: f32, total: usize) -> Div {
    let filled = ((fraction.clamp(0., 1.) * total as f32).round() as usize).min(total);
    div().flex().gap(px(3.)).children((0..total).map(|index| {
        div()
            .w(px(6.))
            .h(px(6.))
            .rounded(px(3.))
            .flex_none()
            .bg(rgb(if index < filled { INK } else { LINE }))
    }))
}

/// One cell of the 2x2 statistics grid.
pub fn stat_cell(label_text: &str, value: impl ToString, color: Rgba) -> Div {
    div()
        .flex()
        .flex_col()
        .justify_between()
        .gap_1()
        .p_4()
        .min_h(px(80.))
        .child(muted(label_text.to_owned()))
        .child(
            div()
                .text_size(px(22.))
                .font_weight(gpui::FontWeight::BOLD)
                .text_color(color)
                .child(value.to_string()),
        )
}
