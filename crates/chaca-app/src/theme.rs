//! Design tokens for the native shell.
//!
//! Light canvas, white cards, and a quiet sidebar, in the same family as the
//! reference layout: rounded surfaces, hairline borders, and a sans-serif UI.
use chaca_core::Severity;
use gpui::{rgb, Rgba};

/// Main canvas behind the cards.
pub const BG: u32 = 0xfafafa;
/// Primary foreground text.
pub const INK: u32 = 0x18181b;
/// Card and sidebar surface.
pub const CARD: u32 = 0xffffff;
/// Secondary copy.
pub const MUTED: u32 = 0x71717a;
/// Body text that should stay readable.
pub const SUBTLE: u32 = 0x3f3f46;
/// Hairline borders.
pub const LINE: u32 = 0xe4e4e7;
/// Status green, used for the sidebar dot and healthy scores.
pub const GREEN: u32 = 0x22c55e;
/// Sidebar surface. Same as the cards so the chrome reads as one app.
pub const SIDEBAR: u32 = 0xffffff;
/// Selected nav and hover wash.
pub const WASH: u32 = 0xf4f4f5;

/// Severity foreground colors (`--severity-*`).
pub const CRITICAL: u32 = 0xdc2626;
pub const HIGH: u32 = 0xea580c;
pub const MEDIUM: u32 = 0xca8a04;
pub const LOW: u32 = 0x2563eb;
pub const INFO: u32 = 0x737373;

/// Severity tinted backgrounds (`--severity-*-bg`).
pub const CRITICAL_BG: u32 = 0xfef2f2;
pub const HIGH_BG: u32 = 0xfff7ed;
pub const MEDIUM_BG: u32 = 0xfffaeb;
pub const LOW_BG: u32 = 0xeff6ff;
pub const INFO_BG: u32 = 0xf5f5f5;

/// Severity tinted borders (`--severity-*-border`).
pub const CRITICAL_BORDER: u32 = 0xfecaca;
pub const HIGH_BORDER: u32 = 0xfed7aa;
pub const MEDIUM_BORDER: u32 = 0xfde68a;
pub const LOW_BORDER: u32 = 0xbfdbfe;
pub const INFO_BORDER: u32 = 0xe5e5e5;

/// Foreground color for a severity.
pub fn severity_color(severity: &Severity) -> Rgba {
    rgb(match severity {
        Severity::Critical => CRITICAL,
        Severity::High => HIGH,
        Severity::Medium => MEDIUM,
        Severity::Low => LOW,
        Severity::Info => INFO,
    })
}

/// Tinted background for a severity.
pub fn severity_bg(severity: &Severity) -> Rgba {
    rgb(match severity {
        Severity::Critical => CRITICAL_BG,
        Severity::High => HIGH_BG,
        Severity::Medium => MEDIUM_BG,
        Severity::Low => LOW_BG,
        Severity::Info => INFO_BG,
    })
}

/// Tinted border for a severity.
pub fn severity_border(severity: &Severity) -> Rgba {
    rgb(match severity {
        Severity::Critical => CRITICAL_BORDER,
        Severity::High => HIGH_BORDER,
        Severity::Medium => MEDIUM_BORDER,
        Severity::Low => LOW_BORDER,
        Severity::Info => INFO_BORDER,
    })
}

/// Short uppercase label for a severity.
pub fn severity_label(severity: &Severity) -> &'static str {
    match severity {
        Severity::Critical => "Critical",
        Severity::High => "High",
        Severity::Medium => "Medium",
        Severity::Low => "Low",
        Severity::Info => "Info",
    }
}

/// Score color: green while healthy, otherwise the worst severity present.
pub fn score_color(score: u32) -> Rgba {
    match score {
        80..=100 => rgb(GREEN),
        60..=79 => rgb(MEDIUM),
        40..=59 => rgb(HIGH),
        _ => rgb(CRITICAL),
    }
}

#[cfg(target_os = "macos")]
pub const FONT: &str = "Helvetica Neue";
#[cfg(target_os = "windows")]
pub const FONT: &str = "Segoe UI";
#[cfg(not(any(target_os = "macos", target_os = "windows")))]
pub const FONT: &str = "DejaVu Sans";
