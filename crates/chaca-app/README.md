# Chaca Native

A native Rust desktop app rendered by **GPUI 0.2.2**. This binary uses
`chaca-core` directly; it does not initialize Tauri, React, or a webview.

## Build and launch

From the workspace root:

```sh
cargo build -p chaca-app
cargo run -p chaca-app
cargo test -p chaca-app
```

These commands use Cargo's default workspace `target/` directory. No separate
`CARGO_TARGET_DIR` is needed. Format only this crate's sources, rather than the
whole workspace.

For an optional local macOS development bundle after building:

```sh
sh crates/chaca-app/verification/run-macos.sh
open "crates/chaca-app/verification/Chaca Native.app"
```

The helper copies the debug binary into an unsigned `.app` inside this crate.
It does not install or sign the app. Quit an old instance before rebuilding its
bundle. Release installers/signing are not part of this implementation.

## Features

- Native URL editor with selection, clipboard shortcuts, UTF-16/UTF-8 IME
  translation, and horizontal cursor scrolling. HTTP/HTTPS URL validation;
  missing schemes become HTTPS.
- Passive (default), Active, and Full Scan modes. Mode changes and duplicate
  starts are disabled during scanning.
- Start / Cancel controls, Cmd/Ctrl+Enter to start, Escape to cancel, and
  Cmd/Ctrl+Q to quit.
- Live phase, current/total progress, message, detail, findings-so-far, and
  elapsed time. Progress remains visible when navigating away from New Scan.
- Results dashboard with the engine's security score, vulnerability/API/data
  exposure counts, duration, endpoints, all scan metrics, authentication status,
  target intelligence, cookies, response headers, and endpoint inventory.
- Severity filters and expandable vulnerabilities with confidence, description,
  evidence, impact, remediation, affected endpoints, rule, CWE, and references.
- API and data exposure views. Matched secret values are not printed in the
  data-exposure list; the engine's report serialization remains unchanged.
- JSON, CSV, and SARIF exports using native save dialogs and shared core export
  helpers. Exports contain the complete selected result, independent of filters.
- Up to 20 completed scans in session history, with restore and clear actions.
  Export reports to retain them after quitting.

## Implementation map

| File | Responsibility |
| --- | --- |
| `src/main.rs` | Window bootstrap, root entity, navigation, result/history state, foreground event drain, native exports |
| `src/input.rs` | Native editable text element and input handler; adapted from GPUI's Apache-2.0 input example |
| `src/state.rs` | Scan state machine, channel sink, background Tokio worker, cancellation, measured duration |
| `src/theme.rs` | Colors, severity colors, installed system font selection |
| `src/views/mod.rs` | Shared native panels, labels, buttons, and detail rows |
| `src/views/scan_input.rs` | URL, scan mode, Start/Cancel, errors |
| `src/views/progress.rs` | Live progress and elapsed time |
| `src/views/dashboard.rs` | Results, statistics, metrics, target intelligence, inventory |
| `src/views/vulnerabilities.rs` | Severity filters, expandable evidence, API/data exposures |
| `verification/fixture.py` | Loopback-only HTTP fixture for manual native smoke tests |
| `verification/run-macos.sh` | Optional local macOS development bundle helper |

The existing crate manifest is updated to pin `gpui = "=0.2.2"` and add `url`
for proper target validation. No source changes outside `crates/chaca-app/`
are required by this implementation.

## Thread and engine boundaries

`App::open_window` creates the root `Entity<Chaca>` using `cx.new(Chaca::new)`.
The root owns state and the editor entity. Its `Render::render` returns native
GPUI elements; the view modules read that state.

A named OS thread owns a two-thread Tokio runtime. The `ChannelSink` implements
`ProgressSink: Send + Sync` and clones events into `std::sync::mpsc`. A detached
`Context::spawn` foreground task uses `BackgroundExecutor::timer` every 50ms,
then updates the weak root entity and calls `cx.notify()`. Drains are bounded
at 256 messages per tick to keep rendering responsive.

Cancellation calls `chaca_core::request_scan_cancel()`. A Tokio select branch
also checks cancellation every 50ms, so an in-flight network await can be dropped
without blocking GPUI. The worker tears down its runtime before sending the
terminal event. Start stays disabled until that event, so resetting the engine's
global cancel flag cannot race with a previous scan. Runtime creation, spawn,
worker panic, channel disconnection, scan errors, and save failures have visible
error paths. Quit and closing the last window request cancellation.

The engine currently returns `scan_duration_ms: 0`; the native worker measures
wall-clock duration, like the existing desktop host, and fills the result before
it reaches the UI/exporters.

## Verified GPUI 0.2.2 API differences

The authoritative source was the locally installed crates.io crate and its
`hello_world.rs`, `input.rs`, `scrollable.rs`, `uniform_list.rs`, and window-close
examples. This version uses:

- `gpui::Application::new().run(...)`, **not** `platform::Application`.
- `App::open_window(WindowOptions, |window, cx| cx.new(...))`; the closure's
  returned entity is the root. No `set_root_view` call is needed.
- `Render`, `IntoElement`, `Element`, `EntityInputHandler`,
  `ElementInputHandler::new`, `FocusHandle`, `Window::handle_input`, and native
  text shaping for the editor.
- `div().id(...).on_click(...)` for buttons. There are no packaged
  `elements/button.rs` or `elements/input.rs` widgets in this release.
- `Styled` utility methods and `overflow_y_scroll()` on an identified div for
  scrolling variable-height findings and intelligence.
- `Context::spawn(async move |this, cx| ...)`, `WeakEntity::update`,
  `BackgroundExecutor::timer`, and `BackgroundExecutor::spawn` for async UI work.
- `App::prompt_for_new_path` for asynchronous native save dialogs.

`AssetSource::{load,list}` and `Application::with_assets` are available, but a
font asset source is **not required** here: GPUI uses the OS font system. The
native macOS window successfully rendered Menlo without embedded fonts.
Consolas/DejaVu Sans Mono are selected on Windows/Linux respectively.

The actual engine confidence variants are `Confirmed`, `Firm`, and `Tentative`;
the UI displays these values rather than the stale Probable/Possible summary.

## Verification — 2026-11-11, macOS arm64

- `cargo build -p chaca-app`: exit 0, no compilation errors or app warnings.
- `cargo test -p chaca-app`: 3 passed, covering URL validation, cross-thread
  progress detail preservation, and Unicode native composition offsets.
- Opened and visually inspected the actual GPUI window, including URL entry,
  start, live progress, dashboard, severity filtering, expanded evidence,
  session history, and native save dialogs.
- Used only `http://127.0.0.1:38765/` and its `/slow` route from the included
  fixture. No non-local scan was launched.
- Cmd+Enter started the delayed scan; Escape cancelled it and re-enabled Start.
  A subsequent passive scan completed: **18 findings, 3 endpoints, 71 requests,
  4,186ms**. The dashboard displayed a measured 4.2 seconds.
- Saved JSON/CSV/SARIF through the UI into ignored `verification/exports/`.
  Reopened and parsed them: JSON had 18 vulnerabilities, CSV 18 data rows, and
  SARIF version 2.1.0 with 18 results; URL and passive scan type matched.
- Cargo emits a future-compatibility notice for upstream `block 0.1.6` and
  `proc-macro-error2 2.0.1`. It does not prevent the build or tests.

Generated logs, report exports, and development bundles are ignored within
`verification/`; source fixtures and the helper script are retained.

## Scope and limits

Scan, progress, results, filters, and JSON/CSV/SARIF export are implemented.
History is session-only. Scans use `ScanConfig::default()`. Active and Full
modes are wired to the engine but were not used against external targets during
verification.

Runtime verification was on macOS arm64 only. GPUI's accessibility tree exposed
window chrome rather than semantic controls in this build, so custom controls
were visually verified with native mouse/keyboard input. Screen-reader parity
and full keyboard navigation across every custom button need follow-up.

See `LICENSE-GPUI-APACHE` for the license of the adapted native editor example.
