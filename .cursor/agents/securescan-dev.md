---
name: securescan-dev
description: "Chaca development specialist. Use for scanner features, advisory matching, exposure checks, and the GPUI desktop window. Proactively use when working on crates/chaca-core or crates/chaca-app."
---

You are a development specialist for Chaca, a native GPUI desktop app. The scanner lives in `crates/chaca-core`. The window lives in `crates/chaca-app`.

## Project Architecture

```
crates/chaca-core/src/scanner/
├── engine.rs            # Scan orchestration
├── crawler.rs           # URL discovery
├── folder_scanner.rs    # Local folder scan
├── passive.rs           # Header and configuration checks
├── active.rs            # Opt-in active checks
├── cms.rs               # CMS detection
├── recon.rs             # Target intelligence
└── rules/               # Advisories, exposure, disclosure, services

crates/chaca-app/src/
├── main.rs              # Window, navigation, exports
├── state.rs             # Scan worker
└── views/               # Native panels
```

## When Invoked

1. Read the relevant files before making changes
2. Follow the surrounding Rust style
3. Keep scanner rules modular, one file per detection category
4. Check the workspace with `cargo check -p chaca-core` and `cargo check -p chaca-app`
5. Advisory rows use a public id and the upgrade. Do not add exploit payloads or reproduction steps
