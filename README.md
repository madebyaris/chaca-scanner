# Chaca — Web Security Scanner

A native desktop security scanner built with **Tauri 2**, **React 19**, and **Rust**. Designed for developers and vibe coders who want fast, opinionated security audits of their web apps without touching the terminal.

**Chaca** stands for **Cha**lim S**ca**nner.

## Features

### Scanning Engine (Rust)

- **Passive analysis** — security headers, cookie flags, CORS policy, CSP evaluation, CSRF detection, clickjacking, JWT analysis, rate-limit headers, insecure deserialization indicators
- **Active testing** — reflected XSS (canary + attribute/event injection), SQL injection, SSTI, open redirect, path traversal, CORS origin reflection, CSRF verification
- **CMS detection** — fingerprints WordPress, Drupal, Joomla, Shopify, Magento with platform-specific vulnerability checks
- **API exposure** — probes 57+ common sensitive paths (`/swagger.json`, `/env`, `/graphql`, `/wp-json/wp/v2/users`, etc.)
- **Information disclosure** — stack traces, debug headers, file path leaks across Python, Java, PHP, .NET, Go, Ruby, Node.js
- **Exposed services** — detects publicly accessible Supabase, Firebase, PocketBase URLs and admin panels (phpMyAdmin, Adminer, wp-login, debug consoles)
- **Target intelligence** — IP resolution, DNS records, TLS info, server fingerprinting, technology detection (frameworks, CDNs, WAFs, hosting), cookie analysis, `robots.txt` / `sitemap.xml` / `security.txt` discovery
- **Vulnerability knowledge base** — 50+ embedded vulnerability definitions with CWE mappings, CVSS-aligned severity, remediation guidance, and external references
- **Confidence scoring** — Confirmed / Firm / Tentative classification to reduce false positives
- **Deduplication & scoring** — groups findings by type, computes a category-capped security score out of 100

### Desktop App (React + Tailwind)

- Monospace-first, minimal UI with structured layout
- Real-time scan progress with crawl/passive/active phases
- Interactive dashboard with security score, vulnerability grid, scan chart, and stats
- Target Intelligence panel showing full recon data
- Detailed report viewer with CWE links and external references
- Filterable findings by severity and confidence
- Export to JSON and CSV
- Comprehensive settings page (network, crawling, passive scan, active scan, data detection, export)
- Persistent settings via `tauri-plugin-store`

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Native shell | Tauri 2 |
| Frontend | React 19, TypeScript, Tailwind CSS v4 |
| State | Zustand |
| UI primitives | Radix UI, Lucide icons |
| Backend | Rust (reqwest, regex, tokio, serde, tracing) |
| Charts | Recharts |

## Prerequisites

- [Node.js](https://nodejs.org/) 18+
- [Rust](https://rustup.rs/) 1.77+
- Platform-specific Tauri dependencies — see [Tauri prerequisites](https://v2.tauri.app/start/prerequisites/)

## Getting Started

```bash
# Install frontend dependencies
npm install

# Run in development mode (opens native window with hot reload)
npm run tauri dev

# Build for production
npm run tauri build
```

The production bundle is output to `src-tauri/target/release/bundle/`.

## Project Structure

```
src/                    # React frontend
  components/
    dashboard/          # Scan results, charts, target intelligence
    layout/             # App shell, sidebar, header
    settings/           # Settings page and controls
    ui/                 # Radix-based primitives
  store/                # Zustand stores (scan state, settings)
  utils/                # Export helpers

src-tauri/              # Rust backend
  src/
    scanner/
      engine.rs         # Scan orchestrator
      crawler.rs        # URL discovery
      passive.rs        # Passive checks
      active.rs         # Active vulnerability tests
      cms.rs            # CMS detection & checks
      recon.rs          # Target intelligence collection
      rules/
        api_exposure.rs # Sensitive path probing
        data_exposure.rs# Sensitive data patterns
        info_disclosure.rs # Stack traces, debug info
        exposed_services.rs # DB services, admin panels
        vuln_db.rs      # Vulnerability knowledge base
    lib.rs              # Tauri commands & data structures
```

## Usage

1. Enter a target URL in the scan input
2. Choose scan type (passive or full)
3. Review results in the dashboard — security score, vulnerability breakdown, target intelligence
4. Drill into individual findings for evidence, remediation, and CWE references
5. Export the report as JSON or CSV

**Only scan targets you have explicit permission to test.**

## Author

**Aris Setiawan**
- Website: [madebyaris.com](https://madebyaris.com)
- GitHub: [@madebyaris](https://github.com/madebyaris)
- X: [@arisberikut](https://x.com/arisberikut)

## License

Open-source. Use responsibly.
