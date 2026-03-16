<p align="center">
  <strong>Chaca</strong> — Web Security Scanner
</p>
<p align="center">
  <em>A native desktop security scanner for vibe coders and developers</em>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/version-0.6.0-18181b?style=flat-square" alt="version" />
  <img src="https://img.shields.io/badge/Tauri-2-18181b?style=flat-square" alt="tauri" />
  <img src="https://img.shields.io/badge/React-19-18181b?style=flat-square" alt="react" />
  <img src="https://img.shields.io/badge/Rust-1.77+-18181b?style=flat-square" alt="rust" />
</p>

<p align="center">
  Fast, opinionated security audits of your web apps — no terminal required.
</p>

<p align="center">
  Support Chaca directly: <a href="https://madebyaris.gumroad.com/l/chacha-security">buy Chaca Pro</a>, support via <a href="https://github.com/madebyaris">GitHub</a>, or send $100 founder support via PayPal to <code>arissetia.m@gmail.com</code> and get your company logo listed here forever.
</p>

---

## Screenshots

| New Scan | Dashboard | Full Report |
|:--------:|:----------:|:-----------:|
| [<img src="assets/home.png" width="280" alt="Chaca New Scan screen" />](assets/home.png) | [<img src="assets/detail.png" width="280" alt="Chaca Dashboard" />](assets/detail.png) | [<img src="assets/list-vuln.png" width="280" alt="Chaca vulnerability list" />](assets/list-vuln.png) |
| Configure target URL, scan mode (Passive/Active/Full), or scan a local folder | Security score, vulnerability trend, target intelligence | Filter by severity, CWE references, export to JSON/CSV/SARIF/PDF |

---

## What is Chaca?

**Chaca** = **Cha**lim S**ca**nner — a desktop app built with **Tauri 2**, **React 19**, and **Rust** that scans web applications for security issues. Designed for developers who want actionable results without learning Burp Suite or OWASP ZAP.

---

## Features

### Scanning Engine (Rust)

| Category | Capabilities |
|----------|--------------|
| **Passive** | Security headers, cookies, CORS, CSP, CSRF, clickjacking, JWT, rate limits, deserialization indicators |
| **Active** | XSS (canary + attribute/event injection), SQLi, SSTI, open redirect, path traversal, CORS reflection, CSRF verification |
| **CMS** | WordPress, Drupal, Joomla, Shopify, Magento fingerprinting + platform-specific checks |
| **API** | 57+ sensitive path probes (`/swagger.json`, `/env`, `/graphql`, `/wp-json/wp/v2/users`, …) |
| **Disclosure** | Stack traces, debug headers, file path leaks (Python, Java, PHP, .NET, Go, Ruby, Node.js) |
| **Services** | Supabase, Firebase, PocketBase, admin panels (phpMyAdmin, Adminer, wp-login, debug consoles) |
| **Recon** | IP, DNS, TLS, server fingerprinting, tech detection (frameworks, CDNs, WAFs, hosting), `robots.txt` / `sitemap.xml` / `security.txt` |
| **Knowledge** | 50+ vulnerability definitions with CWE, CVSS severity, remediation, references |
| **Quality** | Confidence scoring (Confirmed/Firm/Tentative), deduplication, category-capped security score (0–100) |

### Desktop App (React + Tailwind)

- Monospace-first minimal UI
- Real-time progress (crawl → passive → active)
- Dashboard with score, charts, stats, target intelligence panel
- Report viewer with CWE links and external references
- Filter by severity and confidence
- Export to JSON, CSV, SARIF, and PDF
- Pro scan helpers: quick headers, login-first setup, branded PDF exports
- Persistent scan history across app restarts
- Scan presets (Quick passive, API audit, Full scan) + custom presets
- Local folder scanning: secrets, config exposure, endpoint inventory (local-only)
- Settings page (network, crawling, passive, active, data detection, export, presets) with persistent storage

---

## Tech Stack

| Layer | Technology |
|-------|------------|
| Shell | Tauri 2 |
| Frontend | React 19, TypeScript, Tailwind CSS v4 |
| State | Zustand, tauri-plugin-store |
| UI | Radix UI, Lucide icons, Recharts |
| Backend | Rust (reqwest, regex, tokio, serde, tracing, base64) |

---

## Getting Started

### Prerequisites

- [Node.js](https://nodejs.org/) 18+
- [Rust](https://rustup.rs/) 1.77+
- [Tauri prerequisites](https://v2.tauri.app/start/prerequisites/) for your platform

### Run

```bash
npm install
npm run tauri dev
```

### Build

```bash
npm run tauri build
```

Output: `src-tauri/target/release/bundle/`

### Release (GitHub)

Pre-built binaries for **Windows (x64)** and **Linux (x64 AppImage)** are published to [GitHub Releases](https://github.com/madebyaris/chaca-scanner/releases) on each version tag. macOS builds currently require local compilation because Chaca is not yet signed/notarized with an Apple Developer account.

**To cut a release:**

1. Bump version in `package.json` and `src-tauri/tauri.conf.json`
2. Commit and push
3. Create and push a version tag: `git tag v0.6.0 && git push origin v0.6.0`
4. GitHub Actions builds all platforms and creates a draft release
5. Edit the draft release, add release notes, and publish

**Expected artifacts:**

| Platform | Artifact | Notes |
|----------|----------|-------|
| macOS (Apple Silicon) | Build locally | For now, macOS developers should compile Chaca themselves with `npm run tauri build` |
| Windows (x64) | `Chaca_0.6.0_x64-portable.exe` | Run directly; requires [WebView2](https://developer.microsoft.com/en-us/microsoft-edge/webview2/) on Windows 10 |
| Windows (x64) | `Chaca_0.6.0_x64-setup.nsis.exe` | Installer (includes WebView2) |
| Linux (x64) | `Chaca_0.6.0_amd64.AppImage` | Run directly |

**Note:** Current releases are unsigned. Windows may show security warnings, and macOS public distribution is temporarily blocked until Chaca is signed/notarized. Ensure **Settings → Actions → General → Workflow permissions** is set to "Read and write permissions" so the release workflow can create releases.

### macOS "Damaged" Warning

If macOS says `"Chaca.app" is damaged and can't be opened`, the app is usually being blocked by Gatekeeper because it is unsigned or was downloaded with a quarantine flag.

If you are a Mac developer, the most reliable option for now is to clone the repo and build locally:

```bash
npm install
npm run tauri build
```

Try these steps:

1. Download the macOS release artifact (`*.app.zip` or `*.app.tar.gz`) and extract it
2. Drag `Chaca.app` into `Applications`
3. In Finder, right-click `Chaca.app` and choose `Open`
4. If macOS still blocks it, go to `System Settings -> Privacy & Security` and click `Open Anyway`

If that still does not work, remove the quarantine attribute manually:

```bash
xattr -dr com.apple.quarantine "/Applications/Chaca.app"
```

Then open the app again.

---

## Usage

### URL Scan
1. Enter a target URL
2. Choose **Passive** or **Full** scan
3. Review dashboard — score, vulnerabilities, target intelligence
4. Open findings for evidence, remediation, CWE references
5. Export as JSON, CSV, SARIF, or PDF

### Local Folder Scan (v0.6)
1. Click **SCAN FOLDER** and select a project directory
2. Chaca scans for: secrets (AWS, GitHub, Stripe, etc.), exposed config files (`.env`, CI, K8s), and endpoint patterns (Express, Next.js, FastAPI)
3. All scanning is local-only; no content leaves your machine
4. Results appear in the same dashboard; export as usual

> **Only scan targets you have explicit permission to test.**

---

## Project Structure

```
src/                    # React frontend
├── components/
│   ├── dashboard/      # Scan results, charts, target intelligence
│   ├── layout/         # App shell, sidebar, header
│   ├── settings/       # Settings page and controls
│   └── ui/             # Radix-based primitives
├── store/              # Zustand (scan state, settings)
└── utils/              # Export helpers

src-tauri/              # Rust backend
└── src/
    ├── scanner/
    │   ├── engine.rs       # Scan orchestrator
    │   ├── crawler.rs      # URL discovery
    │   ├── folder_scanner.rs # Local folder scan (secrets, config, endpoints)
    │   ├── passive.rs      # Passive checks
    │   ├── active.rs       # Active tests
    │   ├── cms.rs          # CMS detection
    │   ├── recon.rs        # Target intelligence
    │   └── rules/          # api_exposure, data_exposure, info_disclosure,
    │                       # exposed_services, vuln_db
    └── lib.rs          # Tauri commands & data structures
```

---

## Support

**Chaca Pro** unlocks branded PDF export, unlimited history, scan profiles, quick auth headers, and login-first scanning. [Get a license](https://madebyaris.gumroad.com/l/chacha-security) to support indie development.

If you want to directly support the work at the founder level, you can also contribute **$100** via:

- [GitHub Sponsors / GitHub profile](https://github.com/madebyaris)
- PayPal: `arissetia.m@gmail.com`

Founder-level supporters can have their company logo listed here as a permanent founding supporter of the repo.

If your subscription expires, you have 7 days to resubscribe before Pro features are disabled — no sudden interruptions.

---

## Author

**Aris Setiawan**

- [madebyaris.com](https://madebyaris.com)
- [GitHub @madebyaris](https://github.com/madebyaris)
- [X @arisberikut](https://x.com/arisberikut)

---

<p align="center">
  <sub>Open-source. Use responsibly.</sub>
</p>
