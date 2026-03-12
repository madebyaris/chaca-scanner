# Chaca - Security Scanner PRD (Full Version)

## 1. Executive Summary

**Project Name:** Chaca - Web Security Scanner (formerly SecureScan)

**Type:** Desktop Application (Tauri 2 + React 19 + Rust)

**Version:** 0.6.0

**Core Summary:** A user-friendly security scanner that enables developers and non-technical "vibe coders" to identify OWASP Top 10 vulnerabilities, API exposure, CMS-specific issues, exposed services, and unrestricted data exposure in their web applications before deployment. v0.6 adds a local-first workflow: persistent scan history, scan presets, PDF export, project folder scanning, and PRO enhancements for authenticated scan setup and branded client-facing exports.

**Target Users:**
- Developers with basic security awareness
- "Vibe coders" who build apps without deep security expertise
- Small teams without dedicated security resources

---

## 2. Problem Statement

### The Problem

1. **Security is inaccessible**: Traditional security tools (OWASP ZAP, Burp Suite, Nmap) have steep learning curves designed for security professionals, not casual developers
2. **Late detection**: Security issues are often found in production or during penetration testing, making fixes expensive
3. **Overwhelming output**: Existing tools produce technical reports that require expertise to interpret
4. **No guidance**: Beginner developers don't know what to look for or what "good" security looks like

### The Goal

Create a security scanner that:
- Detects OWASP Top 10 vulnerabilities automatically
- Identifies exposed APIs, services, and unrestricted data exposure
- Provides beginner-friendly results with severity and confidence ratings
- Works as a desktop app for privacy and offline capability
- Reduces false positives through confidence scoring

---

## 3. Target Users

### Primary Users

| User Type | Characteristics | Needs |
|-----------|----------------|-------|
| **Vibe Coders** | Build apps using AI tools, no formal CS background | Simple UI, clear explanations, actionable results |
| **Junior Developers** | 0-2 years experience | Understand what's wrong, how to fix it |
| **Indie Hackers** | Solo developers, ship fast | Quick scans, no config, works out of the box |

### User Personas

1. **Alex (Vibe Coder)**: Uses Bolt, Lovable, Replit to build apps. Has deployed 5 apps but never thought about security. Wants to "just know if my app is safe."

2. **Jordan (Junior Dev)**: Recently learned React. Building a SaaS. Knows "SQL injection" is bad but doesn't know how to check for it.

3. **Sam (Indie Hacker)**: Ships products fast. Doesn't have time to learn complex security tools. Wants a "security check" button.

---

## 4. Functional Requirements

### 4.1 Core Features (Implemented in v0.5)

#### F1: URL-Based Scanning
- User enters a URL to scan
- Automatic endpoint discovery via crawling
- Passive and active security tests
- Report generation with security score

#### F2: OWASP Top 10 Vulnerability Detection
- BOLA, Broken Authentication, SSRF, Security Misconfiguration
- SQL Injection, XSS (reflected, DOM-based indicators, attribute/event injection)
- SSTI, CSRF, Open Redirect, Path Traversal

#### F3: API Exposure Detection
- 57+ sensitive path probes (`/swagger.json`, `/env`, `/graphql`, `/wp-json/wp/v2/users`, etc.)
- Internal API paths discovered in client-side code
- Debug endpoints exposed in production

#### F4: Data Exposure Detection
- PII patterns in API responses (SSN, credit cards, emails, phone numbers)
- Excessive data in responses
- Sensitive data in URLs and headers

#### F5: CMS Detection & Checks
- Fingerprints WordPress, Drupal, Joomla, Shopify, Magento
- Platform-specific vulnerability checks per CMS

#### F6: Target Intelligence
- IP resolution, DNS records
- TLS certificate info
- Server fingerprinting, HTTP version
- Technology detection (frameworks, languages, CDNs, WAFs, hosting)
- Cookie analysis
- `robots.txt`, `sitemap.xml`, `security.txt` discovery

#### F7: Exposed Services & Admin Panels
- Supabase, Firebase, PocketBase URL detection in client code
- Active probing of discovered service endpoints
- Admin panel detection (phpMyAdmin, Adminer, wp-login, debug consoles)

#### F8: Information Disclosure
- Stack trace detection (Python, Java, PHP, .NET, Go, Ruby, Node.js)
- Debug header detection (`X-Debug-Token`, `X-AspNet-Version`, etc.)
- File path leak detection with false-positive filtering

#### F9: Vulnerability Knowledge Base
- 50+ embedded vulnerability definitions
- CWE mappings, CVSS-aligned severity
- Remediation guidance and external references

#### F10: Scan Types
- **Passive Scan**: Analyze responses without sending attack payloads
- **Active Scan**: Send test payloads to identify vulnerabilities
- **Full Scan**: Both passive + active combined

#### F11: Results Dashboard
- Overall security score (0-100, category-capped deduction model)
- Severity breakdown (Critical/High/Medium/Low/Info)
- Confidence levels (Confirmed/Firm/Tentative)
- Vulnerability grid, scan chart, stats
- Target Intelligence panel

#### F12: Detailed Report
- Title, severity, confidence
- Description in plain English
- Location (URL, endpoint, parameter)
- Evidence
- Remediation guidance
- CWE links and external references

#### F13: Settings
- Network (timeout, max redirects, user agent, custom headers)
- Crawling (max depth, max pages, scope)
- Passive scan (individual check toggles)
- Active scan (individual test toggles)
- Data detection (PII patterns, sensitivity)
- Export/General preferences
- Persistent storage via `tauri-plugin-store`

#### F14: Export
- JSON export with full scan data
- CSV export for spreadsheet analysis

### 4.2 v0.6 Feature Pack

#### F15: Persistent Scan History
- Scan history persists across app restarts via tauri-plugin-store
- Respects `historyLimit` setting
- Clear-history behavior preserved

#### F16: Scan Presets
- Named presets: full `ScanSettings` snapshots plus metadata (name, description, mode)
- Built-in defaults: Quick passive, API audit, Full scan
- Preset management in Settings; apply from Scan Input

#### F17: PDF Export
- PDF report generation from normalized result model
- Single export pipeline for JSON/CSV/SARIF/PDF
- Redacted sensitive values in PDF output
- Pro branding controls for company name, logo, and report colors
- Target intelligence and detected stack featured prominently in client-facing exports

#### F17b: PRO Authenticated Scan Setup
- New Scan exposes quick Pro actions for custom headers and login-first setup
- Login-first flow accepts login URL, email, and password before scanning
- Authenticated session cookies are reused by crawl, passive, and active phases
- Auth state is surfaced in results for validation and troubleshooting

#### F18: Local Project Folder Scanning (MVP)
- **Secrets detection**: Provider-format regexes, keyword prefiltering, entropy heuristics
- **Config exposure**: `.env`, YAML/TOML/JSON/properties, CI, Docker/Kubernetes/Terraform, private-key-like files
- **Endpoint inventory**: Static extraction from Next.js, Express, FastAPI, GraphQL patterns; generic URL strings
- **Sensitive endpoint labeling**: Reuse existing API exposure knowledge base
- **Local-only**: No content leaves the machine; no code execution; symlinks off by default
- **Excludes**: `.git`, `node_modules`, `dist`, `.next`, caches, binaries, deep symlinks

**Explicitly excluded from v0.6 folder scan MVP:**
- Broad SAST / taint analysis
- Live secret validation against providers
- Git history scanning or pre-commit hooks
- Dependency/CVE/SCA scanning
- Binary/archive/document scanning

### 4.3 Scan Flow
```
1. Launch App
   ↓
2. Enter URL
   ↓
3. Select Scan Type (Passive/Full)
   ↓
4. Start Scan
   ↓
5. View Progress (crawl → passive → active phases)
   ↓
6. Results Dashboard (score, vulnerabilities, target intel)
   ↓
7. Detailed Report (click for specifics)
   ↓
8. Export (optional)
```

### 4.4 Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                      React Frontend                          │
│  ┌──────────┐  ┌────────────┐  ┌──────────┐  ┌───────────┐ │
│  │ URL Input│  │ Dashboard  │  │  Report  │  │ Settings  │ │
│  └────┬─────┘  └──────┬─────┘  └────┬─────┘  └─────┬─────┘ │
│       └───────────────┴──────────────┴──────────────┘       │
│                              │                               │
│                    Tauri IPC (invoke)                        │
└──────────────────────────────┬───────────────────────────────┘
                               │
┌──────────────────────────────┴───────────────────────────────┐
│                      Rust Backend                             │
│  ┌─────────────┐  ┌─────────────┐  ┌────────────────────┐   │
│  │   HTTP      │  │  Scanner    │  │   Target           │   │
│  │   Client    │  │  Engine     │  │   Intelligence     │   │
│  │ (reqwest)   │  │             │  │   (recon)          │   │
│  └──────┬──────┘  └──────┬──────┘  └──────────┬─────────┘   │
│         └────────────────┼─────────────────────┘             │
│                          │                                    │
│  ┌───────────┐  ┌───────┴───────┐  ┌────────────────────┐   │
│  │  Passive  │  │    Active     │  │    CMS Detection   │   │
│  │  Scanner  │  │    Scanner    │  │    & Checks        │   │
│  └─────┬─────┘  └───────┬───────┘  └────────┬───────────┘   │
│        └────────────────┼────────────────────┘               │
│                         │                                     │
│  ┌──────────────────────┴────────────────────────────────┐   │
│  │              Rules & Knowledge Base                    │   │
│  │  api_exposure │ data_exposure │ info_disclosure        │   │
│  │  exposed_services │ vuln_db (50+ definitions)         │   │
│  └───────────────────────────────────────────────────────┘   │
└──────────────────────────────────────────────────────────────┘
```

### 4.5 Licensing

- **Product/Support Link**: [Chaca - Web Security Scanner PRO](https://madebyaris.gumroad.com/l/chacha-security)
- **License States**: `active` (valid subscription), `grace` (post-expiry renewal window), `expired` (access ended)
- **7-Day Renewal Grace**: When a subscription is cancelled or payment fails, users retain Pro access for 7 days. During grace, the UI shows a supportive renewal message and CTA to resubscribe. No sudden interruption.
- **Refunded/Chargebacked**: Immediately invalid; no grace period.

---

## 5. Non-Functional Requirements

### 5.1 Performance
- **Scan Speed**: Complete full scan of typical site in under 60 seconds
- **App Startup**: <2 seconds to usable interface
- **Memory Usage**: <200MB RAM during scanning

### 5.2 Usability
- **Onboarding**: First-time user can run first scan in under 2 minutes
- **Error Handling**: All errors show friendly messages with suggested actions
- **Design**: Monospace-first, minimal UI following anti-slop design principles

### 5.3 Security
- **Privacy**: No data sent to external servers (except target URL during scan)
- **Safe Scanning**: Active scans can be canceled anytime
- **Rate Limiting**: Built-in delays to avoid overwhelming target servers

### 5.4 Platform
- **Current Target**: macOS (Apple Silicon), Windows (x64), Linux (x64)
- **Architecture**: Tauri 2; GitHub Actions for cross-platform releases
- **Artifacts**: macOS .app.zip (run directly), Windows portable exe + NSIS installer, Linux AppImage

---

## 6. Out of Scope (v0.6)

| Feature | Reason |
|---------|--------|
| ~~Project folder scanning~~ | v0.6 MVP: secrets, config exposure, endpoint inventory (local-only) |
| **Continuous monitoring** | Single scan focus |
| **Team collaboration** | Single user focus |
| ~~Linux/Windows builds~~ | Implemented — cross-platform releases via GitHub Actions |
| **Mobile app scanning** | Web/API focus only |
| **Custom rule creation** | Built-in rules only |
| **Scheduled scans** | Manual trigger only |

---

## 7. Success Metrics

### 7.1 Launch Criteria
- [x] Successfully scans a URL and returns results
- [x] Detects OWASP Top 10 categories
- [x] Displays severity and confidence ratings correctly
- [x] Generates exportable report (JSON/CSV)
- [x] Works offline after installation
- [x] CMS detection and platform-specific checks
- [x] Target intelligence collection
- [x] Comprehensive settings page

### 7.2 Performance Metrics

| Metric | Target |
|--------|--------|
| First scan completion | <60 seconds |
| App startup time | <2 seconds |
| False positive rate | Low (confidence scoring) |

---

## 8. Technology Stack

| Layer | Technology |
|-------|-----------|
| Native shell | Tauri 2 |
| Frontend | React 19, TypeScript, Tailwind CSS v4 |
| State | Zustand, tauri-plugin-store |
| UI primitives | Radix UI, Lucide icons |
| Charts | Recharts |
| Backend | Rust (reqwest, regex, tokio, serde, tracing, base64) |
| Build | Vite 7 |

---

## 9. Version History

| Version | Milestone |
|---------|-----------|
| 0.1.0 | MVP — basic scanning, passive scan, dashboard, OWASP detection, macOS build |
| 0.5.0 | Expanded vuln database (50+ types), CMS detection, target intelligence, exposed services, info disclosure, comprehensive settings, anti-slop UI redesign, cross-platform GitHub Releases (macOS .app.zip, Windows portable/installer, Linux AppImage) |
| 0.6.0 | v0.6 Feature Pack: persistent scan history, scan presets, branded PDF export, login-first Pro scan setup, local project folder scanning MVP (secrets, config exposure, endpoint inventory) |

---

## 10. Author

**Aris Setiawan**
- Website: [madebyaris.com](https://madebyaris.com)
- GitHub: [@madebyaris](https://github.com/madebyaris)
- X: [@arisberikut](https://x.com/arisberikut)
