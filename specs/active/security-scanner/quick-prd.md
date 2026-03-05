# Chaca - Quick PRD

## Problem
Security tools are too complex for non-security experts. Vibe coders and junior developers need a simple way to find security issues before deploying their apps.

## Solution
A user-friendly desktop security scanner that detects OWASP Top 10 vulnerabilities, API exposure, CMS-specific issues, and unrestricted data exposure through a simple URL input.

---

## Core Features

1. **URL-Based Scanning** - Enter any URL to scan
2. **OWASP Top 10 Detection** - Auto-detect all 10 categories
3. **API Exposure Check** - Find exposed internal APIs (57+ paths)
4. **Data Exposure Check** - Detect unrestricted PII/excessive data
5. **Active + Passive Scans** - Safe analysis + attack simulation
6. **CMS Detection** - WordPress, Drupal, Joomla, Shopify, Magento fingerprinting with platform-specific checks
7. **Target Intelligence** - IP, DNS, TLS, server fingerprinting, technology detection, WAF/CDN identification
8. **Vulnerability Knowledge Base** - 50+ embedded definitions with CWE, CVSS severity, remediation, references
9. **Dashboard View** - Security score + severity breakdown + vulnerability grid + charts
10. **Detailed Reports** - Plain English explanations + remediation + CWE links
11. **Severity & Confidence Ratings** - Critical/High/Medium/Low/Info with Confirmed/Firm/Tentative confidence
12. **Exposed Services Detection** - Supabase, Firebase, PocketBase, admin panels
13. **Information Disclosure** - Stack traces, debug headers, file path leaks
14. **Comprehensive Settings** - Network, crawling, passive, active, data detection, export configuration
15. **Export** - JSON and CSV

---

## Tech Stack

- **Framework**: Tauri 2 (native shell)
- **Frontend**: React 19 + TypeScript + Tailwind CSS v4
- **Backend**: Rust (reqwest, regex, tokio, serde, tracing, base64)
- **State**: Zustand + tauri-plugin-store (persistent settings)
- **UI**: Radix UI + Lucide icons + Recharts
- **Target**: macOS (v0.5)

---

## Out of Scope (v0.5)

- Authentication integration
- Project folder scanning
- Continuous monitoring
- Team features
- Linux/Windows
- Mobile app scanning
- Custom rules

---

## Success Metrics

- Complete scan in <60 seconds
- App startup <2 seconds
- Detect 5+ OWASP categories
- Export to JSON/CSV
- Confidence scoring to reduce false positives

---

## Version History

- **v0.1.0** - MVP: basic scanning, passive scan, dashboard, OWASP detection
- **v0.5.0** - Expanded vulnerability database (50+ types), CMS detection, target intelligence, exposed services detection, information disclosure, comprehensive settings, anti-slop UI redesign
