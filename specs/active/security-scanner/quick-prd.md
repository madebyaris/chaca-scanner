# SecureScan - Quick PRD

## Problem
Security tools are too complex for non-security experts. Vibe coders and junior developers need a simple way to find security issues before deploying their apps.

## Solution
A user-friendly desktop security scanner that detects OWASP Top 10 vulnerabilities, API exposure, and unrestricted data exposure through a simple URL input.

---

## Core Features

1. **URL-Based Scanning** - Enter any URL to scan
2. **OWASP Top 10 Detection** - Auto-detect all 10 categories
3. **API Exposure Check** - Find exposed internal APIs
4. **Data Exposure Check** - Detect unrestricted PII/excessive data
5. **Active + Passive Scans** - Safe analysis + attack simulation
6. **Dashboard View** - Security score + severity breakdown
7. **Detailed Reports** - Plain English explanations + remediation
8. **Severity Ratings** - Critical/High/Medium/Low/Info with color coding

---

## Tech Stack

- **Framework**: Tauri 2.10.3 (March 2026)
- **Frontend**: React 19.2 + TypeScript + Tailwind CSS v4.0
- **HTTP**: tauri-plugin-http (reqwest)
- **State**: Zustand
- **Target**: macOS only (v1)

---

## Out of Scope (v1)

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

---

## Timeline

- **Weeks 1-4**: MVP (basic scanning, passive scan, 3 OWASP categories)
- **Weeks 5-8**: Core (active scan, full OWASP, reports)
- **Weeks 9-12**: Polish (UI, errors, performance)
- **Week 13**: macOS launch
