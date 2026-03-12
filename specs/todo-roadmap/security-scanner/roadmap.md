# Chaca - Project Roadmap

## Project Overview

| Field | Value |
|-------|-------|
| **ID** | security-scanner |
| **Title** | Chaca - Web Security Scanner |
| **Status** | v0.6.0 Released |
| **Complexity** | Medium |
| **Total Epics** | 7 |
| **Total Tasks** | 28 |
| **Tech Stack** | Tauri 2 + React 19 + Tailwind CSS v4 + Rust |

## Project Description

A user-friendly desktop security scanner for vibe coders and developers to detect OWASP Top 10 vulnerabilities, API exposure, CMS-specific issues, exposed services, and unrestricted data exposure before deploying their apps.

---

## Kanban Board

### Epic 1: Project Setup
| Status | Task | Priority |
|--------|------|----------|
| done | Initialize Tauri + React project | critical |
| done | Configure Tailwind CSS v4 | high |
| done | Set up logging and error handling | high |

### Epic 2: Core Infrastructure
| Status | Task | Priority |
|--------|------|----------|
| done | Implement Rust HTTP client wrapper | critical |
| done | Create scanner engine architecture | critical |
| done | Set up frontend state management (Zustand) | high |

### Epic 3: Scanner Features
| Status | Task | Priority |
|--------|------|----------|
| done | Implement endpoint discovery (crawler) | critical |
| done | Implement passive scanner | critical |
| done | Implement active scanner with OWASP detection | critical |
| done | Implement API exposure and data exposure detection | high |
| done | CMS detection (WordPress, Drupal, Joomla, Shopify, Magento) | high |
| done | Target intelligence / reconnaissance | high |
| done | Exposed services & admin panel detection | high |
| done | Information disclosure detection | medium |
| done | Vulnerability knowledge base (50+ definitions) | high |
| done | Confidence scoring (Confirmed/Firm/Tentative) | medium |

### Epic 4: Frontend Foundation
| Status | Task | Priority |
|--------|------|----------|
| done | Create scan input component | critical |
| done | Create scan progress component | high |
| done | Implement Tauri IPC commands | critical |

### Epic 5: Dashboard & Reports
| Status | Task | Priority |
|--------|------|----------|
| done | Create results dashboard (score, grid, charts) | critical |
| done | Create detailed report viewer (CWE links, references) | critical |
| done | Implement export functionality (JSON, CSV) | medium |
| done | Target Intelligence panel | high |
| done | Apply anti-slop design system | high |

### Epic 6: Polish & Build
| Status | Task | Priority |
|--------|------|----------|
| done | Comprehensive settings page (6 tabs, persistent storage) | high |
| done | UI redesign with monospace-first anti-slop design | high |
| done | Cross-platform release (macOS .app.zip, Windows portable/installer, Linux AppImage) | critical |

### Epic 7: v0.6 Feature Pack
| Status | Task | Priority |
|--------|------|----------|
| done | Persistent scan history (tauri-plugin-store, hydrate on startup) | high |
| done | Scan presets (named settings snapshots, built-in + custom) | high |
| done | Unified export pipeline + PDF generation | medium |
| done | Local folder scanning MVP (secrets, config exposure, endpoint inventory) | critical |

---

## Execution Commands

```bash
# Execute all tasks
/execute-parallel security-scanner --until-finish

# Execute specific epic
/execute-parallel security-scanner --epic epic-1
```

---

## Progress Summary

- **Completed**: 28/28 tasks (100%)
- **In Progress**: 0/28 tasks (0%)
- **Todo**: 0/28 tasks (0%)

---

## Version History

| Version | Date | Milestone |
|---------|------|-----------|
| 0.1.0 | 2026-03-05 | MVP — basic scanning, passive scan, dashboard, OWASP detection, macOS build |
| 0.5.0 | 2026-03-05 | Expanded vuln DB, CMS detection, target intel, exposed services, info disclosure, settings, anti-slop UI, renamed to Chaca |
| 0.5.0 | 2026-03-12 | Cross-platform GitHub Releases: macOS .app.zip, Windows portable/installer, Linux AppImage |
| 0.6.0 | 2026-03-12 | v0.6 Feature Pack: persistent history, scan presets, branded PDF export, login-first Pro scan setup, local folder scanning MVP |
| 0.6.0 | 2026-03-12 | Licensing polish: new Gumroad product link, 7-day post-expiry renewal grace period |
