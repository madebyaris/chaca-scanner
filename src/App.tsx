import { AppShell } from "./components/layout/AppShell"
import { ScanInput } from "./components/ScanInput"
import { ScanProgress } from "./components/ScanProgress"
import { ScanDashboard } from "./components/dashboard/ScanDashboard"
import { ScanHistory } from "./components/dashboard/ScanHistory"
import { ReportViewer } from "./components/ReportViewer"
import { SettingsPage } from "./components/settings/SettingsPage"
import { useScanStore } from "./store/scanStore"
import "./App.css"

function AppContent() {
  const { view, result, error, isScanning } = useScanStore()

  return (
    <>
      {error && view === "new-scan" && (
        <div className="mx-6 mt-4 animate-fade-in">
          <div className="border border-[#FECACA] bg-[#FEF2F2] px-5 py-3 flex items-center gap-3">
            <span className="text-[9px] font-mono tracking-widest font-bold text-[#DC2626] border border-[#FECACA] px-2 py-0.5">
              ERROR
            </span>
            <span className="text-[11px] font-mono text-[#DC2626]">{error}</span>
          </div>
        </div>
      )}

      {view === "new-scan" && <ScanInput />}
      {view === "scanning" && isScanning && <ScanProgress />}
      {view === "dashboard" && <ScanDashboard />}
      {view === "report" && result && <ReportViewer result={result} />}
      {view === "api-exposure" && result && <ReportViewer result={{
        ...result,
        vulnerabilities: [],
        data_exposures: [],
      }} />}
      {view === "data-exposure" && result && <ReportViewer result={{
        ...result,
        vulnerabilities: [],
        api_exposures: [],
      }} />}
      {view === "history" && <ScanHistory />}
      {view === "settings" && <SettingsPage />}
      {view === "about" && <AboutPlaceholder />}
      {view === "documentation" && <DocumentationPage />}
    </>
  )
}

function AboutPlaceholder() {
  return (
    <div className="px-6 py-6 space-y-4 animate-fade-in">
      <div className="border border-[#e5e5e5] bg-[#ffffff]">
        <div className="px-5 py-3 border-b border-[#e5e5e5]">
          <span className="text-[11px] font-mono tracking-widest text-[#191919] font-bold">
            ABOUT CHACA
          </span>
        </div>
        <div className="p-8">
          <div className="flex flex-col gap-3">
            {[
              { key: "VERSION", value: "0.1.0" },
              { key: "FRAMEWORK", value: "Tauri 2.x + React 19" },
              { key: "SCANNER", value: "Rust (reqwest + tokio)" },
              { key: "COVERAGE", value: "OWASP API Security Top 10" },
            ].map(({ key, value }) => (
              <div key={key} className="flex gap-2">
                <span className="text-[10px] font-mono tracking-wider text-[#8f8f8f] w-[100px]">
                  {key}
                </span>
                <span className="text-[11px] font-mono text-[#191919] font-bold">{value}</span>
              </div>
            ))}
          </div>
        </div>
      </div>

      <div className="border border-[#e5e5e5] bg-[#ffffff]">
        <div className="px-5 py-3 border-b border-[#e5e5e5]">
          <span className="text-[11px] font-mono tracking-widest text-[#191919] font-bold">
            CREATED BY
          </span>
        </div>
        <div className="p-8">
          <div className="flex flex-col gap-4">
            <div>
              <p className="text-[14px] font-bold text-[#191919] font-sans">Aris Setiawan</p>
              <p className="text-[11px] font-mono text-[#8f8f8f] mt-1">
                Security tools for modern developers
              </p>
            </div>
            <div className="flex flex-col gap-2">
              {[
                { key: "WEBSITE", value: "madebyaris.com", href: "https://madebyaris.com" },
                { key: "GITHUB", value: "github.com/madebyaris", href: "https://github.com/madebyaris" },
                { key: "X", value: "@arisberikut", href: "https://x.com/arisberikut" },
              ].map(({ key, value, href }) => (
                <div key={key} className="flex gap-2 items-center">
                  <span className="text-[10px] font-mono tracking-wider text-[#8f8f8f] w-[80px]">
                    {key}
                  </span>
                  <a
                    href={href}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="text-[11px] font-mono text-[#191919] font-bold hover:underline"
                  >
                    {value}
                  </a>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>

      <div className="border border-[#e5e5e5] bg-[#ffffff]">
        <div className="px-5 py-3 border-b border-[#e5e5e5]">
          <span className="text-[11px] font-mono tracking-widest text-[#191919] font-bold">
            LICENSE
          </span>
        </div>
        <div className="p-8">
          <p className="text-[11px] font-mono text-[#525252]">
            Chaca is open-source software. Use responsibly and only scan targets you have permission to test.
          </p>
        </div>
      </div>
    </div>
  )
}

function DocumentationPage() {
  const sections = [
    {
      title: "GETTING STARTED",
      items: [
        { label: "Enter a target URL in the scan input field" },
        { label: "Choose scan type: Passive (safe), Active (sends payloads), or Full (both)" },
        { label: "Click Start Security Scan to begin" },
        { label: "View results in the Dashboard, Full Report, or export as JSON/CSV" },
      ],
    },
    {
      title: "SCAN TYPES",
      items: [
        { label: "PASSIVE — Analyzes HTTP headers, cookies, CORS, and response content without modifying the target. Safe for production." },
        { label: "ACTIVE — Sends test payloads to detect SQL injection, XSS, SSTI, SSRF, BOLA, and auth bypass. Use only on targets you own." },
        { label: "FULL — Runs both passive and active scans for comprehensive coverage." },
      ],
    },
    {
      title: "DETECTION CAPABILITIES",
      items: [
        { label: "Security header analysis (HSTS, CSP, X-Frame-Options, CORS, cookies)" },
        { label: "Sensitive data detection with 3-tier system: known secret formats, field-value entropy analysis, PII regex matching" },
        { label: "CMS fingerprinting and specific checks for WordPress, Drupal, Joomla, Shopify" },
        { label: "API endpoint discovery and exposure assessment" },
        { label: "Active injection testing: SQLi, XSS, SSTI with unique canary values" },
        { label: "SSRF detection with baseline comparison" },
        { label: "Authentication bypass testing" },
        { label: "Generic exposure checks: .git, .env, robots.txt" },
      ],
    },
    {
      title: "SEVERITY LEVELS",
      items: [
        { label: "CRITICAL — Confirmed credential exposure, RCE, SSRF with internal data access" },
        { label: "HIGH — Confirmed injection, BOLA, CORS with credentials" },
        { label: "MEDIUM — Missing security headers, potential auth bypass, cookie flags" },
        { label: "LOW — Version disclosure, missing optional headers" },
        { label: "INFO — Server identification, API endpoint discovery" },
      ],
    },
    {
      title: "CONFIDENCE LEVELS",
      items: [
        { label: "CONFIRMED — Exploit verified or direct proof (e.g., known secret format matched)" },
        { label: "FIRM — Strong evidence from multiple signals (e.g., high-entropy secret in JSON field)" },
        { label: "TENTATIVE — Single signal or pattern match only (e.g., PII regex, heuristic test)" },
      ],
    },
    {
      title: "OWASP API SECURITY TOP 10 (2023)",
      items: [
        { label: "API1 — Broken Object Level Authorization (BOLA)" },
        { label: "API2 — Broken Authentication" },
        { label: "API3 — Broken Object Property Level Authorization" },
        { label: "API7 — Server-Side Request Forgery (SSRF)" },
        { label: "API8 — Security Misconfiguration" },
        { label: "API9 — Improper Inventory Management" },
        { label: "API10 — Unsafe Consumption of API" },
      ],
    },
  ]

  return (
    <div className="px-6 py-6 space-y-4 animate-fade-in">
      {sections.map((section) => (
        <div key={section.title} className="border border-[#e5e5e5] bg-[#ffffff]">
          <div className="px-5 py-3 border-b border-[#e5e5e5]">
            <span className="text-[11px] font-mono tracking-widest text-[#191919] font-bold">
              {section.title}
            </span>
          </div>
          <div className="p-5">
            <div className="flex flex-col gap-2.5">
              {section.items.map((item, i) => (
                <div key={i} className="flex gap-3 items-start">
                  <span className="text-[9px] font-mono text-[#8f8f8f] mt-0.5 shrink-0 w-4 text-right">
                    {String(i + 1).padStart(2, "0")}
                  </span>
                  <p className="text-[11px] font-mono text-[#525252] leading-relaxed">
                    {item.label}
                  </p>
                </div>
              ))}
            </div>
          </div>
        </div>
      ))}

      <div className="border border-[#e5e5e5] bg-[#ffffff]">
        <div className="px-5 py-3 border-b border-[#e5e5e5]">
          <span className="text-[11px] font-mono tracking-widest text-[#191919] font-bold">
            LINKS
          </span>
        </div>
        <div className="p-5 flex flex-col gap-2">
          {[
            { label: "Source Code", href: "https://github.com/madebyaris" },
            { label: "Author Website", href: "https://madebyaris.com" },
            { label: "Report Issues", href: "https://github.com/madebyaris" },
            { label: "OWASP API Security Top 10", href: "https://owasp.org/API-Security/editions/2023/en/0x11-t10/" },
          ].map(({ label, href }) => (
            <a
              key={label}
              href={href}
              target="_blank"
              rel="noopener noreferrer"
              className="text-[11px] font-mono text-[#191919] font-bold hover:underline"
            >
              {label} →
            </a>
          ))}
        </div>
      </div>
    </div>
  )
}

function App() {
  return (
    <AppShell>
      <AppContent />
    </AppShell>
  )
}

export default App
