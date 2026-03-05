import { useEffect } from "react"
import { cn } from "@/lib/utils"
import { useSettingsStore, DEFAULT_SETTINGS, type SettingsTab } from "@/store/settingsStore"
import {
  ToggleRow,
  InputRow,
  SliderRow,
  SelectRow,
  TextRow,
  TextAreaRow,
  KeyValueRow,
  SettingsSection,
} from "./SettingsControls"
import { RotateCcw } from "lucide-react"

const TABS: { id: SettingsTab; label: string }[] = [
  { id: "network", label: "NETWORK" },
  { id: "crawling", label: "CRAWLING" },
  { id: "passive", label: "PASSIVE SCAN" },
  { id: "active", label: "ACTIVE SCAN" },
  { id: "owasp", label: "OWASP / DATA" },
  { id: "export", label: "EXPORT" },
]

export function SettingsPage() {
  const { activeTab, setActiveTab, resetSettings, loadSettings, loaded } =
    useSettingsStore()

  useEffect(() => {
    if (!loaded) loadSettings()
  }, [loaded, loadSettings])

  return (
    <div className="px-6 py-6 animate-fade-in">
      {/* Tab bar */}
      <div className="flex items-center gap-0 border border-[#e5e5e5] bg-[#ffffff] mb-4">
        {TABS.map((tab) => (
          <button
            key={tab.id}
            onClick={() => setActiveTab(tab.id)}
            className={cn(
              "flex-1 py-2.5 text-[10px] font-mono tracking-widest text-center transition-colors border-r border-[#e5e5e5] last:border-r-0",
              activeTab === tab.id
                ? "bg-[#191919] text-white font-bold"
                : "text-[#707070] hover:text-[#191919] hover:bg-[#fafafa]"
            )}
          >
            {tab.label}
          </button>
        ))}
      </div>

      {/* Tab content */}
      <div className="space-y-4">
        {activeTab === "network" && <NetworkTab />}
        {activeTab === "crawling" && <CrawlingTab />}
        {activeTab === "passive" && <PassiveTab />}
        {activeTab === "active" && <ActiveTab />}
        {activeTab === "owasp" && <OwaspDataTab />}
        {activeTab === "export" && <ExportTab />}
      </div>

      {/* Reset button */}
      <div className="mt-6 flex justify-end">
        <button
          onClick={() => {
            if (window.confirm("Reset all settings to defaults? This cannot be undone.")) {
              resetSettings()
            }
          }}
          className="flex items-center gap-2 px-4 py-2 text-[10px] font-mono tracking-widest text-[#DC2626] border border-[#FECACA] hover:bg-[#FEF2F2] transition-colors"
        >
          <RotateCcw size={12} />
          RESET ALL SETTINGS
        </button>
      </div>
    </div>
  )
}

function NetworkTab() {
  const { settings, updateSettings } = useSettingsStore()
  return (
    <>
      <SettingsSection title="HTTP CLIENT">
        <SliderRow
          label="HTTP TIMEOUT"
          description="Request timeout in seconds. Increase for slow targets."
          value={settings.httpTimeoutSecs}
          onChange={(v) => updateSettings({ httpTimeoutSecs: v })}
          min={5}
          max={120}
          suffix="s"
        />
        <ToggleRow
          label="ACCEPT INVALID CERTIFICATES"
          description="Allow self-signed or expired TLS certificates."
          value={settings.acceptInvalidCerts}
          onChange={(v) => updateSettings({ acceptInvalidCerts: v })}
        />
        <TextRow
          label="CUSTOM USER-AGENT"
          description="Override the default HTTP User-Agent header."
          value={settings.customUserAgent}
          onChange={(v) => updateSettings({ customUserAgent: v })}
          placeholder="Leave empty for default"
        />
        <InputRow
          label="RATE LIMIT"
          description="Max requests per second. 0 = unlimited."
          value={settings.rateLimitRps}
          onChange={(v) => updateSettings({ rateLimitRps: v })}
          min={0}
          max={100}
          suffix="req/s"
        />
      </SettingsSection>

      <SettingsSection title="AUTHENTICATION HEADERS">
        <KeyValueRow
          label="CUSTOM HEADERS"
          description="Added to every request. Use for auth tokens, API keys, or cookies."
          pairs={settings.customHeaders}
          onChange={(v) => updateSettings({ customHeaders: v })}
          keyPlaceholder="Header name"
          valuePlaceholder="Header value"
        />
      </SettingsSection>
    </>
  )
}

function CrawlingTab() {
  const { settings, updateSettings } = useSettingsStore()
  return (
    <>
      <SettingsSection title="DISCOVERY LIMITS">
        <SliderRow
          label="MAX CRAWL DEPTH"
          description="How many levels of links to follow from the target URL."
          value={settings.maxCrawlDepth}
          onChange={(v) => updateSettings({ maxCrawlDepth: v })}
          min={1}
          max={5}
        />
        <InputRow
          label="MAX ENDPOINTS"
          description="Maximum number of URLs to scan. Caps discovered endpoints."
          value={settings.maxEndpoints}
          onChange={(v) => updateSettings({ maxEndpoints: v })}
          min={10}
          max={500}
        />
        <ToggleRow
          label="FOLLOW ROBOTS.TXT"
          description="Use robots.txt for endpoint discovery."
          value={settings.followRobotsTxt}
          onChange={(v) => updateSettings({ followRobotsTxt: v })}
        />
      </SettingsSection>

      <SettingsSection title="CUSTOM API PATHS">
        <TextAreaRow
          label="ADDITIONAL PATHS"
          description="One path per line (e.g. /api/v2/users). Appended to built-in API path list."
          value={settings.customApiPaths.join("\n")}
          onChange={(v) =>
            updateSettings({
              customApiPaths: v
                .split("\n")
                .map((s) => s.trim())
                .filter(Boolean),
            })
          }
          placeholder="/api/v2/users&#10;/internal/health&#10;/admin/config"
          rows={4}
        />
      </SettingsSection>
    </>
  )
}

function PassiveTab() {
  const { settings, updateSettings } = useSettingsStore()

  const checks: { key: keyof typeof settings; label: string; desc: string }[] = [
    { key: "passiveServerHeader", label: "SERVER HEADER DISCLOSURE", desc: "Detect server version in Server header" },
    { key: "passiveXPoweredBy", label: "X-POWERED-BY DISCLOSURE", desc: "Detect technology stack in X-Powered-By" },
    { key: "passiveJsonApi", label: "JSON API DETECTION", desc: "Identify JSON API endpoints" },
    { key: "passiveHsts", label: "MISSING HSTS", desc: "Check for Strict-Transport-Security header" },
    { key: "passiveContentTypeOptions", label: "MISSING X-CONTENT-TYPE-OPTIONS", desc: "Check for nosniff header" },
    { key: "passiveFrameOptions", label: "MISSING X-FRAME-OPTIONS", desc: "Check for clickjacking protection" },
    { key: "passiveCsp", label: "WEAK / MISSING CSP", desc: "Analyze Content-Security-Policy header" },
    { key: "passiveCors", label: "CORS MISCONFIGURATION", desc: "Check for overly permissive CORS" },
    { key: "passiveReferrerPolicy", label: "MISSING REFERRER-POLICY", desc: "Check for Referrer-Policy header" },
    { key: "passivePermissionsPolicy", label: "MISSING PERMISSIONS-POLICY", desc: "Check for Permissions-Policy header" },
    { key: "passiveCacheControl", label: "JSON CACHE-CONTROL", desc: "Check JSON responses for Cache-Control" },
    { key: "passiveCookieFlags", label: "COOKIE SECURITY FLAGS", desc: "Check Secure, HttpOnly, SameSite on cookies" },
    { key: "passiveCsrf", label: "CSRF DETECTION", desc: "Detect forms missing CSRF tokens" },
    { key: "passiveClickjack", label: "CLICKJACKING PROTECTION", desc: "Check for both X-Frame-Options and frame-ancestors" },
    { key: "passiveInfoDisclosure", label: "INFO DISCLOSURE", desc: "Detect stack traces, file paths, debug info in responses" },
    { key: "passiveJwtAnalysis", label: "JWT ANALYSIS", desc: "Detect JWT tokens in responses; check for alg:none" },
    { key: "passiveRatelimitCheck", label: "RATE LIMIT HEADERS", desc: "Check API endpoints for rate-limiting headers" },
    { key: "passiveDeserCheck", label: "DESERIALIZATION INDICATORS", desc: "Detect serialized objects (Java, PHP, .NET) in responses" },
  ]

  const allOn = checks.every((c) => settings[c.key] === true)

  return (
    <>
      <SettingsSection title="PASSIVE ANALYSIS CHECKS">
        <div className="py-2 border-b border-[#f0f0f0] flex justify-end">
          <button
            onClick={() => {
              const next = !allOn
              const patch: Record<string, boolean> = {}
              for (const c of checks) patch[c.key] = next
              updateSettings(patch)
            }}
            className="text-[10px] font-mono tracking-wider text-[#525252] hover:text-[#191919] transition-colors"
          >
            {allOn ? "DISABLE ALL" : "ENABLE ALL"}
          </button>
        </div>
        {checks.map((c) => (
          <ToggleRow
            key={c.key}
            label={c.label}
            description={c.desc}
            value={settings[c.key] as boolean}
            onChange={(v) => updateSettings({ [c.key]: v })}
          />
        ))}
      </SettingsSection>

      <SettingsSection title="ADDITIONAL CHECKS">
        <ToggleRow
          label="CMS DETECTION"
          description="Fingerprint WordPress, Drupal, Joomla, Shopify, Magento and run CMS-specific checks."
          value={settings.cmsDetection}
          onChange={(v) => updateSettings({ cmsDetection: v })}
        />
        <ToggleRow
          label="GENERIC EXPOSURE CHECKS"
          description="Check for .git, .env, and sensitive paths in robots.txt."
          value={settings.genericExposureChecks}
          onChange={(v) => updateSettings({ genericExposureChecks: v })}
        />
        <ToggleRow
          label="EXPOSED DATABASE SERVICES"
          description="Detect misconfigured Supabase, Firebase, PocketBase, and MongoDB services."
          value={settings.checkExposedServices}
          onChange={(v) => updateSettings({ checkExposedServices: v })}
        />
        <ToggleRow
          label="EXPOSED ADMIN PANELS"
          description="Probe for phpMyAdmin, Adminer, phpinfo, server-status, debug toolbars."
          value={settings.checkAdminPanels}
          onChange={(v) => updateSettings({ checkAdminPanels: v })}
        />
      </SettingsSection>
    </>
  )
}

function ActiveTab() {
  const { settings, updateSettings } = useSettingsStore()
  return (
    <>
      <SettingsSection title="ACTIVE TEST MODULES">
        <ToggleRow
          label="BOLA TESTING"
          description="Test for Broken Object Level Authorization by probing sequential IDs."
          value={settings.activeBola}
          onChange={(v) => updateSettings({ activeBola: v })}
        />
        <ToggleRow
          label="SSRF TESTING"
          description="Test for Server-Side Request Forgery with internal URL payloads."
          value={settings.activeSsrf}
          onChange={(v) => updateSettings({ activeSsrf: v })}
        />
        <ToggleRow
          label="INJECTION TESTING"
          description="Test for SQL injection, XSS, and SSTI with canary payloads."
          value={settings.activeInjection}
          onChange={(v) => updateSettings({ activeInjection: v })}
        />
        <ToggleRow
          label="AUTH BYPASS TESTING"
          description="Test authentication bypass via header manipulation."
          value={settings.activeAuthBypass}
          onChange={(v) => updateSettings({ activeAuthBypass: v })}
        />
        <ToggleRow
          label="OPEN REDIRECT TESTING"
          description="Test redirect parameters for open redirect vulnerabilities."
          value={settings.activeOpenRedirect}
          onChange={(v) => updateSettings({ activeOpenRedirect: v })}
        />
        <ToggleRow
          label="PATH TRAVERSAL TESTING"
          description="Test file parameters for directory traversal (../etc/passwd)."
          value={settings.activePathTraversal}
          onChange={(v) => updateSettings({ activePathTraversal: v })}
        />
        <ToggleRow
          label="CORS ORIGIN REFLECTION"
          description="Test if server reflects arbitrary Origin with credentials."
          value={settings.activeCorsReflection}
          onChange={(v) => updateSettings({ activeCorsReflection: v })}
        />
        <ToggleRow
          label="ENHANCED XSS TESTING"
          description="Test attribute injection and event handler XSS beyond basic canary."
          value={settings.activeXssEnhanced}
          onChange={(v) => updateSettings({ activeXssEnhanced: v })}
        />
        <ToggleRow
          label="CSRF VERIFICATION"
          description="Actively verify if forms accept requests without CSRF tokens."
          value={settings.activeCsrfVerify}
          onChange={(v) => updateSettings({ activeCsrfVerify: v })}
        />
      </SettingsSection>

      <SettingsSection title="THRESHOLDS">
        <InputRow
          label="BOLA DIFF THRESHOLD"
          description="Minimum response size difference (bytes) to flag BOLA."
          value={settings.bolaDiffThreshold}
          onChange={(v) => updateSettings({ bolaDiffThreshold: v })}
          min={10}
          max={500}
          suffix="bytes"
        />
        <InputRow
          label="AUTH BYPASS DIFF THRESHOLD"
          description="Minimum response size difference (bytes) to flag auth bypass."
          value={settings.authBypassDiffThreshold}
          onChange={(v) => updateSettings({ authBypassDiffThreshold: v })}
          min={50}
          max={1000}
          suffix="bytes"
        />
      </SettingsSection>
    </>
  )
}

function OwaspDataTab() {
  const { settings, updateSettings } = useSettingsStore()
  return (
    <>
      <SettingsSection title="DATA DETECTION TIERS">
        <ToggleRow
          label="TIER 1: KNOWN SECRET FORMATS"
          description="AWS keys, GitHub PATs, JWTs, Stripe keys, database URIs, etc."
          value={settings.tier1Secrets}
          onChange={(v) => updateSettings({ tier1Secrets: v })}
        />
        <ToggleRow
          label="TIER 2: FIELD-VALUE ENTROPY"
          description="Detect high-entropy values in JSON fields like api_key, secret, password."
          value={settings.tier2Entropy}
          onChange={(v) => updateSettings({ tier2Entropy: v })}
        />
        <ToggleRow
          label="TIER 3: PII REGEX"
          description="Detect email addresses, SSNs, and credit card numbers."
          value={settings.tier3Pii}
          onChange={(v) => updateSettings({ tier3Pii: v })}
        />
      </SettingsSection>

      <SettingsSection title="DETECTION PARAMETERS">
        <SliderRow
          label="ENTROPY THRESHOLD"
          description="Minimum Shannon entropy to flag a field value as a secret (Tier 2)."
          value={settings.entropyThreshold}
          onChange={(v) => updateSettings({ entropyThreshold: v })}
          min={1.0}
          max={5.0}
          step={0.1}
        />
        <InputRow
          label="MAX PII MATCHES PER PATTERN"
          description="Cap findings per PII pattern type (Tier 3)."
          value={settings.maxPiiMatches}
          onChange={(v) => updateSettings({ maxPiiMatches: v })}
          min={1}
          max={20}
        />
        <SelectRow
          label="MINIMUM SEVERITY TO REPORT"
          description="Filter out findings below this severity level."
          value={settings.minSeverity}
          onChange={(v) => updateSettings({ minSeverity: v as typeof settings.minSeverity })}
          options={[
            { value: "critical", label: "CRITICAL" },
            { value: "high", label: "HIGH" },
            { value: "medium", label: "MEDIUM" },
            { value: "low", label: "LOW" },
            { value: "info", label: "INFO (all)" },
          ]}
        />
      </SettingsSection>
    </>
  )
}

function ExportTab() {
  const { settings, updateSettings } = useSettingsStore()
  return (
    <>
      <SettingsSection title="EXPORT PREFERENCES">
        <SelectRow
          label="DEFAULT EXPORT FORMAT"
          description="Format used when exporting scan results."
          value={settings.defaultExportFormat}
          onChange={(v) =>
            updateSettings({ defaultExportFormat: v as "json" | "csv" })
          }
          options={[
            { value: "json", label: "JSON" },
            { value: "csv", label: "CSV" },
          ]}
        />
        <ToggleRow
          label="AUTO-EXPORT ON SCAN COMPLETE"
          description="Automatically download the report when a scan finishes."
          value={settings.autoExportOnComplete}
          onChange={(v) => updateSettings({ autoExportOnComplete: v })}
        />
        <InputRow
          label="HISTORY LIMIT"
          description="Maximum number of past scans to keep in history."
          value={settings.historyLimit}
          onChange={(v) => updateSettings({ historyLimit: v })}
          min={10}
          max={200}
        />
      </SettingsSection>

      <SettingsSection title="SCORING WEIGHTS (ADVANCED)">
        <div className="py-1.5">
          <span className="text-[10px] font-mono text-[#8f8f8f] leading-relaxed block">
            Points deducted per finding of each severity. Caps limit the maximum deduction per category.
          </span>
        </div>
        <div className="grid grid-cols-2 gap-x-6">
          <div>
            <div className="text-[10px] font-mono tracking-wider text-[#525252] font-bold py-2 border-b border-[#f0f0f0]">
              PER-FINDING WEIGHT
            </div>
            <InputRow
              label="CRITICAL"
              value={settings.scoreCriticalWeight}
              onChange={(v) => updateSettings({ scoreCriticalWeight: v })}
              min={1}
              max={50}
              suffix="pts"
            />
            <InputRow
              label="HIGH"
              value={settings.scoreHighWeight}
              onChange={(v) => updateSettings({ scoreHighWeight: v })}
              min={1}
              max={50}
              suffix="pts"
            />
            <InputRow
              label="MEDIUM"
              value={settings.scoreMediumWeight}
              onChange={(v) => updateSettings({ scoreMediumWeight: v })}
              min={1}
              max={50}
              suffix="pts"
            />
            <InputRow
              label="LOW"
              value={settings.scoreLowWeight}
              onChange={(v) => updateSettings({ scoreLowWeight: v })}
              min={1}
              max={50}
              suffix="pts"
            />
          </div>
          <div>
            <div className="text-[10px] font-mono tracking-wider text-[#525252] font-bold py-2 border-b border-[#f0f0f0]">
              CATEGORY CAP
            </div>
            <InputRow
              label="CRITICAL CAP"
              value={settings.scoreCriticalCap}
              onChange={(v) => updateSettings({ scoreCriticalCap: v })}
              min={5}
              max={100}
              suffix="pts"
            />
            <InputRow
              label="HIGH CAP"
              value={settings.scoreHighCap}
              onChange={(v) => updateSettings({ scoreHighCap: v })}
              min={5}
              max={100}
              suffix="pts"
            />
            <InputRow
              label="MEDIUM CAP"
              value={settings.scoreMediumCap}
              onChange={(v) => updateSettings({ scoreMediumCap: v })}
              min={5}
              max={100}
              suffix="pts"
            />
            <InputRow
              label="LOW CAP"
              value={settings.scoreLowCap}
              onChange={(v) => updateSettings({ scoreLowCap: v })}
              min={5}
              max={100}
              suffix="pts"
            />
          </div>
        </div>
        <div className="py-2 flex justify-end">
          <button
            onClick={() =>
              updateSettings({
                scoreCriticalWeight: DEFAULT_SETTINGS.scoreCriticalWeight,
                scoreHighWeight: DEFAULT_SETTINGS.scoreHighWeight,
                scoreMediumWeight: DEFAULT_SETTINGS.scoreMediumWeight,
                scoreLowWeight: DEFAULT_SETTINGS.scoreLowWeight,
                scoreCriticalCap: DEFAULT_SETTINGS.scoreCriticalCap,
                scoreHighCap: DEFAULT_SETTINGS.scoreHighCap,
                scoreMediumCap: DEFAULT_SETTINGS.scoreMediumCap,
                scoreLowCap: DEFAULT_SETTINGS.scoreLowCap,
              })
            }
            className="text-[10px] font-mono tracking-wider text-[#8f8f8f] hover:text-[#191919] transition-colors"
          >
            RESET SCORING TO DEFAULTS
          </button>
        </div>
      </SettingsSection>
    </>
  )
}
