import { useEffect, useState } from "react"
import { cn } from "@/lib/utils"
import { useSettingsStore, DEFAULT_SETTINGS, type SettingsTab } from "@/store/settingsStore"
import { useLicenseStore, PRO_FEATURES, type ProFeature } from "@/store/licenseStore"
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
import { usePresetStore } from "@/store/presetStore"
import { RotateCcw, Crown, Check, Loader2, AlertCircle, ExternalLink, Sparkles, Play, Trash2, Plus } from "lucide-react"

const TABS: { id: SettingsTab; label: string; pro?: boolean }[] = [
  { id: "network", label: "NETWORK" },
  { id: "crawling", label: "CRAWLING" },
  { id: "passive", label: "PASSIVE SCAN" },
  { id: "active", label: "ACTIVE SCAN" },
  { id: "owasp", label: "OWASP / DATA" },
  { id: "export", label: "EXPORT" },
  { id: "presets", label: "PRESETS" },
  { id: "license", label: "LICENSE", pro: true },
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
                ? tab.pro
                  ? "bg-gradient-to-r from-[#c4a44a] to-[#a08530] text-white font-bold"
                  : "bg-[#191919] text-white font-bold"
                : tab.pro
                  ? "text-[#a08530] hover:text-[#8b6914] hover:bg-[#faf7f4]"
                  : "text-[#707070] hover:text-[#191919] hover:bg-[#fafafa]"
            )}
          >
            <span className="flex items-center justify-center gap-1">
              {tab.pro && <Crown size={9} />}
              {tab.label}
            </span>
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
        {activeTab === "presets" && <PresetsTab />}
        {activeTab === "license" && <LicenseTab />}
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
        <SelectRow
          label="DISCOVERY MODE"
          description="Choose whether to crawl live targets, use pasted artifacts, or merge both sources."
          value={settings.discoveryMode}
          onChange={(v) => updateSettings({ discoveryMode: v as typeof settings.discoveryMode })}
          options={[
            { value: "crawl", label: "CRAWL ONLY" },
            { value: "artifact", label: "ARTIFACT ONLY" },
            { value: "merged", label: "MERGED" },
          ]}
        />
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

      <SettingsSection title="SCAN SCOPE">
        <TextAreaRow
          label="ALLOWLIST PATH PREFIXES"
          description="Optional list of in-scope path prefixes. Leave empty to scan the full origin."
          value={settings.scopeAllowlist.join("\n")}
          onChange={(v) =>
            updateSettings({
              scopeAllowlist: v
                .split("\n")
                .map((s) => s.trim())
                .filter(Boolean),
            })
          }
          placeholder="/app&#10;/api&#10;/graphql"
          rows={3}
        />
        <TextAreaRow
          label="DENYLIST PATH PREFIXES"
          description="Exclude logout, billing, delete, invite, or other sensitive paths from scans."
          value={settings.scopeDenylist.join("\n")}
          onChange={(v) =>
            updateSettings({
              scopeDenylist: v
                .split("\n")
                .map((s) => s.trim())
                .filter(Boolean),
            })
          }
          placeholder="/logout&#10;/billing&#10;/admin/delete"
          rows={3}
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

      <SettingsSection title="ARTIFACT IMPORT">
        <TextAreaRow
          label="OPENAPI / POSTMAN / HAR / URL SEEDS"
          description="Paste JSON artifacts or newline-separated URLs/paths to seed discovery before active scanning."
          value={settings.artifactInput}
          onChange={(v) => updateSettings({ artifactInput: v })}
          placeholder='{"openapi":"3.1.0","paths":{"\/api\/users":{"get":{}}}}&#10;https://example.com/graphql&#10;/api/v2/orders'
          rows={8}
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
        <ToggleRow
          label="GRAPHQL INTROSPECTION TESTING"
          description="Probe discovered GraphQL endpoints for schema introspection exposure."
          value={settings.activeGraphql}
          onChange={(v) => updateSettings({ activeGraphql: v })}
        />
        <ToggleRow
          label="RESOURCE CONSUMPTION TESTING"
          description="Probe pagination and batch-like parameters for missing server-side limits."
          value={settings.activeResourceConsumption}
          onChange={(v) => updateSettings({ activeResourceConsumption: v })}
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
            updateSettings({ defaultExportFormat: v as "json" | "csv" | "sarif" | "pdf" })
          }
          options={[
            { value: "json", label: "JSON" },
            { value: "csv", label: "CSV" },
            { value: "sarif", label: "SARIF" },
            { value: "pdf", label: "PDF" },
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

function PresetsTab() {
  const { presets, applyPreset, createPreset, deletePreset } = usePresetStore()
  const [newName, setNewName] = useState("")
  const [newDesc, setNewDesc] = useState("")

  const handleCreate = () => {
    const name = newName.trim()
    if (!name) return
    createPreset(newName.trim(), newDesc.trim() || undefined)
    setNewName("")
    setNewDesc("")
  }

  return (
    <>
      <SettingsSection title="SCAN PRESETS">
        <p className="text-[10px] font-mono text-[#8f8f8f] mb-4">
          Apply a preset to load its scan type and settings. Built-in presets cannot be deleted.
        </p>
        <div className="space-y-2">
          {presets.map((p) => (
            <div
              key={p.id}
              className="flex items-center justify-between px-4 py-3 border border-[#e5e5e5] bg-[#ffffff]"
            >
              <div>
                <p className="text-[11px] font-mono font-bold text-[#191919]">{p.name}</p>
                <p className="text-[10px] font-mono text-[#8f8f8f]">{p.description}</p>
                <span className="text-[9px] font-mono text-[#8f8f8f] mt-1 inline-block">
                  {p.scanType.toUpperCase()}
                  {p.isBuiltIn && " · Built-in"}
                </span>
              </div>
              <div className="flex items-center gap-2">
                <button
                  onClick={() => applyPreset(p.id)}
                  className="flex items-center gap-1 px-3 py-1.5 border border-[#e5e5e5] text-[10px] font-mono tracking-widest text-[#525252] hover:border-[#191919] hover:text-[#191919] transition-colors"
                >
                  <Play size={10} />
                  APPLY
                </button>
                {!p.isBuiltIn && (
                  <button
                    onClick={() => deletePreset(p.id)}
                    className="p-1.5 border border-[#FECACA] text-[#DC2626] hover:bg-[#FEF2F2] transition-colors"
                    title="Delete preset"
                  >
                    <Trash2 size={10} />
                  </button>
                )}
              </div>
            </div>
          ))}
        </div>
      </SettingsSection>

      <SettingsSection title="CREATE PRESET FROM CURRENT SETTINGS">
        <p className="text-[10px] font-mono text-[#8f8f8f] mb-3">
          Save your current scan type and settings as a new preset.
        </p>
        <div className="flex flex-col gap-3 max-w-md">
          <div>
            <label className="block text-[10px] font-mono tracking-widest text-[#525252] font-bold mb-1">
              NAME
            </label>
            <input
              type="text"
              value={newName}
              onChange={(e) => setNewName(e.target.value)}
              placeholder="My preset"
              className="w-full px-3 py-2 border border-[#e5e5e5] text-[11px] font-mono text-[#191919] focus:outline-none focus:border-[#191919]"
            />
          </div>
          <div>
            <label className="block text-[10px] font-mono tracking-widest text-[#525252] font-bold mb-1">
              DESCRIPTION (OPTIONAL)
            </label>
            <input
              type="text"
              value={newDesc}
              onChange={(e) => setNewDesc(e.target.value)}
              placeholder="Brief description"
              className="w-full px-3 py-2 border border-[#e5e5e5] text-[11px] font-mono text-[#191919] focus:outline-none focus:border-[#191919]"
            />
          </div>
          <button
            onClick={handleCreate}
            disabled={!newName.trim()}
            className="flex items-center gap-2 px-4 py-2 bg-[#191919] text-white text-[10px] font-mono tracking-widest hover:bg-[#161616] disabled:opacity-50 disabled:cursor-not-allowed transition-colors w-fit"
          >
            <Plus size={12} />
            CREATE PRESET
          </button>
        </div>
      </SettingsSection>
    </>
  )
}

function LicenseTab() {
  const { license, isActivating, activationError, activate, deactivate, isPro, loadLicense, loaded } =
    useLicenseStore()
  const [keyInput, setKeyInput] = useState("")

  useEffect(() => {
    if (!loaded) loadLicense()
  }, [loaded, loadLicense])

  const handleActivate = async () => {
    const trimmed = keyInput.trim()
    if (!trimmed) return
    await activate(trimmed)
    if (useLicenseStore.getState().isPro()) {
      setKeyInput("")
    }
  }

  const proFeatureList = Object.entries(PRO_FEATURES) as [ProFeature, { label: string; description: string }][]

  return (
    <>
      {/* Current status */}
      <div className={cn(
        "border",
        isPro()
          ? "border-[#e0d5c8] bg-gradient-to-br from-[#fdfbf8] to-[#f8f4ee]"
          : "border-[#e5e5e5] bg-[#ffffff]"
      )}>
        <div className={cn(
          "px-5 py-3 border-b",
          isPro() ? "border-[#e0d5c8]" : "border-[#e5e5e5]"
        )}>
          <span className="text-[11px] font-mono tracking-widest text-[#191919] font-bold flex items-center gap-2">
            {isPro() && <Crown size={12} className="text-[#c4a44a]" />}
            LICENSE STATUS
          </span>
        </div>
        <div className="px-5 py-4">
          {isPro() && license ? (
            <div className="space-y-3">
              <div className="flex items-center gap-3">
                <div className="w-8 h-8 bg-gradient-to-br from-[#c4a44a] to-[#8b6914] flex items-center justify-center">
                  <Check size={14} className="text-white" />
                </div>
                <div>
                  <span className="text-[12px] font-mono font-bold text-[#191919] block">
                    {license.status === "grace"
                      ? "CHACA PRO (RENEWAL GRACE)"
                      : "CHACA PRO ACTIVE"}
                  </span>
                  <span className="text-[10px] font-mono text-[#8f8f8f]">
                    {license.status === "grace"
                      ? license.grace_expires_at
                        ? `Your subscription expired, but you still have access until ${new Date(license.grace_expires_at * 1000).toLocaleDateString()}. Resubscribe to keep Pro features.`
                        : "Your subscription expired. Resubscribe to keep Pro features."
                      : `Licensed to ${license.email}`}
                  </span>
                </div>
              </div>
              <div className="flex flex-col gap-1.5 pl-11">
                <div className="flex gap-2">
                  <span className="text-[10px] font-mono text-[#8f8f8f] w-[80px]">KEY</span>
                  <span className="text-[10px] font-mono text-[#525252]">
                    {license.license_key.slice(0, 8)}...{license.license_key.slice(-4)}
                  </span>
                </div>
                <div className="flex gap-2">
                  <span className="text-[10px] font-mono text-[#8f8f8f] w-[80px]">SINCE</span>
                  <span className="text-[10px] font-mono text-[#525252]">
                    {license.created_at ? new Date(license.created_at).toLocaleDateString() : "—"}
                  </span>
                </div>
              </div>
              {license.status === "grace" && (
                <div className="pt-2 pl-11">
                  <a
                    href="https://madebyaris.gumroad.com/l/chacha-security"
                    target="_blank"
                    rel="noopener noreferrer"
                    className="flex items-center gap-1.5 text-[10px] font-mono tracking-wider text-[#c4a44a] font-bold hover:underline"
                  >
                    RESUBSCRIBE TO KEEP PRO
                    <ExternalLink size={9} />
                  </a>
                </div>
              )}
              <div className="pt-2 pl-11">
                <button
                  onClick={() => {
                    if (window.confirm("Deactivate your Pro license on this device?")) {
                      deactivate()
                    }
                  }}
                  className="text-[10px] font-mono tracking-wider text-[#DC2626] hover:text-[#b91c1c] transition-colors"
                >
                  DEACTIVATE LICENSE
                </button>
              </div>
            </div>
          ) : license?.status === "expired" ? (
            <div className="space-y-4">
              <div className="flex items-center gap-3">
                <div className="w-8 h-8 bg-[#fef2f2] flex items-center justify-center">
                  <AlertCircle size={14} className="text-[#DC2626]" />
                </div>
                <div>
                  <span className="text-[12px] font-mono font-bold text-[#191919] block">
                    GRACE PERIOD ENDED
                  </span>
                  <span className="text-[10px] font-mono text-[#8f8f8f]">
                    Your renewal grace period has ended. Resubscribe to restore Pro features.
                  </span>
                </div>
              </div>
              <div className="pl-11">
                <a
                  href="https://madebyaris.gumroad.com/l/chacha-security"
                  target="_blank"
                  rel="noopener noreferrer"
                  className="flex items-center gap-2 px-4 py-2 text-[10px] font-mono tracking-widest font-bold bg-gradient-to-r from-[#c4a44a] to-[#a08530] text-white hover:from-[#b8993e] hover:to-[#947a2a] transition-all w-fit"
                >
                  <Crown size={10} />
                  RESUBSCRIBE
                  <ExternalLink size={9} />
                </a>
              </div>
            </div>
          ) : (
            <div className="space-y-4">
              <div className="flex items-center gap-3">
                <div className="w-8 h-8 bg-[#f5f5f5] flex items-center justify-center">
                  <Crown size={14} className="text-[#8f8f8f]" />
                </div>
                <div>
                  <span className="text-[12px] font-mono font-bold text-[#191919] block">
                    FREE EDITION
                  </span>
                  <span className="text-[10px] font-mono text-[#8f8f8f]">
                    Upgrade to unlock Pro features
                  </span>
                </div>
              </div>

              {/* Activation form */}
              <div className="pl-11 space-y-3">
                <div>
                  <label className="text-[10px] font-mono tracking-wider text-[#525252] font-bold block mb-1.5">
                    LICENSE KEY
                  </label>
                  <div className="flex gap-2">
                    <input
                      type="text"
                      value={keyInput}
                      onChange={(e) => setKeyInput(e.target.value)}
                      onKeyDown={(e) => e.key === "Enter" && handleActivate()}
                      placeholder="XXXXXXXX-XXXXXXXX-XXXXXXXX-XXXXXXXX"
                      className="flex-1 h-8 px-3 text-[11px] font-mono text-[#191919] bg-[#fafafa] border border-[#e5e5e5] focus:border-[#191919] focus:outline-none transition-colors placeholder:text-[#c4c4c4]"
                      disabled={isActivating}
                    />
                    <button
                      onClick={handleActivate}
                      disabled={isActivating || !keyInput.trim()}
                      className={cn(
                        "px-4 h-8 text-[10px] font-mono tracking-widest font-bold transition-colors flex items-center gap-2",
                        isActivating || !keyInput.trim()
                          ? "bg-[#e5e5e5] text-[#8f8f8f] cursor-not-allowed"
                          : "bg-[#191919] text-white hover:bg-[#333]"
                      )}
                    >
                      {isActivating ? (
                        <>
                          <Loader2 size={10} className="animate-spin" />
                          VERIFYING
                        </>
                      ) : (
                        "ACTIVATE"
                      )}
                    </button>
                  </div>
                </div>

                {activationError && (
                  <div className="flex items-center gap-2 px-3 py-2 bg-[#FEF2F2] border border-[#FECACA]">
                    <AlertCircle size={12} className="text-[#DC2626] shrink-0" />
                    <span className="text-[10px] font-mono text-[#DC2626]">{activationError}</span>
                  </div>
                )}

                <div className="flex items-center gap-4 pt-1">
                  <a
                    href="https://madebyaris.gumroad.com/l/chacha-security"
                    target="_blank"
                    rel="noopener noreferrer"
                    className="flex items-center gap-1.5 text-[10px] font-mono tracking-wider text-[#191919] font-bold hover:underline"
                  >
                    GET A LICENSE
                    <ExternalLink size={9} />
                  </a>
                  <span className="text-[10px] font-mono text-[#8f8f8f]">
                    $5/month or $50/year
                  </span>
                </div>
              </div>
            </div>
          )}
        </div>
      </div>

      {/* Pro features list */}
      <SettingsSection title="PRO FEATURES">
        <div className="divide-y divide-[#f0f0f0]">
          {proFeatureList.map(([key, info]) => (
            <div key={key} className="flex items-center justify-between py-3">
              <div className="flex-1 min-w-0">
                <span className="text-[11px] font-mono tracking-wider text-[#191919] font-bold block">
                  {info.label.toUpperCase()}
                </span>
                <span className="text-[10px] font-mono text-[#8f8f8f] mt-0.5 block leading-relaxed">
                  {info.description}
                </span>
              </div>
              <div className="shrink-0 ml-4">
                {isPro() ? (
                  <span className="flex items-center gap-1 text-[10px] font-mono tracking-wider text-[#16a34a] font-bold">
                    <Check size={10} />
                    ACTIVE
                  </span>
                ) : (
                  <span className="flex items-center gap-1 text-[10px] font-mono tracking-wider text-[#8f8f8f]">
                    <Crown size={9} className="text-[#c4a44a]" />
                    PRO
                  </span>
                )}
              </div>
            </div>
          ))}
        </div>
      </SettingsSection>

      {/* Comparison */}
      {!isPro() && (
        <div className="border border-[#e0d5c8] bg-gradient-to-br from-[#fdfbf8] to-[#f8f4ee]">
          <div className="px-5 py-3 border-b border-[#e0d5c8]">
            <span className="text-[11px] font-mono tracking-widest text-[#191919] font-bold flex items-center gap-2">
              <Sparkles size={12} className="text-[#c4a44a]" />
              WHY UPGRADE?
            </span>
          </div>
          <div className="px-5 py-4">
            <div className="grid grid-cols-2 gap-4">
              <div>
                <span className="text-[10px] font-mono tracking-wider text-[#8f8f8f] font-bold block mb-2">
                  FREE
                </span>
                <ul className="space-y-1.5">
                  {[
                    "Full passive + active scanning",
                    "JSON, CSV, SARIF export",
                    "50-scan history",
                    "CWE remediation guidance",
                    "Community support",
                  ].map((item) => (
                    <li key={item} className="flex items-start gap-2">
                      <Check size={9} className="text-[#16a34a] mt-0.5 shrink-0" />
                      <span className="text-[10px] font-mono text-[#525252]">{item}</span>
                    </li>
                  ))}
                </ul>
              </div>
              <div>
                <span className="text-[10px] font-mono tracking-wider text-[#c4a44a] font-bold mb-2 flex items-center gap-1">
                  <Crown size={9} />
                  PRO
                </span>
                <ul className="space-y-1.5">
                  {[
                    "Everything in Free",
                    "Branded PDF reports",
                    "Scheduled scans + drift detection",
                    "Unlimited scan history",
                    "Compliance mapping (PCI, SOC2)",
                    "Attack surface visualization",
                    "AI-powered remediation",
                    "Scan profiles & templates",
                    "Trending analytics",
                    "Priority support",
                  ].map((item) => (
                    <li key={item} className="flex items-start gap-2">
                      <Check size={9} className="text-[#c4a44a] mt-0.5 shrink-0" />
                      <span className="text-[10px] font-mono text-[#525252]">{item}</span>
                    </li>
                  ))}
                </ul>
              </div>
            </div>
            <div className="mt-4 pt-4 border-t border-[#e0d5c8] flex items-center justify-between">
              <span className="text-[10px] font-mono text-[#8f8f8f]">
                Support indie development. Ship secure code.
              </span>
              <a
                href="https://madebyaris.gumroad.com/l/chacha-security"
                target="_blank"
                rel="noopener noreferrer"
                className="flex items-center gap-2 px-4 py-2 text-[10px] font-mono tracking-widest font-bold bg-gradient-to-r from-[#c4a44a] to-[#a08530] text-white hover:from-[#b8993e] hover:to-[#947a2a] transition-all"
              >
                <Crown size={10} />
                GET CHACA PRO
                <ExternalLink size={9} />
              </a>
            </div>
          </div>
        </div>
      )}
    </>
  )
}
