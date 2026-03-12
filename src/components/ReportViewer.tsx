import { useEffect, useMemo, useState } from "react"
import { cn } from "@/lib/utils"
import type { ScanResult, Vulnerability, Severity, Confidence } from "@/store/scanStore"
import { useScanStore } from "@/store/scanStore"
import { useSettingsStore, toScanConfig } from "@/store/settingsStore"
import { useLicenseStore } from "@/store/licenseStore"
import { startScan } from "@/api/scan"
import { exportCSV, exportJSON, exportSARIF, exportPDF, exportByFormat } from "@/utils/export"
import { ChevronDown, ChevronRight, RotateCcw } from "lucide-react"

const severityOrder: Severity[] = ["critical", "high", "medium", "low", "info"]

const severityConfig: Record<Severity, { color: string; bg: string; border: string }> = {
  critical: { color: "text-[#DC2626]", bg: "bg-[#FEF2F2]", border: "border-[#FECACA]" },
  high: { color: "text-[#EA580C]", bg: "bg-[#FFF7ED]", border: "border-[#FED7AA]" },
  medium: { color: "text-[#CA8A04]", bg: "bg-[#FEFCE8]", border: "border-[#FEF08A]" },
  low: { color: "text-[#2563EB]", bg: "bg-[#EFF6FF]", border: "border-[#BFDBFE]" },
  info: { color: "text-[#737373]", bg: "bg-[#F5F5F5]", border: "border-[#E5E5E5]" },
}

const confidenceConfig: Record<Confidence, { label: string; color: string }> = {
  confirmed: { label: "CONFIRMED", color: "text-[#DC2626]" },
  firm: { label: "FIRM", color: "text-[#EA580C]" },
  tentative: { label: "TENTATIVE", color: "text-[#8f8f8f]" },
}

type TriageStatus = "open" | "accepted-risk" | "false-positive" | "fixed" | "duplicate"

interface StoredTriage {
  status: TriageStatus
  note: string
  updatedAt: number
}

function triageStorageKey(vuln: Vulnerability): string {
  return `chaca-triage:${vuln.fingerprint ?? vuln.id}`
}

function loadTriage(vuln: Vulnerability): StoredTriage {
  if (typeof window === "undefined") {
    return { status: "open", note: "", updatedAt: 0 }
  }
  try {
    const raw = window.localStorage.getItem(triageStorageKey(vuln))
    if (!raw) {
      return { status: "open", note: "", updatedAt: 0 }
    }
    const parsed = JSON.parse(raw) as StoredTriage
    return {
      status: parsed.status ?? "open",
      note: parsed.note ?? "",
      updatedAt: parsed.updatedAt ?? 0,
    }
  } catch {
    return { status: "open", note: "", updatedAt: 0 }
  }
}

function fingerprintFor(vuln: Vulnerability): string {
  return vuln.fingerprint ?? `${vuln.rule_id ?? vuln.id}:${vuln.location}`
}

function computeBaselineDiff(result: ScanResult, history: ScanResult[]) {
  const previous = [...history]
    .reverse()
    .find((item) => item.timestamp !== result.timestamp && item.url === result.url)

  if (!previous) {
    return { previous: null as ScanResult | null, newCount: result.vulnerabilities.length, unchangedCount: 0 }
  }

  const baselineFingerprints = new Set(previous.vulnerabilities.map((item) => fingerprintFor(item)))
  const currentFingerprints = new Set(result.vulnerabilities.map((item) => fingerprintFor(item)))
  const unchangedCount = [...currentFingerprints].filter((fingerprint) => baselineFingerprints.has(fingerprint)).length
  return {
    previous,
    newCount: [...currentFingerprints].filter((fingerprint) => !baselineFingerprints.has(fingerprint)).length,
    unchangedCount,
  }
}

function SummaryChip({ label, value }: { label: string; value: string }) {
  return (
    <div className="border border-[#e5e5e5] bg-[#ffffff] px-3 py-2 min-w-[140px]">
      <p className="text-[9px] font-mono tracking-widest text-[#8f8f8f]">{label}</p>
      <p className="text-[11px] font-mono text-[#191919] font-bold mt-1">{value}</p>
    </div>
  )
}

function VulnerabilityRow({
  vuln,
  scanType,
  rootUrl,
}: {
  vuln: Vulnerability
  scanType: ScanResult["scan_type"]
  rootUrl: string
}) {
  const [expanded, setExpanded] = useState(false)
  const [triage, setTriage] = useState<StoredTriage>(() => loadTriage(vuln))
  const [isRetesting, setIsRetesting] = useState(false)
  const config = severityConfig[vuln.severity] ?? severityConfig.info
  const confConfig = confidenceConfig[vuln.confidence] ?? confidenceConfig.tentative
  const endpointCount = vuln.affected_endpoints?.length ?? 0
  const { startScan: startScanAction, setResult, setError } = useScanStore()

  useEffect(() => {
    if (typeof window === "undefined") return
    window.localStorage.setItem(triageStorageKey(vuln), JSON.stringify(triage))
  }, [triage, vuln])

  const handleRetest = async () => {
    const settings = useSettingsStore.getState().settings
    setIsRetesting(true)
    startScanAction()
    try {
      const config = toScanConfig(settings)
      const result = await startScan(rootUrl, scanType, config as Record<string, unknown>)
      setResult(result, settings.historyLimit)
      if (
        settings.autoExportOnComplete &&
        (settings.defaultExportFormat !== "pdf" || useLicenseStore.getState().hasFeature("pdf-export"))
      ) {
        exportByFormat(result, settings.defaultExportFormat)
      }
    } catch (error) {
      setError(error instanceof Error ? error.message : String(error))
    } finally {
      setIsRetesting(false)
    }
  }

  return (
    <div className="border-b border-[#e5e5e5] last:border-b-0">
      <button
        onClick={() => setExpanded(!expanded)}
        className="w-full flex items-center gap-3 px-5 py-3 text-left hover:bg-[#f7f7f7] transition-colors"
      >
        {expanded ? (
          <ChevronDown size={14} className="text-[#8f8f8f] shrink-0" />
        ) : (
          <ChevronRight size={14} className="text-[#8f8f8f] shrink-0" />
        )}
        <span
          className={cn(
            "px-2 py-0.5 text-[9px] font-mono tracking-widest font-bold border shrink-0",
            config.color,
            config.bg,
            config.border
          )}
        >
          {vuln.severity.toUpperCase()}
        </span>
        <span className={cn("text-[8px] font-mono tracking-wider shrink-0", confConfig.color)}>
          {confConfig.label}
        </span>
        <span className="text-[11px] font-mono text-[#191919] font-bold flex-1 truncate">
          {vuln.title}
        </span>
        <span className="text-[8px] font-mono tracking-widest text-[#8f8f8f] border border-[#e5e5e5] px-1.5 py-0.5 shrink-0">
          {triage.status.toUpperCase()}
        </span>
        {endpointCount > 1 && (
          <span className="text-[9px] font-mono text-[#8f8f8f] border border-[#e5e5e5] px-1.5 py-0.5 shrink-0">
            {endpointCount} endpoints
          </span>
        )}
        <span className="text-[10px] font-mono text-[#8f8f8f] shrink-0 max-w-[250px] truncate">
          {vuln.category}
        </span>
      </button>

      {expanded && (
        <div className="px-5 pb-4 pt-0 ml-8 space-y-3 animate-fade-in">
          <div className="flex items-center justify-between gap-3">
            <p className="text-[11px] font-mono text-[#525252] flex-1">{vuln.description}</p>
            <button
              onClick={handleRetest}
              disabled={isRetesting}
              className="flex items-center gap-1 px-3 py-1 border border-[#e5e5e5] text-[10px] font-mono tracking-widest text-[#525252] hover:border-[#191919] hover:text-[#191919] transition-colors disabled:opacity-50"
            >
              <RotateCcw size={11} />
              {isRetesting ? "RETESTING" : "RETEST"}
            </button>
          </div>
          <div className="grid grid-cols-3 gap-3">
            <div className="border border-[#e5e5e5] bg-[#fafafa] p-2">
              <p className="text-[9px] font-mono tracking-widest text-[#8f8f8f] font-bold mb-1">FINGERPRINT</p>
              <p className="text-[10px] font-mono text-[#191919] break-all">{fingerprintFor(vuln)}</p>
            </div>
            <div className="border border-[#e5e5e5] bg-[#fafafa] p-2">
              <p className="text-[9px] font-mono tracking-widest text-[#8f8f8f] font-bold mb-1">TRIAGE STATUS</p>
              <select
                value={triage.status}
                onChange={(e) =>
                  setTriage((state) => ({ ...state, status: e.target.value as TriageStatus, updatedAt: Date.now() }))
                }
                className="w-full border border-[#e5e5e5] bg-white px-2 py-1 text-[10px] font-mono text-[#191919]"
              >
                <option value="open">OPEN</option>
                <option value="accepted-risk">ACCEPTED RISK</option>
                <option value="false-positive">FALSE POSITIVE</option>
                <option value="fixed">FIXED</option>
                <option value="duplicate">DUPLICATE</option>
              </select>
            </div>
            <div className="border border-[#e5e5e5] bg-[#fafafa] p-2">
              <p className="text-[9px] font-mono tracking-widest text-[#8f8f8f] font-bold mb-1">LAST UPDATED</p>
              <p className="text-[10px] font-mono text-[#191919]">
                {triage.updatedAt ? new Date(triage.updatedAt).toLocaleString() : "Not triaged"}
              </p>
            </div>
          </div>
          <div>
            <p className="text-[9px] font-mono tracking-widest text-[#8f8f8f] font-bold mb-1">TRIAGE NOTE</p>
            <textarea
              value={triage.note}
              onChange={(e) =>
                setTriage((state) => ({ ...state, note: e.target.value, updatedAt: Date.now() }))
              }
              rows={3}
              className="w-full border border-[#e5e5e5] bg-[#ffffff] px-3 py-2 text-[11px] font-mono text-[#191919] resize-y"
              placeholder="Document why this finding is real, accepted, suppressed, or fixed."
            />
          </div>
          {vuln.evidence && (
            <div>
              <p className="text-[9px] font-mono tracking-widest text-[#8f8f8f] font-bold mb-1">
                EVIDENCE
              </p>
              <pre className="text-[11px] font-mono text-[#191919] bg-[#f7f7f7] border border-[#e5e5e5] p-2 whitespace-pre-wrap break-all">
                {vuln.evidence}
              </pre>
            </div>
          )}
          {vuln.evidence_items && vuln.evidence_items.length > 0 && (
            <div>
              <p className="text-[9px] font-mono tracking-widest text-[#8f8f8f] font-bold mb-1">
                EVIDENCE ITEMS
              </p>
              <div className="space-y-1">
                {vuln.evidence_items.map((item, index) => (
                  <div key={`${item.label}-${index}`} className="border border-[#e5e5e5] bg-[#fafafa] px-3 py-2">
                    <p className="text-[9px] font-mono tracking-widest text-[#8f8f8f]">
                      {item.kind.toUpperCase()} · {item.label}
                    </p>
                    <p className="text-[10px] font-mono text-[#191919] mt-1 break-all">{item.value}</p>
                  </div>
                ))}
              </div>
            </div>
          )}
          {vuln.impact && (
            <div>
              <p className="text-[9px] font-mono tracking-widest text-[#8f8f8f] font-bold mb-1">
                IMPACT
              </p>
              <p className="text-[11px] font-mono text-[#525252]">{vuln.impact}</p>
            </div>
          )}
          {vuln.remediation && (
            <div>
              <p className="text-[9px] font-mono tracking-widest text-[#8f8f8f] font-bold mb-1">
                REMEDIATION
              </p>
              <p className="text-[11px] font-mono text-[#525252]">{vuln.remediation}</p>
            </div>
          )}
          {vuln.cwe && (
            <div>
              <p className="text-[9px] font-mono tracking-widest text-[#8f8f8f] font-bold mb-1">
                CWE
              </p>
              <a
                href={`https://cwe.mitre.org/data/definitions/${vuln.cwe.replace('CWE-', '')}.html`}
                target="_blank"
                rel="noopener noreferrer"
                className="text-[11px] font-mono text-[#2563EB] hover:underline"
              >
                {vuln.cwe}
              </a>
            </div>
          )}
          {vuln.references && vuln.references.length > 0 && (
            <div>
              <p className="text-[9px] font-mono tracking-widest text-[#8f8f8f] font-bold mb-1">
                REFERENCES
              </p>
              <div className="space-y-1">
                {vuln.references.map((refUrl, index) => (
                  <a
                    key={index}
                    href={refUrl}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="block text-[10px] font-mono text-[#2563EB] hover:underline truncate"
                  >
                    {refUrl}
                  </a>
                ))}
              </div>
            </div>
          )}
          {endpointCount > 0 && (
            <div>
              <p className="text-[9px] font-mono tracking-widest text-[#8f8f8f] font-bold mb-1">
                AFFECTED ENDPOINTS ({endpointCount})
              </p>
              <div className="space-y-1 max-h-32 overflow-y-auto">
                {vuln.affected_endpoints.slice(0, 10).map((endpoint, index) => (
                  <p key={index} className="text-[10px] font-mono text-[#525252] truncate">{endpoint}</p>
                ))}
                {endpointCount > 10 && (
                  <p className="text-[10px] font-mono text-[#8f8f8f]">
                    ...and {endpointCount - 10} more
                  </p>
                )}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  )
}

interface ReportViewerProps {
  result: ScanResult
}

export function ReportViewer({ result }: ReportViewerProps) {
  const [severityFilter, setSeverityFilter] = useState<Severity | "all">("all")
  const [sortBy, setSortBy] = useState<"severity" | "category" | "confidence">("severity")
  const history = useScanStore((state) => state.history)
  const setView = useScanStore((state) => state.setView)
  const setActiveTab = useSettingsStore((state) => state.setActiveTab)
  const hasPdfExport = useLicenseStore((state) => state.hasFeature("pdf-export"))

  const filteredVulns = useMemo(() => {
    let list = result.vulnerabilities
    if (severityFilter !== "all") {
      list = list.filter((v) => v.severity === severityFilter)
    }
    if (sortBy === "severity") {
      list = [...list].sort(
        (a, b) => severityOrder.indexOf(a.severity) - severityOrder.indexOf(b.severity)
      )
    } else if (sortBy === "confidence") {
      const order: Record<Confidence, number> = { confirmed: 0, firm: 1, tentative: 2 }
      list = [...list].sort((a, b) => order[a.confidence] - order[b.confidence])
    } else {
      list = [...list].sort((a, b) => a.category.localeCompare(b.category))
    }
    return list
  }, [result.vulnerabilities, severityFilter, sortBy])

  const cmsLabel = result.cms_detected
    ? result.cms_detected.charAt(0).toUpperCase() + result.cms_detected.slice(1)
    : null
  const baseline = useMemo(() => computeBaselineDiff(result, history), [history, result])

  const handlePdfExport = () => {
    if (!hasPdfExport) {
      setActiveTab("license")
      setView("settings")
      return
    }
    exportPDF(result)
  }

  return (
    <div className="px-6 py-6 space-y-4 animate-fade-in">
      {cmsLabel && (
        <div className="flex items-center gap-3 border border-[#e5e5e5] bg-[#ffffff] px-5 py-3">
          <span className="text-[9px] font-mono tracking-widest font-bold text-[#191919] border border-[#191919] px-2 py-0.5">
            CMS
          </span>
          <span className="text-[11px] font-mono text-[#191919] font-bold">
            {cmsLabel} Detected
          </span>
          <span className="text-[10px] font-mono text-[#8f8f8f]">
            CMS-specific security checks were applied
          </span>
        </div>
      )}

      <div className="flex flex-wrap gap-3">
        <SummaryChip label="AUTH STATUS" value={result.auth_state?.status?.toUpperCase() ?? "ANONYMOUS"} />
        <SummaryChip label="AUTH MODE" value={result.auth_state?.mode ?? "anonymous"} />
        <SummaryChip label="ENDPOINTS" value={String(result.metrics?.endpoint_total ?? result.inventory?.length ?? 0)} />
        <SummaryChip label="REQUESTS" value={String(result.metrics?.request_count ?? 0)} />
        <SummaryChip label="NEW SINCE BASELINE" value={String(baseline.newCount)} />
        <SummaryChip label="UNCHANGED" value={String(baseline.unchangedCount)} />
      </div>

      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="flex items-center gap-1 bg-[#ffffff] border border-[#e5e5e5] px-1">
            <button
              onClick={() => setSeverityFilter("all")}
              className={cn(
                "px-2 py-1 text-[10px] font-mono tracking-widest transition-colors",
                severityFilter === "all"
                  ? "text-[#191919] font-bold border-b-2 border-[#191919]"
                  : "text-[#8f8f8f] hover:text-[#191919]"
              )}
            >
              ALL
            </button>
            {severityOrder.map((severity) => (
              <button
                key={severity}
                onClick={() => setSeverityFilter(severity)}
                className={cn(
                  "px-2 py-1 text-[10px] font-mono tracking-widest transition-colors",
                  severityFilter === severity
                    ? "text-[#191919] font-bold border-b-2 border-[#191919]"
                    : "text-[#8f8f8f] hover:text-[#191919]"
                )}
              >
                {severity.toUpperCase()}
              </button>
            ))}
          </div>
          <div className="flex items-center gap-1 bg-[#ffffff] border border-[#e5e5e5] px-1">
            {(["severity", "category", "confidence"] as const).map((key) => (
              <button
                key={key}
                onClick={() => setSortBy(key)}
                className={cn(
                  "px-2 py-1 text-[10px] font-mono tracking-widest transition-colors",
                  sortBy === key
                    ? "text-[#191919] font-bold border-b-2 border-[#191919]"
                    : "text-[#8f8f8f] hover:text-[#191919]"
                )}
              >
                {key.toUpperCase()}
              </button>
            ))}
          </div>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={() => exportJSON(result)}
            className="px-3 py-1 border border-[#e5e5e5] text-[10px] font-mono tracking-widest text-[#525252] hover:border-[#191919] hover:text-[#191919] transition-colors"
          >
            JSON
          </button>
          <button
            onClick={() => exportCSV(result)}
            className="px-3 py-1 border border-[#e5e5e5] text-[10px] font-mono tracking-widest text-[#525252] hover:border-[#191919] hover:text-[#191919] transition-colors"
          >
            CSV
          </button>
          <button
            onClick={() => exportSARIF(result)}
            className="px-3 py-1 border border-[#e5e5e5] text-[10px] font-mono tracking-widest text-[#525252] hover:border-[#191919] hover:text-[#191919] transition-colors"
          >
            SARIF
          </button>
          <button
            onClick={handlePdfExport}
            className={cn(
              "px-3 py-1 border text-[10px] font-mono tracking-widest transition-colors",
              hasPdfExport
                ? "border-[#e5e5e5] text-[#525252] hover:border-[#191919] hover:text-[#191919]"
                : "border-[#e0d5c8] text-[#a08530] bg-[#faf7f4] hover:border-[#c4a44a]"
            )}
          >
            PDF
          </button>
        </div>
      </div>

      {baseline.previous && (
        <div className="border border-[#e5e5e5] bg-[#ffffff] px-5 py-3">
          <p className="text-[10px] font-mono tracking-widest text-[#191919] font-bold">BASELINE COMPARISON</p>
          <p className="text-[10px] font-mono text-[#8f8f8f] mt-1">
            Compared against the previous scan for this target from{" "}
            {baseline.previous.timestamp
              ? new Date(baseline.previous.timestamp).toLocaleString()
              : "history"}.
          </p>
        </div>
      )}

      <div className="border border-[#e5e5e5] bg-[#ffffff]">
        <div className="px-5 py-3 border-b border-[#e5e5e5]">
          <span className="text-[11px] font-mono tracking-widest text-[#191919] font-bold">
            VULNERABILITIES ({filteredVulns.length})
          </span>
        </div>
        {filteredVulns.length === 0 ? (
          <div className="px-5 py-8 text-center">
            <p className="text-[11px] font-mono text-[#8f8f8f]">No vulnerabilities match the filter</p>
          </div>
        ) : (
          filteredVulns.map((vuln, index) => (
            <VulnerabilityRow
              key={`${fingerprintFor(vuln)}-${index}`}
              vuln={vuln}
              scanType={result.scan_type}
              rootUrl={result.url}
            />
          ))
        )}
      </div>

      {result.api_exposures.length > 0 && (
        <div className="border border-[#e5e5e5] bg-[#ffffff]">
          <div className="px-5 py-3 border-b border-[#e5e5e5]">
            <span className="text-[11px] font-mono tracking-widest text-[#191919] font-bold">
              API EXPOSURES ({result.api_exposures.length})
            </span>
          </div>
          {result.api_exposures.map((exp, index) => {
            const expConfig = severityConfig[exp.severity] ?? severityConfig.info
            return (
              <div key={`${exp.fingerprint ?? exp.endpoint}-${index}`} className="flex items-center gap-3 px-5 py-3 border-b border-[#e5e5e5] last:border-b-0 hover:bg-[#f7f7f7] transition-colors">
                <span className={cn(
                  "px-2 py-0.5 text-[9px] font-mono tracking-widest font-bold border shrink-0",
                  expConfig.color, expConfig.bg, expConfig.border
                )}>
                  {exp.severity.toUpperCase()}
                </span>
                <span className="px-2 py-0.5 text-[9px] font-mono tracking-widest font-bold border border-[#BFDBFE] bg-[#EFF6FF] text-[#2563EB]">
                  {exp.method}
                </span>
                <span className="text-[11px] font-mono text-[#191919] font-bold flex-1 truncate">
                  {exp.endpoint}
                </span>
                <span className="text-[10px] font-mono text-[#8f8f8f] max-w-[300px] truncate">{exp.description}</span>
              </div>
            )
          })}
        </div>
      )}

      {result.data_exposures.length > 0 && (
        <div className="border border-[#e5e5e5] bg-[#ffffff]">
          <div className="px-5 py-3 border-b border-[#e5e5e5]">
            <span className="text-[11px] font-mono tracking-widest text-[#191919] font-bold">
              DATA EXPOSURES ({result.data_exposures.length})
            </span>
          </div>
          {result.data_exposures.map((exp, index) => {
            const expConfig = severityConfig[exp.severity] ?? severityConfig.info
            const confCfg = confidenceConfig[exp.confidence] ?? confidenceConfig.tentative
            return (
              <div key={`${exp.fingerprint ?? exp.location}-${index}`} className="px-5 py-3 border-b border-[#e5e5e5] last:border-b-0 hover:bg-[#f7f7f7] transition-colors">
                <div className="flex items-center gap-3">
                  <span className={cn(
                    "px-2 py-0.5 text-[9px] font-mono tracking-widest font-bold border shrink-0",
                    expConfig.color, expConfig.bg, expConfig.border
                  )}>
                    {exp.severity.toUpperCase()}
                  </span>
                  <span className={cn("text-[8px] font-mono tracking-wider shrink-0", confCfg.color)}>
                    {confCfg.label}
                  </span>
                  <span className="text-[11px] font-mono text-[#191919] font-bold">
                    {exp.data_type}
                  </span>
                  <span className="text-[10px] font-mono text-[#8f8f8f] flex-1 truncate">
                    {exp.field} · {exp.location}
                  </span>
                </div>
                {exp.matched_value && (
                  <p className="mt-2 text-[10px] font-mono text-[#525252] break-all">
                    Match sample: {exp.matched_value}
                  </p>
                )}
              </div>
            )
          })}
        </div>
      )}

      {result.inventory && result.inventory.length > 0 && (
        <div className="border border-[#e5e5e5] bg-[#ffffff]">
          <div className="px-5 py-3 border-b border-[#e5e5e5]">
            <span className="text-[11px] font-mono tracking-widest text-[#191919] font-bold">
              ENDPOINT INVENTORY ({result.inventory.length})
            </span>
          </div>
          <div className="max-h-[320px] overflow-y-auto">
            {result.inventory.slice(0, 100).map((item, index) => (
              <div key={`${item.url}-${index}`} className="px-5 py-3 border-b border-[#e5e5e5] last:border-b-0">
                <div className="flex items-center gap-2">
                  <span className="px-2 py-0.5 text-[9px] font-mono tracking-widest font-bold border border-[#BFDBFE] bg-[#EFF6FF] text-[#2563EB]">
                    {item.method}
                  </span>
                  <span className="text-[11px] font-mono text-[#191919] font-bold truncate">{item.url}</span>
                </div>
                <p className="mt-1 text-[10px] font-mono text-[#8f8f8f]">
                  Source: {item.source}
                  {item.tags.length > 0 ? ` · Tags: ${item.tags.join(", ")}` : ""}
                  {item.parameter_names.length > 0 ? ` · Params: ${item.parameter_names.join(", ")}` : ""}
                </p>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  )
}
