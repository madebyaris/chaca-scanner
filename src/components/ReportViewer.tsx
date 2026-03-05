import { useState, useMemo } from "react"
import { cn } from "@/lib/utils"
import type { ScanResult, Vulnerability, Severity, Confidence } from "@/store/scanStore"
import { exportJSON, exportCSV } from "@/utils/export"
import { ChevronDown, ChevronRight } from "lucide-react"

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

function VulnerabilityRow({ vuln }: { vuln: Vulnerability }) {
  const [expanded, setExpanded] = useState(false)
  const config = severityConfig[vuln.severity] ?? severityConfig.info
  const confConfig = confidenceConfig[vuln.confidence] ?? confidenceConfig.tentative
  const endpointCount = vuln.affected_endpoints?.length ?? 0

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
          <p className="text-[11px] font-mono text-[#525252]">{vuln.description}</p>
          {vuln.evidence && (
            <div>
              <p className="text-[9px] font-mono tracking-widest text-[#8f8f8f] font-bold mb-1">
                EVIDENCE
              </p>
              <p className="text-[11px] font-mono text-[#191919] bg-[#f7f7f7] border border-[#e5e5e5] p-2 break-all">
                {vuln.evidence}
              </p>
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
                {vuln.references.map((ref_url, i) => (
                  <a
                    key={i}
                    href={ref_url}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="block text-[10px] font-mono text-[#2563EB] hover:underline truncate"
                  >
                    {ref_url}
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
                {vuln.affected_endpoints.slice(0, 10).map((ep, i) => (
                  <p key={i} className="text-[10px] font-mono text-[#525252] truncate">{ep}</p>
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
  const [sortBy, setSortBy] = useState<"severity" | "category">("severity")

  const filteredVulns = useMemo(() => {
    let list = result.vulnerabilities
    if (severityFilter !== "all") {
      list = list.filter((v) => v.severity === severityFilter)
    }
    if (sortBy === "severity") {
      list = [...list].sort(
        (a, b) => severityOrder.indexOf(a.severity) - severityOrder.indexOf(b.severity)
      )
    } else {
      list = [...list].sort((a, b) => a.category.localeCompare(b.category))
    }
    return list
  }, [result.vulnerabilities, severityFilter, sortBy])

  const cmsLabel = result.cms_detected
    ? result.cms_detected.charAt(0).toUpperCase() + result.cms_detected.slice(1)
    : null

  return (
    <div className="px-6 py-6 space-y-4 animate-fade-in">
      {/* CMS Detection Banner */}
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

      {/* Controls */}
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
            {severityOrder.map((s) => (
              <button
                key={s}
                onClick={() => setSeverityFilter(s)}
                className={cn(
                  "px-2 py-1 text-[10px] font-mono tracking-widest transition-colors",
                  severityFilter === s
                    ? "text-[#191919] font-bold border-b-2 border-[#191919]"
                    : "text-[#8f8f8f] hover:text-[#191919]"
                )}
              >
                {s.toUpperCase()}
              </button>
            ))}
          </div>
          <div className="flex items-center gap-1 bg-[#ffffff] border border-[#e5e5e5] px-1">
            <button
              onClick={() => setSortBy("severity")}
              className={cn(
                "px-2 py-1 text-[10px] font-mono tracking-widest transition-colors",
                sortBy === "severity"
                  ? "text-[#191919] font-bold border-b-2 border-[#191919]"
                  : "text-[#8f8f8f] hover:text-[#191919]"
              )}
            >
              SEVERITY
            </button>
            <button
              onClick={() => setSortBy("category")}
              className={cn(
                "px-2 py-1 text-[10px] font-mono tracking-widest transition-colors",
                sortBy === "category"
                  ? "text-[#191919] font-bold border-b-2 border-[#191919]"
                  : "text-[#8f8f8f] hover:text-[#191919]"
              )}
            >
              CATEGORY
            </button>
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
        </div>
      </div>

      {/* Vulnerabilities */}
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
          filteredVulns.map((vuln, idx) => (
            <VulnerabilityRow key={`${vuln.id}-${idx}`} vuln={vuln} />
          ))
        )}
      </div>

      {/* API Exposures */}
      {result.api_exposures.length > 0 && (
        <div className="border border-[#e5e5e5] bg-[#ffffff]">
          <div className="px-5 py-3 border-b border-[#e5e5e5]">
            <span className="text-[11px] font-mono tracking-widest text-[#191919] font-bold">
              API EXPOSURES ({result.api_exposures.length})
            </span>
          </div>
          {result.api_exposures.map((exp, idx) => {
            const expConfig = severityConfig[exp.severity] ?? severityConfig.info
            return (
              <div key={`api-${idx}`} className="flex items-center gap-3 px-5 py-3 border-b border-[#e5e5e5] last:border-b-0 hover:bg-[#f7f7f7] transition-colors">
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

      {/* Data Exposures */}
      {result.data_exposures.length > 0 && (
        <div className="border border-[#e5e5e5] bg-[#ffffff]">
          <div className="px-5 py-3 border-b border-[#e5e5e5]">
            <span className="text-[11px] font-mono tracking-widest text-[#191919] font-bold">
              DATA EXPOSURES ({result.data_exposures.length})
            </span>
          </div>
          {result.data_exposures.map((exp, idx) => {
            const expConfig = severityConfig[exp.severity] ?? severityConfig.info
            const confCfg = confidenceConfig[exp.confidence] ?? confidenceConfig.tentative
            return (
              <div key={`data-${idx}`} className="flex items-center gap-3 px-5 py-3 border-b border-[#e5e5e5] last:border-b-0 hover:bg-[#f7f7f7] transition-colors">
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
                  {exp.field} &middot; {exp.location}
                </span>
              </div>
            )
          })}
        </div>
      )}
    </div>
  )
}
