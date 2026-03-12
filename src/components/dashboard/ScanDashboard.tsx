import { cn } from "@/lib/utils"
import { useScanStore } from "@/store/scanStore"
import { useSettingsStore } from "@/store/settingsStore"
import { useLicenseStore } from "@/store/licenseStore"
import { exportPDF } from "@/utils/export"
import { ReportCard } from "./ReportCard"
import { ScanChart } from "./ScanChart"
import { StatsGrid } from "./StatsGrid"
import { VulnerabilityGrid } from "./VulnerabilityGrid"
import { TargetIntelligence } from "./TargetIntelligence"
import { Search, Crown } from "lucide-react"
import { useMemo } from "react"

function fingerprintFor(value: { fingerprint?: string; id?: string; location?: string }) {
  return value.fingerprint ?? `${value.id ?? "finding"}:${value.location ?? ""}`
}

export function ScanDashboard() {
  const { result, history, setView } = useScanStore()
  const setActiveTab = useSettingsStore((s) => s.setActiveTab)
  const hasPdfExport = useLicenseStore((s) => s.hasFeature("pdf-export"))

  if (!result) {
    return (
      <div className="px-6 py-16 text-center animate-fade-in">
        <div className="w-12 h-12 border border-[#e5e5e5] flex items-center justify-center mx-auto mb-4">
          <Search size={20} className="text-[#8f8f8f]" strokeWidth={1.5} />
        </div>
        <p className="text-[11px] font-mono tracking-widest text-[#8f8f8f] mb-4">
          NO SCAN RESULTS
        </p>
        <button
          onClick={() => setView("new-scan")}
          className="px-4 py-1.5 bg-[#191919] text-[#ffffff] text-[10px] font-mono tracking-widest hover:bg-[#161616] transition-colors"
        >
          START FIRST SCAN
        </button>
      </div>
    )
  }

  const baseline = useMemo(() => {
    const previous = [...history]
      .reverse()
      .find((entry) => entry.timestamp !== result.timestamp && entry.url === result.url)
    if (!previous) {
      return null
    }

    const previousFingerprints = new Set(previous.vulnerabilities.map((item) => fingerprintFor(item)))
    const currentFingerprints = new Set(result.vulnerabilities.map((item) => fingerprintFor(item)))
    const newCount = [...currentFingerprints].filter((item) => !previousFingerprints.has(item)).length
    const unchangedCount = [...currentFingerprints].filter((item) => previousFingerprints.has(item)).length
    return { previous, newCount, unchangedCount }
  }, [history, result])

  const handleExportPdf = () => {
    if (!hasPdfExport) {
      setActiveTab("license")
      setView("settings")
      return
    }
    exportPDF(result)
  }

  return (
    <div className="animate-fade-in">
      {/* Three-column panel */}
      <div className="border border-[#e5e5e5] bg-[#ffffff] mx-6 mt-6">
        <div className="flex items-center justify-between px-5 py-3 border-b border-[#e5e5e5]">
          <div className="flex items-center gap-3">
            <span className="text-[11px] font-mono tracking-widest text-[#191919] font-bold">
              SCAN RESULTS
            </span>
            <span
              className={`px-2 py-0.5 text-[#ffffff] text-[9px] font-mono tracking-widest font-bold ${
                result.security_score >= 70 ? "bg-[#288034]" : "bg-[#DC2626]"
              }`}
            >
              {result.security_score >= 70 ? "PASS" : "FAIL"}
            </span>
          </div>
          <div className="flex items-center gap-2">
            <span className="px-4 py-1.5 border border-[#e5e5e5] text-[10px] font-mono tracking-widest text-[#525252]">
              {result.scan_type.toUpperCase()}
            </span>
            <button
              onClick={handleExportPdf}
              className={cn(
                "px-4 py-1.5 text-[10px] font-mono tracking-widest transition-colors border flex items-center gap-2",
                hasPdfExport
                  ? "border-[#e0d5c8] bg-[#faf7f4] text-[#8b6914] hover:border-[#c4a44a]"
                  : "border-[#e5e5e5] bg-[#fafafa] text-[#8f8f8f] hover:text-[#191919]"
              )}
            >
              {!hasPdfExport && <Crown size={10} className="text-[#c4a44a]" />}
              EXPORT PDF
            </button>
            <button
              onClick={() => setView("report")}
              className="px-4 py-1.5 bg-[#191919] text-[#ffffff] text-[10px] font-mono tracking-widest hover:bg-[#161616] transition-colors"
            >
              FULL REPORT
            </button>
          </div>
        </div>

        <div className="flex divide-x divide-[#e5e5e5]">
          <ReportCard result={result} />
          <ScanChart history={history} />
          <StatsGrid result={result} />
        </div>
      </div>

      <div className="grid grid-cols-4 gap-4 px-6 pt-4">
        <MetricCard label="AUTH STATUS" value={(result.auth_state?.status ?? "anonymous").toUpperCase()} />
        <MetricCard label="ENDPOINTS" value={String(result.metrics?.endpoint_total ?? result.inventory?.length ?? 0)} />
        <MetricCard label="REQUESTS" value={String(result.metrics?.request_count ?? 0)} />
        <MetricCard
          label="NEW SINCE BASELINE"
          value={baseline ? String(baseline.newCount) : "N/A"}
          detail={baseline ? `${baseline.unchangedCount} unchanged` : "No previous scan"}
        />
      </div>

      {/* Target Intelligence */}
      {result.target_info && (
        <TargetIntelligence info={result.target_info} url={result.url} />
      )}

      {/* Vulnerability cards */}
      <VulnerabilityGrid vulnerabilities={result.vulnerabilities} />
    </div>
  )
}

function MetricCard({ label, value, detail }: { label: string; value: string; detail?: string }) {
  return (
    <div className="border border-[#e5e5e5] bg-[#ffffff] px-4 py-3">
      <p className="text-[10px] font-mono tracking-widest text-[#8f8f8f]">{label}</p>
      <p className="text-[18px] font-mono text-[#191919] font-bold mt-2">{value}</p>
      {detail && <p className="text-[10px] font-mono text-[#8f8f8f] mt-1">{detail}</p>}
    </div>
  )
}
