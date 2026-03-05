import { useScanStore } from "@/store/scanStore"
import { ReportCard } from "./ReportCard"
import { ScanChart } from "./ScanChart"
import { StatsGrid } from "./StatsGrid"
import { VulnerabilityGrid } from "./VulnerabilityGrid"
import { TargetIntelligence } from "./TargetIntelligence"
import { Search } from "lucide-react"

export function ScanDashboard() {
  const { result, history, setView } = useScanStore()

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

      {/* Target Intelligence */}
      {result.target_info && (
        <TargetIntelligence info={result.target_info} url={result.url} />
      )}

      {/* Vulnerability cards */}
      <VulnerabilityGrid vulnerabilities={result.vulnerabilities} />
    </div>
  )
}
