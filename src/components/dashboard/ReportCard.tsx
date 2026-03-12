import { DotProgressBar } from "./DotProgressBar"
import type { ScanResult } from "@/store/scanStore"

interface ReportCardProps {
  result: ScanResult
}

function computeScores(result: ScanResult) {
  const score = result.security_score

  const headerVulns = result.vulnerabilities.filter(
    (v) =>
      v.category.toLowerCase().includes("header") ||
      v.category.toLowerCase().includes("hsts") ||
      v.category.toLowerCase().includes("csp")
  )
  const headerScore = Math.max(0, 100 - headerVulns.length * 15)
  const apiScore = Math.max(0, 100 - result.api_exposures.length * 10)
  const dataScore = Math.max(0, 100 - result.data_exposures.length * 12)
  const coverageScore = result.metrics?.endpoint_total
    ? Math.min(
        100,
        Math.round(
          ((result.metrics.active_candidate_total || result.metrics.endpoint_total) /
            result.metrics.endpoint_total) *
            100
        )
      )
    : 0

  return [
    { label: "SECURITY SCORE", value: score },
    { label: "HEADER SECURITY", value: headerScore },
    { label: "API SECURITY", value: apiScore },
    { label: "DATA PROTECTION", value: dataScore },
    { label: "ACTIVE COVERAGE", value: coverageScore },
  ]
}

export function ReportCard({ result }: ReportCardProps) {
  const scores = computeScores(result)
  const scanDate = result.timestamp
    ? new Date(result.timestamp).toLocaleDateString("en-US", { month: "short", day: "numeric" })
    : "Just now"

  return (
    <div className="w-[310px] min-w-[310px] p-5">
      <div className="flex items-start justify-between mb-1">
        <div>
          <p className="text-[11px] font-mono tracking-widest text-[#191919] font-bold">
            REPORT CARD
          </p>
          <p className="text-[10px] font-mono text-[#8f8f8f] mt-0.5">
            Last scanned {scanDate}
          </p>
        </div>
        <span className="px-3 py-1 border border-[#e5e5e5] text-[10px] font-mono tracking-widest text-[#525252]">
          {result.scan_type.toUpperCase()}
        </span>
      </div>

      <div className="mt-4 flex flex-col gap-3">
        {scores.map((item) => (
          <div key={item.label} className="flex items-center gap-3">
            <span className="text-[10px] font-mono tracking-wider text-[#525252] w-[130px] shrink-0">
              {item.label}
            </span>
            <DotProgressBar value={item.value} />
            <span className="text-[11px] font-mono text-[#191919] font-bold w-9 text-right">
              {item.value}%
            </span>
          </div>
        ))}
      </div>
    </div>
  )
}
