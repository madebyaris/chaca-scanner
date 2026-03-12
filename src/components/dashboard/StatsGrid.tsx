import { cn } from "@/lib/utils"
import type { ScanResult, Severity } from "@/store/scanStore"

interface StatCellProps {
  label: string
  value: string
  unit?: string
  valueClass?: string
}

function StatCell({ label, value, unit, valueClass }: StatCellProps) {
  return (
    <div className="flex flex-col justify-between p-4 min-h-[80px]">
      <p className="text-[10px] font-mono tracking-wider text-[#8f8f8f]">{label}</p>
      <div className="flex items-baseline gap-1 mt-1">
        <span className={cn("font-bold font-mono text-3xl", valueClass || "text-[#191919]")}>
          {value}
        </span>
        {unit && <span className="text-[11px] font-mono text-[#8f8f8f]">{unit}</span>}
      </div>
    </div>
  )
}

function worstSeverityColor(result: ScanResult): string {
  const severities: Severity[] = result.vulnerabilities.map((v) => v.severity)
  if (severities.includes("critical")) return "text-[#DC2626]"
  if (severities.includes("high")) return "text-[#EA580C]"
  if (severities.includes("medium")) return "text-[#CA8A04]"
  return "text-[#288034]"
}

interface StatsGridProps {
  result: ScanResult
}

export function StatsGrid({ result }: StatsGridProps) {
  const vulnCount = result.vulnerabilities.length
  const apiCount = result.api_exposures.length
  const endpointCount = result.metrics?.endpoint_total ?? result.inventory?.length ?? 0
  const duration = result.scan_duration_ms

  const durationStr =
    duration >= 1000
      ? (duration / 1000).toFixed(1)
      : String(duration)
  const durationUnit = duration >= 1000 ? "s" : "ms"

  return (
    <div className="w-[280px] min-w-[280px] grid grid-cols-2 divide-x divide-y divide-[#e5e5e5]">
      <StatCell
        label="Vulnerabilities"
        value={String(vulnCount)}
        valueClass={vulnCount > 0 ? worstSeverityColor(result) : "text-[#288034]"}
      />
      <StatCell label="API Exposures" value={String(apiCount)} />
      <StatCell label="Endpoints" value={String(endpointCount)} />
      <StatCell label="Scan Duration" value={durationStr} unit={durationUnit} />
    </div>
  )
}
