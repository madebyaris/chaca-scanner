import { useScanStore } from "@/store/scanStore"
import { Search, Download, Share2, Clock, ArrowUpRight } from "lucide-react"

const VIEW_LABELS: Record<string, string> = {
  "new-scan": "NEW SCAN",
  scanning: "SCANNING",
  dashboard: "DASHBOARD",
  report: "FULL REPORT",
  "api-exposure": "API EXPOSURE",
  "data-exposure": "DATA EXPOSURE",
  history: "SCAN HISTORY",
  settings: "SETTINGS",
  about: "ABOUT",
  documentation: "DOCUMENTATION",
}

interface ActionButtonProps {
  label: string
  icon: React.ElementType
  onClick: () => void
}

function ActionButton({ label, icon: Icon, onClick }: ActionButtonProps) {
  return (
    <button
      onClick={onClick}
      className="flex flex-col items-start justify-between w-[150px] h-[100px] border border-[#e5e5e5] bg-[#f7f7f7] hover:bg-[#ffffff] hover:border-[#191919] transition-colors p-4 group"
    >
      <Icon
        size={22}
        className="text-[#525252] group-hover:text-[#191919] transition-colors"
        strokeWidth={1.5}
      />
      <div className="flex items-center justify-between w-full">
        <span className="text-[10px] font-mono tracking-widest text-[#191919] font-bold">
          {label}
        </span>
        <ArrowUpRight
          size={12}
          className="text-[#8f8f8f] group-hover:text-[#191919] transition-colors"
        />
      </div>
    </button>
  )
}

export function ScanHeader() {
  const { view, result, url, setView } = useScanStore()

  const viewLabel = VIEW_LABELS[view] || "CHACA"

  const title = result
    ? result.url
    : view === "new-scan"
      ? "New Security Scan"
      : "Chaca"

  const meta = result
    ? [
        { key: "Scan Type", value: result.scan_type.toUpperCase() },
        { key: "Duration", value: `${result.scan_duration_ms}ms` },
        { key: "Score", value: `${result.security_score}/100` },
      ]
    : url
      ? [{ key: "Target", value: url }]
      : null

  return (
    <div className="border-b border-[#e5e5e5] bg-[#ffffff] px-8 pt-6 pb-6">
      <div className="flex items-center gap-2 mb-4">
        <span className="text-[11px] font-mono tracking-widest text-[#8f8f8f] uppercase">
          CHACA
        </span>
        <span className="text-[11px] text-[#8f8f8f]">/</span>
        <span className="text-[11px] font-mono tracking-widest text-[#8f8f8f] uppercase">
          {viewLabel}
        </span>
      </div>

      <div className="flex items-start justify-between gap-6">
        <div>
          <h1 className="text-[28px] font-bold text-[#191919] leading-tight mb-3 font-sans">
            {title}
          </h1>
          {meta && (
            <div className="flex flex-col gap-0.5 text-[12px] font-mono text-[#525252]">
              {meta.map(({ key, value }) => (
                <div key={key} className="flex gap-2">
                  <span className="text-[#8f8f8f]">{key}:</span>
                  <span>{value}</span>
                </div>
              ))}
            </div>
          )}
        </div>
        <div className="flex gap-3 shrink-0">
          <ActionButton
            label="NEW SCAN"
            icon={Search}
            onClick={() => setView("new-scan")}
          />
          <ActionButton
            label="EXPORT REPORT"
            icon={Download}
            onClick={() => {
              if (!result) return
              const blob = new Blob([JSON.stringify(result, null, 2)], { type: "application/json" })
              const a = document.createElement("a")
              a.href = URL.createObjectURL(blob)
              a.download = `chaca-${result.url.replace(/[^a-z0-9]/gi, "_")}.json`
              a.click()
            }}
          />
          <ActionButton
            label="SHARE RESULTS"
            icon={Share2}
            onClick={() => {
              if (!result) return
              navigator.clipboard.writeText(JSON.stringify(result, null, 2))
            }}
          />
          <ActionButton
            label="VIEW HISTORY"
            icon={Clock}
            onClick={() => setView("history")}
          />
        </div>
      </div>
    </div>
  )
}
