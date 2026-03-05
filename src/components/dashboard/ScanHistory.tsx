import { cn } from "@/lib/utils"
import { useScanStore, type ScanResult } from "@/store/scanStore"
import { Trash2, Shield } from "lucide-react"

function ScoreColor(score: number): string {
  if (score >= 80) return "text-[#288034]"
  if (score >= 60) return "text-[#CA8A04]"
  if (score >= 40) return "text-[#EA580C]"
  return "text-[#DC2626]"
}

function HistoryCard({ result, onClick, index }: { result: ScanResult; onClick: () => void; index: number }) {
  const date = result.timestamp
    ? new Date(result.timestamp).toLocaleDateString("en-US", {
        month: "short",
        day: "numeric",
        hour: "2-digit",
        minute: "2-digit",
      })
    : "Unknown"

  const vulnCount = result.vulnerabilities.length

  return (
    <button
      onClick={onClick}
      className="border border-[#e5e5e5] bg-[#ffffff] hover:border-[#191919] transition-colors cursor-pointer text-left w-full group animate-stagger-in"
      style={{ animationDelay: `${index * 60}ms` }}
    >
      <div className="flex items-center justify-between px-4 py-3 border-b border-[#e5e5e5]">
        <span className="text-[10px] font-mono tracking-widest text-[#525252] font-bold truncate max-w-[200px]">
          {result.url}
        </span>
        <span className="text-[10px] font-mono text-[#8f8f8f]">{date}</span>
      </div>

      <div className="p-4 flex flex-col gap-3">
        <div className="flex items-center gap-3">
          <div className="w-7 h-7 border border-[#e5e5e5] flex items-center justify-center shrink-0">
            <span className={cn("text-[12px] font-mono font-bold", ScoreColor(result.security_score))}>
              {result.security_score}
            </span>
          </div>
          <div>
            <p className="text-[11px] font-mono tracking-wide text-[#191919] font-bold leading-tight">
              SCORE: {result.security_score}/100
            </p>
            <p className="text-[10px] font-mono text-[#8f8f8f] mt-0.5">
              {vulnCount} issue{vulnCount !== 1 ? "s" : ""} &middot; {result.scan_type.toUpperCase()}
            </p>
          </div>
        </div>
      </div>
    </button>
  )
}

export function ScanHistory() {
  const { history, loadResult, clearHistory, setView } = useScanStore()

  if (history.length === 0) {
    return (
      <div className="px-6 py-16 text-center animate-fade-in">
        <div className="w-12 h-12 border border-[#e5e5e5] flex items-center justify-center mx-auto mb-4">
          <Shield size={20} className="text-[#8f8f8f]" strokeWidth={1.5} />
        </div>
        <p className="text-[11px] font-mono tracking-widest text-[#8f8f8f] mb-4">
          NO SCAN HISTORY
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

  const reversed = [...history].reverse()

  return (
    <div className="px-6 py-6 animate-fade-in">
      <div className="flex items-center justify-between mb-4">
        <p className="text-[11px] font-mono tracking-widest text-[#191919] font-bold">
          {history.length} SCAN{history.length !== 1 ? "S" : ""}
        </p>
        <button
          onClick={clearHistory}
          className="flex items-center gap-1 px-3 py-1 border border-[#e5e5e5] text-[10px] font-mono tracking-widest text-[#525252] hover:border-[#191919] hover:text-[#191919] transition-colors"
        >
          <Trash2 size={10} />
          CLEAR
        </button>
      </div>
      <div className="grid grid-cols-3 gap-4">
        {reversed.map((result, i) => (
          <HistoryCard
            key={`${result.url}-${result.timestamp ?? i}`}
            result={result}
            onClick={() => loadResult(result)}
            index={i}
          />
        ))}
      </div>
    </div>
  )
}
