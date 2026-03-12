import { useEffect, useRef, useState } from "react"
import { listen } from "@tauri-apps/api/event"
import { useScanStore, type ScanProgress as ScanProgressType } from "@/store/scanStore"
import { DotProgressBar } from "./dashboard/DotProgressBar"
import { cancelScan } from "@/api/scan"

function useElapsedTime(startedAt: number | null) {
  const [elapsed, setElapsed] = useState(0)
  useEffect(() => {
    if (!startedAt) return
    const tick = () => setElapsed(Math.floor((Date.now() - startedAt) / 1000))
    tick()
    const id = setInterval(tick, 1000)
    return () => clearInterval(id)
  }, [startedAt])
  return elapsed
}

function formatElapsed(seconds: number): string {
  const m = Math.floor(seconds / 60)
  const s = seconds % 60
  return m > 0 ? `${m}m ${s.toString().padStart(2, "0")}s` : `${s}s`
}

const PHASE_LABELS: Record<string, string> = {
  initializing: "INITIALIZING",
  crawling: "DISCOVERY",
  recon: "RECONNAISSANCE",
  fingerprint: "FINGERPRINTING",
  passive: "PASSIVE ANALYSIS",
  cms: "CMS CHECKS",
  generic: "GENERIC CHECKS",
  services: "SERVICE DETECTION",
  admin: "ADMIN PANELS",
  active: "ACTIVE TESTING",
  analysis: "ANALYSIS",
  complete: "COMPLETE",
}

export function ScanProgress() {
  const progress = useScanStore((s) => s.progress)
  const activityLog = useScanStore((s) => s.activityLog)
  const scanStartedAt = useScanStore((s) => s.scanStartedAt)
  const logEndRef = useRef<HTMLDivElement>(null)
  const elapsed = useElapsedTime(scanStartedAt)

  useEffect(() => {
    const unlisten = listen<ScanProgressType>(
      "scan-progress",
      (event) => {
        useScanStore.getState().setProgress({
          phase: event.payload.phase,
          current: event.payload.current,
          total: event.payload.total,
          message: event.payload.message,
          detail: event.payload.detail,
          findings_so_far: event.payload.findings_so_far,
        })
      }
    )

    return () => {
      unlisten.then((fn) => fn())
    }
  }, [])

  useEffect(() => {
    logEndRef.current?.scrollIntoView({ behavior: "smooth" })
  }, [activityLog.length])

  const displayProgress = progress ?? {
    phase: "initializing",
    current: 0,
    total: 100,
    message: "Starting scan...",
  }

  const pct = Math.round(displayProgress.current)
  const findings = displayProgress.findings_so_far ?? 0
  const phaseLabel = PHASE_LABELS[displayProgress.phase] ?? displayProgress.phase.toUpperCase()

  return (
    <div className="px-6 py-6 animate-fade-in space-y-4">
      {/* Main progress card */}
      <div className="border border-[#e5e5e5] bg-[#ffffff]">
        {/* Header */}
        <div className="flex items-center justify-between px-5 py-3 border-b border-[#e5e5e5]">
          <div className="flex items-center gap-3">
            <span className="text-[11px] font-mono tracking-widest text-[#191919] font-bold">
              SCANNING
            </span>
            <span className="px-2 py-0.5 bg-[#288034] text-[#ffffff] text-[9px] font-mono tracking-widest font-bold animate-pulse">
              LIVE
            </span>
          </div>
          <div className="flex items-center gap-4">
            <span className="text-[10px] font-mono text-[#8f8f8f] tabular-nums">
              {formatElapsed(elapsed)}
            </span>
            <button
              onClick={() => void cancelScan()}
              className="px-3 py-1 border border-[#FECACA] text-[10px] font-mono tracking-widest text-[#DC2626] hover:bg-[#FEF2F2] transition-colors"
            >
              CANCEL
            </button>
            <span className="text-[11px] font-mono text-[#191919] font-bold tabular-nums">{pct}%</span>
          </div>
        </div>

        {/* Body */}
        <div className="p-6">
          <div className="flex flex-col items-center gap-5">
            {/* Spinner + phase */}
            <div className="flex items-center gap-4">
              <div className="relative w-10 h-10 shrink-0">
                <div className="absolute inset-0 border border-[#e5e5e5] rounded-full" />
                <div className="absolute inset-0 border-2 border-transparent border-t-[#191919] rounded-full animate-spin" />
                <div className="absolute inset-1.5 border border-[#e5e5e5] rounded-full" />
                <div
                  className="absolute inset-1.5 border-2 border-transparent border-b-[#288034] rounded-full animate-spin"
                  style={{ animationDirection: "reverse", animationDuration: "1.5s" }}
                />
              </div>
              <div>
                <p className="text-[11px] font-mono tracking-widest text-[#191919] font-bold">
                  {phaseLabel}
                </p>
                <p className="text-[10px] font-mono text-[#8f8f8f] mt-0.5">
                  {displayProgress.message}
                </p>
                {displayProgress.detail && (
                  <p className="text-[9px] font-mono text-[#b0b0b0] mt-0.5 truncate max-w-[400px]">
                    {displayProgress.detail}
                  </p>
                )}
              </div>
            </div>

            {/* Stats row */}
            <div className="flex items-center gap-6">
              <div className="text-center">
                <p className="text-[18px] font-mono font-bold text-[#191919] tabular-nums">{pct}%</p>
                <p className="text-[8px] font-mono tracking-widest text-[#8f8f8f]">PROGRESS</p>
              </div>
              <div className="w-px h-8 bg-[#e5e5e5]" />
              <div className="text-center">
                <p className="text-[18px] font-mono font-bold text-[#191919] tabular-nums">{findings}</p>
                <p className="text-[8px] font-mono tracking-widest text-[#8f8f8f]">FINDINGS</p>
              </div>
              <div className="w-px h-8 bg-[#e5e5e5]" />
              <div className="text-center">
                <p className="text-[18px] font-mono font-bold text-[#191919] tabular-nums">{formatElapsed(elapsed)}</p>
                <p className="text-[8px] font-mono tracking-widest text-[#8f8f8f]">ELAPSED</p>
              </div>
            </div>

            {/* Bar progress */}
            <div className="w-full max-w-lg">
              <div className="flex items-center gap-3">
                <DotProgressBar value={pct} total={20} />
                <span className="text-[10px] font-mono text-[#191919] font-bold w-10 text-right tabular-nums">
                  {pct}%
                </span>
              </div>
              <div className="h-[3px] bg-[#e5e5e5] w-full overflow-hidden mt-2">
                <div
                  className="h-full bg-[#191919] transition-all duration-500"
                  style={{ width: `${pct}%` }}
                />
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Activity log */}
      <div className="border border-[#e5e5e5] bg-[#ffffff]">
        <div className="flex items-center justify-between px-5 py-2.5 border-b border-[#e5e5e5]">
          <span className="text-[10px] font-mono tracking-widest text-[#191919] font-bold">
            ACTIVITY LOG
          </span>
          <span className="text-[9px] font-mono text-[#8f8f8f]">
            {activityLog.length} events
          </span>
        </div>
        <div className="max-h-[240px] overflow-y-auto font-mono text-[10px]">
          {activityLog.map((entry, i) => {
            const ts = scanStartedAt
              ? formatElapsed(Math.floor((entry.timestamp - scanStartedAt) / 1000))
              : ""
            const label = PHASE_LABELS[entry.phase] ?? entry.phase.toUpperCase()
            return (
              <div
                key={i}
                className="flex items-start gap-3 px-5 py-1.5 border-b border-[#f5f5f5] last:border-b-0 hover:bg-[#fafafa]"
              >
                <span className="text-[#b0b0b0] w-[48px] text-right shrink-0 tabular-nums">
                  {ts}
                </span>
                <span className="text-[#288034] w-[100px] shrink-0 tracking-wider font-bold truncate">
                  {label}
                </span>
                <span className="text-[#525252] flex-1 truncate">
                  {entry.message}
                  {entry.detail && (
                    <span className="text-[#b0b0b0] ml-2">{entry.detail}</span>
                  )}
                </span>
              </div>
            )
          })}
          <div ref={logEndRef} />
        </div>
      </div>
    </div>
  )
}
