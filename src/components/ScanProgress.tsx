import { useEffect } from "react"
import { listen } from "@tauri-apps/api/event"
import { useScanStore } from "@/store/scanStore"
import { DotProgressBar } from "./dashboard/DotProgressBar"

export function ScanProgress() {
  const progress = useScanStore((s) => s.progress)

  useEffect(() => {
    const unlisten = listen<{ phase: string; current: number; total: number; message: string }>(
      "scan-progress",
      (event) => {
        useScanStore.getState().setProgress({
          phase: event.payload.phase,
          current: event.payload.current,
          total: event.payload.total,
          message: event.payload.message,
        })
      }
    )

    return () => {
      unlisten.then((fn) => fn())
    }
  }, [])

  const displayProgress = progress ?? {
    phase: "initializing",
    current: 0,
    total: 100,
    message: "Starting scan...",
  }

  const pct = Math.round(displayProgress.current)

  return (
    <div className="px-6 py-6 animate-fade-in">
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
          <span className="text-[11px] font-mono text-[#191919] font-bold">{pct}%</span>
        </div>

        {/* Body */}
        <div className="p-8">
          <div className="flex flex-col items-center gap-6">
            {/* Spinner */}
            <div className="relative w-16 h-16">
              <div className="absolute inset-0 border border-[#e5e5e5] rounded-full" />
              <div className="absolute inset-0 border-2 border-transparent border-t-[#191919] rounded-full animate-spin" />
              <div className="absolute inset-3 border border-[#e5e5e5] rounded-full" />
              <div
                className="absolute inset-3 border-2 border-transparent border-b-[#288034] rounded-full animate-spin"
                style={{ animationDirection: "reverse", animationDuration: "1.5s" }}
              />
            </div>

            {/* Phase */}
            <div className="text-center">
              <p className="text-[11px] font-mono tracking-widest text-[#191919] font-bold uppercase">
                {displayProgress.phase}
              </p>
              <p className="text-[10px] font-mono text-[#8f8f8f] mt-1">
                {displayProgress.message}
              </p>
            </div>

            {/* Dot progress */}
            <div className="w-full max-w-md flex items-center gap-3">
              <DotProgressBar value={pct} total={20} />
              <span className="text-[11px] font-mono text-[#191919] font-bold w-10 text-right">
                {pct}%
              </span>
            </div>

            {/* Bar progress */}
            <div className="w-full max-w-md">
              <div className="h-[3px] bg-[#e5e5e5] w-full overflow-hidden">
                <div
                  className="h-full bg-[#191919] transition-all duration-500"
                  style={{ width: `${pct}%` }}
                />
              </div>
            </div>

            {/* Scan line animation */}
            <div className="w-full max-w-md h-px bg-[#e5e5e5] relative overflow-hidden">
              <div className="absolute inset-0 w-1/3 bg-[#288034] animate-scan-line" />
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}
