import { useState } from "react"
import { cn } from "@/lib/utils"
import { useScanStore, type ScanType } from "@/store/scanStore"
import { useSettingsStore, toScanConfig } from "@/store/settingsStore"
import { startScan } from "@/api/scan"
import { Search, ArrowUpRight, AlertTriangle, FileText } from "lucide-react"
import { DotProgressBar } from "./dashboard/DotProgressBar"

const scanTypes: { value: ScanType; label: string; desc: string }[] = [
  { value: "passive", label: "PASSIVE", desc: "Safe header & response analysis" },
  { value: "active", label: "ACTIVE", desc: "Payload injection testing" },
  { value: "full", label: "FULL SCAN", desc: "Comprehensive security audit" },
]

export function ScanInput() {
  const {
    url,
    setUrl,
    scanType,
    setScanType,
    isScanning,
    startScan: startScanAction,
    setResult,
    setError,
  } = useScanStore()

  const [urlError, setUrlError] = useState("")

  const validateUrl = (value: string): boolean => {
    try {
      new URL(value)
      return true
    } catch {
      return false
    }
  }

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()

    if (!url.trim()) {
      setUrlError("Please enter a URL")
      return
    }

    const normalizedUrl = url.startsWith("http") ? url : `https://${url}`

    if (!validateUrl(normalizedUrl)) {
      setUrlError("Please enter a valid URL")
      return
    }

    setUrlError("")
    startScanAction()

    try {
      const config = toScanConfig(useSettingsStore.getState().settings)
      const result = await startScan(normalizedUrl, scanType, config as Record<string, unknown>)
      setResult(result)
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err))
    }
  }

  return (
    <>
      <div className="border border-[#e5e5e5] bg-[#ffffff] mx-6 mt-6 animate-fade-in">
        {/* Panel header */}
        <div className="flex items-center justify-between px-5 py-3 border-b border-[#e5e5e5]">
          <div className="flex items-center gap-3">
            <span className="text-[11px] font-mono tracking-widest text-[#191919] font-bold">NEW SCAN</span>
            <span className="px-2 py-0.5 bg-[#288034] text-[#ffffff] text-[9px] font-mono tracking-widest font-bold">
              READY
            </span>
          </div>
          <div className="flex items-center gap-2">
            <span className="px-4 py-1.5 border border-[#e5e5e5] text-[10px] font-mono tracking-widest text-[#525252]">
              MACOS
            </span>
            <span className="px-4 py-1.5 bg-[#191919] text-[#ffffff] text-[10px] font-mono tracking-widest">
              v0.5.0
            </span>
          </div>
        </div>

        {/* Panel body */}
        <form onSubmit={handleSubmit} className="flex gap-6">
          {/* Left: Scan checklist */}
          <div className="w-[310px] min-w-[310px] p-5 shrink-0">
            <div className="flex items-start justify-between mb-1">
              <div>
                <p className="text-[11px] font-mono tracking-widest text-[#191919] font-bold">SCAN CHECKLIST</p>
                <p className="text-[10px] font-mono text-[#8f8f8f] mt-0.5">Coverage before deployment</p>
              </div>
              <span className="px-3 py-1 border border-[#e5e5e5] text-[10px] font-mono tracking-widest text-[#525252]">
                OWASP
              </span>
            </div>

            <div className="mt-4 flex flex-col gap-3">
              {[
                { label: "OWASP API TOP 10", value: 100 },
                { label: "API EXPOSURE", value: 100 },
                { label: "DATA LEAK CHECK", value: 100 },
                { label: "ACTIVE + PASSIVE", value: 100 },
              ].map((item) => (
                <div key={item.label} className="flex items-center gap-3">
                  <span className="text-[10px] font-mono tracking-wider text-[#525252] w-[130px] shrink-0">
                    {item.label}
                  </span>
                  <DotProgressBar value={item.value} />
                </div>
              ))}
            </div>
          </div>

          {/* Center: Target input + scan type */}
          <div className="flex-1 min-w-0 p-5 pl-6 border-l border-[#e5e5e5] dot-grid-bg">
            <div className="flex items-start justify-between mb-3">
              <div>
                <p className="text-[11px] font-mono tracking-widest text-[#191919] font-bold">TARGET</p>
                <p className="text-[10px] font-mono text-[#8f8f8f]">Enter URL and choose scan mode</p>
              </div>
              <div className="flex items-center gap-1 bg-[#ffffff] border border-[#e5e5e5] px-1">
                {scanTypes.map((type) => (
                  <button
                    key={type.value}
                    type="button"
                    onClick={() => setScanType(type.value)}
                    disabled={isScanning}
                    className={cn(
                      "px-1.5 py-1 text-[9px] font-mono tracking-widest transition-colors disabled:opacity-50",
                      scanType === type.value
                        ? "text-[#191919] font-bold border-b-2 border-[#191919]"
                        : "text-[#8f8f8f] hover:text-[#191919]"
                    )}
                  >
                    {type.label}
                  </button>
                ))}
              </div>
            </div>

            <div className="bg-[#ffffff]/80">
              <label htmlFor="url" className="block text-[10px] font-mono tracking-widest text-[#525252] font-bold mb-2">
                TARGET URL
              </label>
              <input
                type="text"
                id="url"
                value={url}
                onChange={(e) => {
                  setUrl(e.target.value)
                  setUrlError("")
                }}
                placeholder="https://example.com"
                disabled={isScanning}
                className="block w-full h-[38px] px-3 border border-[#e5e5e5] bg-[#ffffff] text-[12px] font-mono text-[#191919] placeholder-[#8f8f8f] focus:outline-none focus:border-[#191919] transition-colors disabled:opacity-50"
              />
              {urlError && (
                <p className="mt-2 text-[11px] font-mono text-[#DC2626] flex items-center gap-1">
                  <AlertTriangle size={12} />
                  {urlError}
                </p>
              )}

              <p className="text-[10px] font-mono text-[#8f8f8f] mt-3">
                {scanTypes.find((t) => t.value === scanType)?.desc}
              </p>

              <button
                type="submit"
                disabled={isScanning}
                className="mt-4 flex items-center justify-between w-full max-w-[260px] px-4 py-2.5 bg-[#191919] text-[#ffffff] hover:bg-[#161616] transition-colors disabled:opacity-50 disabled:cursor-not-allowed group"
              >
                <div className="flex items-center gap-2">
                  {isScanning ? (
                    <div className="w-4 h-4 border-2 border-[#ffffff] border-t-transparent rounded-full animate-spin" />
                  ) : (
                    <Search size={14} strokeWidth={1.5} />
                  )}
                  <span className="text-[10px] font-mono tracking-widest font-bold">
                    {isScanning ? "SCANNING..." : "START SECURITY SCAN"}
                  </span>
                </div>
                {!isScanning && (
                  <ArrowUpRight size={12} className="text-[#8f8f8f] group-hover:text-[#ffffff] transition-colors" />
                )}
              </button>
            </div>
          </div>

          {/* Right: Stats */}
          <div className="w-[280px] min-w-[280px] shrink-0 pl-6 border-l border-[#e5e5e5] grid grid-cols-2 divide-x divide-y divide-[#e5e5e5]">
            <StatCell label="Target" value={url ? "1" : "0"} valueClass="text-[#288034] text-3xl" />
            <StatCell label="Scan Type" value={scanType.toUpperCase()} valueClass="text-xl" />
            <StatCell label="Profile" value="OWASP" />
            <StatCell label="Engine" value="RUST" />
          </div>
        </form>
      </div>

      {/* Quick-start cards */}
      <div className="grid grid-cols-3 gap-4 px-6 py-6">
        {[
          { label: "LAST SCAN", title: "SECURITY BASELINE", subtitle: "Use previous target and scan type", icon: Search },
          { label: "QUICK TEMPLATE", title: "PASSIVE ONLY", subtitle: "Fast headers and exposure checks", icon: FileText },
          { label: "FULL TEMPLATE", title: "ACTIVE + PASSIVE", subtitle: "Comprehensive vulnerability audit", icon: FileText },
        ].map((card, i) => {
          const Icon = card.icon
          return (
          <div
            key={card.label}
            className="border border-[#e5e5e5] bg-[#ffffff] hover:border-[#191919] transition-colors cursor-pointer group animate-stagger-in"
            style={{ animationDelay: `${i * 80}ms` }}
          >
            <div className="flex items-center justify-between px-4 py-3 border-b border-[#e5e5e5]">
              <span className="text-[10px] font-mono tracking-widest text-[#525252] font-bold">{card.label}</span>
            </div>
            <div className="p-4 flex flex-col gap-3">
              <div className="flex items-start gap-3">
                <div className="w-7 h-7 border border-[#e5e5e5] flex items-center justify-center shrink-0">
                  <Icon size={12} className="text-[#525252]" strokeWidth={1.5} />
                </div>
                <div>
                  <p className="text-[11px] font-mono tracking-wide text-[#191919] font-bold leading-tight">
                    {card.title}
                  </p>
                  <p className="text-[10px] font-mono text-[#8f8f8f] mt-0.5">{card.subtitle}</p>
                </div>
              </div>
            </div>
          </div>
          )
        })}
      </div>
    </>
  )
}

function StatCell({
  label,
  value,
  valueClass,
}: {
  label: string
  value: string
  valueClass?: string
}) {
  return (
    <div className="flex flex-col justify-between p-4 min-h-[80px]">
      <p className="text-[10px] font-mono tracking-wider text-[#8f8f8f]">{label}</p>
      <div className="flex items-baseline gap-1 mt-1">
        <span className={cn("font-bold font-mono text-3xl text-[#191919]", valueClass)}>{value}</span>
      </div>
    </div>
  )
}
