import { useLicenseStore, type ProFeature } from "@/store/licenseStore"
import { useScanStore } from "@/store/scanStore"
import { Crown, ArrowRight, Sparkles } from "lucide-react"

interface ProGateProps {
  feature: ProFeature
  children: React.ReactNode
  fallback?: React.ReactNode
}

export function ProGate({ feature, children, fallback }: ProGateProps) {
  const isPro = useLicenseStore((s) => s.isPro)

  if (isPro()) return <>{children}</>

  return fallback ? <>{fallback}</> : <ProUpsell feature={feature} />
}

interface ProUpsellProps {
  feature: ProFeature
  compact?: boolean
}

export function ProUpsell({ feature, compact = false }: ProUpsellProps) {
  const getFeatureInfo = useLicenseStore((s) => s.getFeatureInfo)
  const setView = useScanStore((s) => s.setView)
  const info = getFeatureInfo(feature)

  if (compact) {
    return (
      <button
        onClick={() => setView("settings")}
        className="inline-flex items-center gap-1.5 px-2.5 py-1 text-[10px] font-mono tracking-wider bg-gradient-to-r from-[#f5f0eb] to-[#faf7f4] border border-[#e0d5c8] text-[#8b6914] hover:border-[#c4a44a] transition-colors"
      >
        <Crown size={10} className="text-[#c4a44a]" />
        PRO
      </button>
    )
  }

  return (
    <div className="border border-[#e0d5c8] bg-gradient-to-br from-[#fdfbf8] to-[#f8f4ee]">
      <div className="px-5 py-4 flex items-start gap-4">
        <div className="w-8 h-8 bg-gradient-to-br from-[#c4a44a] to-[#8b6914] flex items-center justify-center shrink-0">
          <Sparkles size={14} className="text-white" />
        </div>
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 mb-1">
            <span className="text-[11px] font-mono tracking-widest text-[#191919] font-bold">
              {info.label.toUpperCase()}
            </span>
            <span className="text-[9px] font-mono tracking-widest px-1.5 py-0.5 bg-gradient-to-r from-[#c4a44a] to-[#a08530] text-white font-bold">
              PRO
            </span>
          </div>
          <p className="text-[10px] font-mono text-[#8f8f8f] leading-relaxed mb-3">
            {info.description}
          </p>
          <button
            onClick={() => setView("settings")}
            className="flex items-center gap-2 px-3 py-1.5 text-[10px] font-mono tracking-widest font-bold bg-[#191919] text-white hover:bg-[#333] transition-colors"
          >
            UPGRADE TO PRO
            <ArrowRight size={10} />
          </button>
        </div>
      </div>
      <div className="px-5 py-2 border-t border-[#e0d5c8] bg-[#faf7f4]/50">
        <span className="text-[9px] font-mono text-[#a08530] tracking-wider">
          $5/MONTH OR $120 LIFETIME
        </span>
      </div>
    </div>
  )
}

export function ProBadge() {
  const isPro = useLicenseStore((s) => s.isPro)

  if (!isPro()) return null

  return (
    <span className="inline-flex items-center gap-1 px-2 py-0.5 text-[9px] font-mono tracking-widest font-bold bg-gradient-to-r from-[#c4a44a] to-[#a08530] text-white">
      <Crown size={8} />
      PRO
    </span>
  )
}

export function ProTag() {
  return (
    <span className="inline-flex items-center gap-0.5 px-1.5 py-0.5 text-[8px] font-mono tracking-widest font-bold bg-gradient-to-r from-[#f5f0eb] to-[#faf7f4] border border-[#e0d5c8] text-[#a08530]">
      <Crown size={7} />
      PRO
    </span>
  )
}
