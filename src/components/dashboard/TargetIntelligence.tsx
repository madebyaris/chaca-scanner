import { useState } from "react"
import { cn } from "@/lib/utils"
import type { TargetInfo } from "@/store/scanStore"
import {
  Server,
  Shield,
  Cookie,
  FileText,
  ChevronDown,
  ChevronRight,
  Lock,
  Unlock,
  Layers,
  Network,
  Eye,
} from "lucide-react"

interface TargetIntelligenceProps {
  info: TargetInfo
  url: string
}

function InfoRow({ label, value, mono = true }: { label: string; value: string; mono?: boolean }) {
  if (!value) return null
  return (
    <div className="flex items-start gap-3 py-1.5">
      <span className="text-[10px] font-mono tracking-wider text-[#8f8f8f] w-[140px] shrink-0 uppercase">
        {label}
      </span>
      <span className={cn("text-[11px] text-[#191919] break-all", mono ? "font-mono" : "font-sans")}>
        {value}
      </span>
    </div>
  )
}

function BoolBadge({ value, trueLabel, falseLabel }: { value: boolean; trueLabel: string; falseLabel: string }) {
  return (
    <span
      className={cn(
        "px-2 py-0.5 text-[9px] font-mono tracking-widest font-bold border",
        value
          ? "text-[#288034] bg-[#F0FDF4] border-[#BBF7D0]"
          : "text-[#8f8f8f] bg-[#F5F5F5] border-[#E5E5E5]"
      )}
    >
      {value ? trueLabel : falseLabel}
    </span>
  )
}

function Section({
  icon: Icon,
  title,
  children,
  defaultOpen = true,
}: {
  icon: React.ElementType
  title: string
  children: React.ReactNode
  defaultOpen?: boolean
}) {
  const [open, setOpen] = useState(defaultOpen)

  return (
    <div className="border-b border-[#f0f0f0] last:border-b-0">
      <button
        onClick={() => setOpen(!open)}
        className="w-full flex items-center gap-2.5 px-5 py-3 text-left hover:bg-[#fafafa] transition-colors"
      >
        <Icon size={14} className="text-[#8f8f8f] shrink-0" strokeWidth={1.5} />
        <span className="text-[10px] font-mono tracking-widest text-[#191919] font-bold flex-1">
          {title}
        </span>
        {open ? (
          <ChevronDown size={12} className="text-[#8f8f8f]" />
        ) : (
          <ChevronRight size={12} className="text-[#8f8f8f]" />
        )}
      </button>
      {open && <div className="px-5 pb-4">{children}</div>}
    </div>
  )
}

export function TargetIntelligence({ info }: TargetIntelligenceProps) {
  const hasRedirects = info.redirect_chain.length > 1

  return (
    <div className="border border-[#e5e5e5] bg-[#ffffff] mx-6 mt-4">
      <div className="px-5 py-3 border-b border-[#e5e5e5] flex items-center justify-between">
        <div className="flex items-center gap-2.5">
          <Eye size={14} className="text-[#525252]" strokeWidth={1.5} />
          <span className="text-[11px] font-mono tracking-widest text-[#191919] font-bold">
            TARGET INTELLIGENCE
          </span>
        </div>
        <span className="text-[10px] font-mono text-[#8f8f8f]">
          {info.response_time_ms}ms response
        </span>
      </div>

      {/* Quick summary strip */}
      <div className="flex items-center gap-4 px-5 py-2.5 border-b border-[#f0f0f0] bg-[#fafafa] overflow-x-auto">
        {info.ip_addresses.length > 0 && (
          <QuickChip label="IP" value={info.ip_addresses[0]} />
        )}
        {info.server && <QuickChip label="SERVER" value={info.server} />}
        {info.cdn_provider && <QuickChip label="CDN" value={info.cdn_provider} />}
        {info.hosting_provider && <QuickChip label="HOST" value={info.hosting_provider} />}
        {info.framework && <QuickChip label="FRAMEWORK" value={info.framework} />}
        {info.language && <QuickChip label="LANG" value={info.language} />}
        {info.waf_detected && <QuickChip label="WAF" value={info.waf_detected} />}
        <QuickChip label="HTTP" value={`${info.status_code} ${info.http_version}`} />
      </div>

      {/* Expandable sections */}
      <Section icon={Network} title="NETWORK & DNS">
        <InfoRow label="IP ADDRESSES" value={info.ip_addresses.join(", ")} />
        <InfoRow label="DNS RECORDS" value={info.dns_records.join(", ")} />
        <InfoRow label="STATUS CODE" value={String(info.status_code)} />
        <InfoRow label="HTTP VERSION" value={info.http_version} />
        <InfoRow label="RESPONSE TIME" value={`${info.response_time_ms}ms`} />
        {info.cdn_provider && <InfoRow label="CDN PROVIDER" value={info.cdn_provider} />}
        {info.hosting_provider && <InfoRow label="HOSTING" value={info.hosting_provider} />}
        {info.waf_detected && <InfoRow label="WAF / FIREWALL" value={info.waf_detected} />}
        {info.os_hint && <InfoRow label="OS HINT" value={info.os_hint} />}
        {info.tls_protocol && <InfoRow label="TLS PROTOCOL" value={info.tls_protocol} />}
        {info.tls_issuer && <InfoRow label="TLS ISSUER" value={info.tls_issuer} />}
        {info.favicon_hash && <InfoRow label="FAVICON HASH" value={info.favicon_hash} />}
        {hasRedirects && (
          <div className="mt-2">
            <p className="text-[9px] font-mono tracking-widest text-[#8f8f8f] font-bold mb-1.5">
              REDIRECT CHAIN ({info.redirect_chain.length} hops)
            </p>
            <div className="space-y-1 bg-[#fafafa] border border-[#f0f0f0] p-2">
              {info.redirect_chain.map((hop, i) => (
                <div key={i} className="flex items-center gap-2">
                  <span className="text-[9px] font-mono text-[#8f8f8f] w-4 text-right shrink-0">
                    {i + 1}
                  </span>
                  <span className="text-[10px] font-mono text-[#191919] break-all">{hop}</span>
                </div>
              ))}
            </div>
          </div>
        )}
      </Section>

      <Section icon={Server} title="SERVER & STACK">
        <InfoRow label="SERVER" value={info.server} />
        <InfoRow label="X-POWERED-BY" value={info.powered_by} />
        <InfoRow label="CONTENT-TYPE" value={info.content_type} />
        <InfoRow label="FRAMEWORK" value={info.framework} />
        <InfoRow label="LANGUAGE" value={info.language} />
        {info.meta_generator && <InfoRow label="META GENERATOR" value={info.meta_generator} />}
      </Section>

      {info.technologies.length > 0 && (
        <Section icon={Layers} title={`TECHNOLOGIES DETECTED (${info.technologies.length})`}>
          <div className="flex flex-wrap gap-1.5 mt-1">
            {info.technologies.map((tech, i) => (
              <span
                key={i}
                className="px-2.5 py-1 text-[10px] font-mono text-[#191919] bg-[#fafafa] border border-[#e5e5e5]"
              >
                {tech}
              </span>
            ))}
          </div>
        </Section>
      )}

      {info.cookies.length > 0 && (
        <Section icon={Cookie} title={`COOKIES (${info.cookies.length})`} defaultOpen={false}>
          <div className="space-y-2 mt-1">
            {info.cookies.map((cookie, i) => (
              <div key={i} className="bg-[#fafafa] border border-[#f0f0f0] p-2.5">
                <div className="flex items-center gap-2 mb-1.5">
                  <span className="text-[11px] font-mono text-[#191919] font-bold">
                    {cookie.name}
                  </span>
                  <div className="flex gap-1">
                    {cookie.secure ? (
                      <span className="flex items-center gap-0.5 px-1.5 py-0.5 text-[8px] font-mono tracking-wider text-[#288034] bg-[#F0FDF4] border border-[#BBF7D0]">
                        <Lock size={8} /> SECURE
                      </span>
                    ) : (
                      <span className="flex items-center gap-0.5 px-1.5 py-0.5 text-[8px] font-mono tracking-wider text-[#DC2626] bg-[#FEF2F2] border border-[#FECACA]">
                        <Unlock size={8} /> NO SECURE
                      </span>
                    )}
                    <BoolBadge value={cookie.http_only} trueLabel="HTTPONLY" falseLabel="NO HTTPONLY" />
                    {cookie.same_site && (
                      <span className="px-1.5 py-0.5 text-[8px] font-mono tracking-wider text-[#525252] bg-[#F5F5F5] border border-[#E5E5E5]">
                        {cookie.same_site}
                      </span>
                    )}
                  </div>
                </div>
                <div className="flex gap-4">
                  {cookie.domain && (
                    <span className="text-[9px] font-mono text-[#8f8f8f]">
                      Domain: {cookie.domain}
                    </span>
                  )}
                  {cookie.path && (
                    <span className="text-[9px] font-mono text-[#8f8f8f]">
                      Path: {cookie.path}
                    </span>
                  )}
                </div>
              </div>
            ))}
          </div>
        </Section>
      )}

      <Section icon={Shield} title="SECURITY POSTURE" defaultOpen={false}>
        <div className="flex flex-wrap gap-2 mt-1">
          <BoolBadge value={info.robots_txt_exists} trueLabel="ROBOTS.TXT" falseLabel="NO ROBOTS.TXT" />
          <BoolBadge value={info.sitemap_exists} trueLabel="SITEMAP.XML" falseLabel="NO SITEMAP" />
          <BoolBadge value={info.security_txt_exists} trueLabel="SECURITY.TXT" falseLabel="NO SECURITY.TXT" />
          {info.waf_detected ? (
            <span className="px-2 py-0.5 text-[9px] font-mono tracking-widest font-bold text-[#288034] bg-[#F0FDF4] border border-[#BBF7D0]">
              WAF: {info.waf_detected}
            </span>
          ) : (
            <span className="px-2 py-0.5 text-[9px] font-mono tracking-widest font-bold text-[#CA8A04] bg-[#FEFCE8] border border-[#FEF08A]">
              NO WAF DETECTED
            </span>
          )}
        </div>
      </Section>

      <Section icon={FileText} title="RESPONSE HEADERS" defaultOpen={false}>
        <div className="bg-[#fafafa] border border-[#f0f0f0] p-2.5 max-h-[300px] overflow-y-auto">
          {info.response_headers.map((h, i) => (
            <div key={i} className="flex gap-2 py-0.5 border-b border-[#f0f0f0] last:border-b-0">
              <span className="text-[10px] font-mono text-[#525252] font-bold w-[200px] shrink-0 truncate">
                {h.key}
              </span>
              <span className="text-[10px] font-mono text-[#8f8f8f] break-all">
                {h.value}
              </span>
            </div>
          ))}
        </div>
      </Section>
    </div>
  )
}

function QuickChip({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex items-center gap-1.5 shrink-0">
      <span className="text-[8px] font-mono tracking-widest text-[#8f8f8f] font-bold">
        {label}
      </span>
      <span className="text-[10px] font-mono text-[#191919] font-bold truncate max-w-[200px]">
        {value}
      </span>
    </div>
  )
}
