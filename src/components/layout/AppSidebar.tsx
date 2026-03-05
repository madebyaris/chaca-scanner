import { cn } from "@/lib/utils"
import { useScanStore, type View } from "@/store/scanStore"
import { useSettingsStore, type SettingsTab } from "@/store/settingsStore"
import { PanelLeft, MoreHorizontal } from "lucide-react"

interface NavItem {
  label: string
  view: View
  settingsTab?: SettingsTab
}

interface NavSection {
  label: string
  items: NavItem[]
}

const navSections: NavSection[] = [
  {
    label: "SCAN",
    items: [
      { label: "NEW SCAN", view: "new-scan" },
      { label: "SCAN HISTORY", view: "history" },
    ],
  },
  {
    label: "ANALYZE",
    items: [
      { label: "DASHBOARD", view: "dashboard" },
      { label: "FULL REPORT", view: "report" },
      { label: "API EXPOSURE", view: "api-exposure" },
      { label: "DATA EXPOSURE", view: "data-exposure" },
    ],
  },
  {
    label: "CONFIGURE",
    items: [
      { label: "SCAN SETTINGS", view: "settings", settingsTab: "network" },
      { label: "OWASP RULES", view: "settings", settingsTab: "owasp" },
      { label: "EXPORT SETTINGS", view: "settings", settingsTab: "export" },
    ],
  },
  {
    label: "HELP",
    items: [
      { label: "ABOUT", view: "about" },
      { label: "DOCUMENTATION", view: "documentation" },
    ],
  },
]

function SectionIcon({ label }: { label: string }) {
  if (label === "SCAN") {
    return (
      <svg width="14" height="14" viewBox="0 0 14 14" fill="none" className="text-[#525252]">
        <circle cx="7" cy="7" r="6" stroke="currentColor" strokeWidth="1.2" />
        <circle cx="7" cy="7" r="2" fill="currentColor" />
      </svg>
    )
  }
  if (label === "ANALYZE") {
    return (
      <svg width="14" height="14" viewBox="0 0 14 14" fill="none" className="text-[#525252]">
        <rect x="1" y="1" width="5" height="5" stroke="currentColor" strokeWidth="1.2" />
        <rect x="8" y="1" width="5" height="5" stroke="currentColor" strokeWidth="1.2" />
        <rect x="4.5" y="8" width="5" height="5" stroke="currentColor" strokeWidth="1.2" />
      </svg>
    )
  }
  if (label === "CONFIGURE") {
    return (
      <svg width="14" height="14" viewBox="0 0 14 14" fill="none" className="text-[#525252]">
        <circle cx="7" cy="7" r="5" stroke="currentColor" strokeWidth="1.2" />
        <path d="M7 4V7L9 9" stroke="currentColor" strokeWidth="1.2" strokeLinecap="round" />
      </svg>
    )
  }
  return (
    <svg width="14" height="14" viewBox="0 0 14 14" fill="none" className="text-[#525252]">
      <path d="M7 1L13 4.5V9.5L7 13L1 9.5V4.5L7 1Z" stroke="currentColor" strokeWidth="1.2" />
    </svg>
  )
}

function LogoIcon() {
  return (
    <svg width="24" height="24" viewBox="0 0 24 24" fill="none">
      <rect x="2" y="2" width="9" height="9" fill="#191919" />
      <rect x="13" y="2" width="4" height="4" fill="#191919" />
      <rect x="19" y="2" width="4" height="4" fill="#191919" />
      <rect x="13" y="8" width="4" height="4" fill="#191919" />
      <rect x="2" y="13" width="4" height="4" fill="#191919" />
      <rect x="2" y="19" width="4" height="4" fill="#191919" />
      <rect x="8" y="13" width="4" height="9" fill="#191919" />
    </svg>
  )
}

export function AppSidebar() {
  const { view, setView, sidebarCollapsed, toggleSidebar } = useScanStore()
  const { activeTab: currentSettingsTab, setActiveTab } = useSettingsStore()

  return (
    <aside
      className={cn(
        "h-screen bg-[#ffffff] border-r border-[#e5e5e5] flex flex-col font-mono transition-all duration-200 select-none",
        sidebarCollapsed ? "w-[60px] min-w-[60px]" : "w-[220px] min-w-[220px]"
      )}
    >
      <div className="flex items-center justify-between px-4 py-4 border-b border-[#e5e5e5]">
        <div className="flex items-center gap-2">
          <LogoIcon />
          {!sidebarCollapsed && (
            <span className="text-[10px] font-mono tracking-widest font-bold text-[#191919] whitespace-nowrap">
              CHACA
            </span>
          )}
        </div>
        <button
          onClick={toggleSidebar}
          className="text-[#8f8f8f] hover:text-[#191919] transition-colors"
          aria-label="Toggle sidebar"
        >
          <PanelLeft size={16} />
        </button>
      </div>

      <nav className="flex-1 overflow-y-auto py-3">
        {navSections.map((section) => (
          <div key={section.label} className="mb-1">
            <div className="flex items-center gap-2 px-4 py-2">
              <SectionIcon label={section.label} />
              {!sidebarCollapsed && (
                <span className="text-[10px] font-bold tracking-widest text-[#525252] whitespace-nowrap">
                  {section.label}
                </span>
              )}
            </div>
            {!sidebarCollapsed && (
              <ul>
                {section.items.map((item) => {
                  const isActive = item.view === view && (
                    !item.settingsTab || currentSettingsTab === item.settingsTab
                  )
                  return (
                    <li key={item.label}>
                      <button
                        onClick={() => {
                          if (item.settingsTab) setActiveTab(item.settingsTab)
                          setView(item.view)
                        }}
                        className={cn(
                          "flex items-center gap-2 pl-8 pr-4 py-1.5 text-[11px] tracking-widest font-mono transition-colors w-full text-left relative whitespace-nowrap",
                          isActive
                            ? "text-[#191919] font-bold"
                            : "text-[#707070] hover:text-[#191919]"
                        )}
                      >
                        {isActive && (
                          <span className="absolute left-4 top-1/2 -translate-y-1/2 w-1 h-4 bg-[#191919]" />
                        )}
                        {item.label}
                        {isActive && (
                          <span className="ml-1 inline-block w-2 h-2 bg-[#191919]" />
                        )}
                      </button>
                    </li>
                  )
                })}
              </ul>
            )}
          </div>
        ))}
      </nav>

      <div className="border-t border-[#e5e5e5] px-4 py-3 flex items-center justify-between">
        {!sidebarCollapsed ? (
          <>
            <span className="text-[12px] text-[#191919] font-mono">Chaca v0.5</span>
            <button className="text-[#8f8f8f] hover:text-[#191919] transition-colors" aria-label="More options">
              <MoreHorizontal size={16} />
            </button>
          </>
        ) : (
          <button className="text-[#8f8f8f] hover:text-[#191919] transition-colors mx-auto" aria-label="More options">
            <MoreHorizontal size={16} />
          </button>
        )}
      </div>
    </aside>
  )
}
