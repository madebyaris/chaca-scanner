import { useEffect, useState } from "react"
import { cn } from "@/lib/utils"
import { useScanStore, type ScanType } from "@/store/scanStore"
import { useSettingsStore, toScanConfig, type HeaderPair } from "@/store/settingsStore"
import { usePresetStore } from "@/store/presetStore"
import { startScan, startFolderScan } from "@/api/scan"
import { open } from "@tauri-apps/plugin-dialog"
import { Search, ArrowUpRight, AlertTriangle, FileText, FolderOpen, SlidersHorizontal, LogIn, Crown, Save, Trash2, Plus } from "lucide-react"
import { DotProgressBar } from "./dashboard/DotProgressBar"
import { exportByFormat } from "@/utils/export"
import { useLicenseStore } from "@/store/licenseStore"
import {
  Sheet,
  SheetContent,
  SheetDescription,
  SheetFooter,
  SheetHeader,
  SheetTitle,
} from "@/components/ui/sheet"

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
    history,
    setView,
  } = useScanStore()
  const { loaded, loadSettings, settings, updateSettings, setActiveTab } = useSettingsStore()
  const { presets, applyPreset } = usePresetStore()
  const hasFeature = useLicenseStore((s) => s.hasFeature)

  const [urlError, setUrlError] = useState("")
  const [headersOpen, setHeadersOpen] = useState(false)
  const [loginOpen, setLoginOpen] = useState(false)
  const [headerDraft, setHeaderDraft] = useState<HeaderPair[]>(settings.customHeaders)
  const [loginDraft, setLoginDraft] = useState({
    enabled: settings.authLoginEnabled,
    loginUrl: settings.authLoginUrl,
    email: settings.authLoginEmail,
    password: settings.authLoginPassword,
    emailField: settings.authLoginEmailField,
    passwordField: settings.authLoginPasswordField,
  })

  useEffect(() => {
    if (!loaded) loadSettings()
  }, [loaded, loadSettings])

  const quickPassive = presets.find((p) => p.id === 'quick-passive')
  const fullScan = presets.find((p) => p.id === 'full-scan')
  const lastResult = history.length > 0 ? history[history.length - 1] : null
  const authFeatureEnabled = hasFeature("authenticated-scanning")
  const pdfExportEnabled = hasFeature("pdf-export")

  const openLicenseUpsell = () => {
    setActiveTab("license")
    setView("settings")
  }

  const openHeadersDrawer = () => {
    if (!authFeatureEnabled) {
      openLicenseUpsell()
      return
    }
    setHeaderDraft(settings.customHeaders)
    setHeadersOpen(true)
  }

  const openLoginDrawer = () => {
    if (!authFeatureEnabled) {
      openLicenseUpsell()
      return
    }
    setLoginDraft({
      enabled: settings.authLoginEnabled,
      loginUrl: settings.authLoginUrl,
      email: settings.authLoginEmail,
      password: settings.authLoginPassword,
      emailField: settings.authLoginEmailField,
      passwordField: settings.authLoginPasswordField,
    })
    setLoginOpen(true)
  }

  const saveHeaderDraft = () => {
    updateSettings({
      customHeaders: headerDraft.filter((pair) => pair.key.trim() || pair.value.trim()),
    })
    setHeadersOpen(false)
  }

  const saveLoginDraft = () => {
    updateSettings({
      authLoginEnabled: loginDraft.enabled,
      authLoginUrl: loginDraft.loginUrl,
      authLoginEmail: loginDraft.email,
      authLoginPassword: loginDraft.password,
      authLoginEmailField: loginDraft.emailField,
      authLoginPasswordField: loginDraft.passwordField,
    })
    setLoginOpen(false)
  }

  const handleFolderScan = async () => {
    try {
      const selected = await open({
        directory: true,
        multiple: false,
      })
      const path = Array.isArray(selected) ? selected[0] : selected
      if (!path || typeof path !== 'string') return
      startScanAction()
      const settings = useSettingsStore.getState().settings
      const result = await startFolderScan(path)
      setResult(result, settings.historyLimit)
      if (settings.autoExportOnComplete && (settings.defaultExportFormat !== "pdf" || pdfExportEnabled)) {
        exportByFormat(result, settings.defaultExportFormat)
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err))
    }
  }

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

    if (
      settings.authLoginEnabled &&
      (
        !settings.authLoginUrl.trim() ||
        !settings.authLoginEmail.trim() ||
        !settings.authLoginPassword
      )
    ) {
      setUrlError("Login First is enabled. Add login URL, email, and password before scanning.")
      return
    }

    setUrlError("")
    startScanAction()

    try {
      const settings = useSettingsStore.getState().settings
      const config = toScanConfig(settings)
      const result = await startScan(normalizedUrl, scanType, config as Record<string, unknown>)
      setResult(result, settings.historyLimit)
      if (settings.autoExportOnComplete && (settings.defaultExportFormat !== "pdf" || pdfExportEnabled)) {
        exportByFormat(result, settings.defaultExportFormat)
      }
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
              v0.6.0
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
              <div className="mb-3 flex flex-wrap items-center gap-2">
                <ProActionButton
                  label="QUICK HEADERS"
                  description="Set tokens, cookies, or auth headers"
                  icon={SlidersHorizontal}
                  onClick={openHeadersDrawer}
                  enabled={authFeatureEnabled}
                />
                <ProActionButton
                  label="LOGIN FIRST"
                  description="Authenticate with email + password first"
                  icon={LogIn}
                  onClick={openLoginDrawer}
                  enabled={authFeatureEnabled}
                />
              </div>
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
              {(settings.authLoginEnabled || settings.customHeaders.length > 0) && (
                <div className="mt-3 border border-[#e5e5e5] bg-[#fafafa] px-3 py-2">
                  <div className="flex flex-wrap items-center gap-2">
                    {settings.authLoginEnabled && (
                      <span className="inline-flex items-center gap-1 text-[10px] font-mono tracking-wider text-[#8b6914] font-bold">
                        <Crown size={10} className="text-[#c4a44a]" />
                        LOGIN FIRST
                      </span>
                    )}
                    {settings.customHeaders.length > 0 && (
                      <span className="text-[10px] font-mono text-[#525252]">
                        {settings.customHeaders.length} custom header{settings.customHeaders.length > 1 ? "s" : ""} ready
                      </span>
                    )}
                  </div>
                  {settings.authLoginEnabled && (
                    <p className="text-[10px] font-mono text-[#8f8f8f] mt-1">
                      Chaca will sign in at {settings.authLoginUrl || "your login URL"} before starting the scan.
                    </p>
                  )}
                </div>
              )}

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
      <div className="grid grid-cols-4 gap-4 px-6 py-6">
        <QuickCard
          label="LAST SCAN"
          title={lastResult ? "SECURITY BASELINE" : "NO PREVIOUS SCAN"}
          subtitle={lastResult ? `Use ${lastResult.url}` : "Run a scan first"}
          icon={Search}
          disabled={!lastResult}
          onClick={() => {
            if (lastResult) {
              setUrl(lastResult.url)
              setScanType(lastResult.scan_type)
            }
          }}
          index={0}
        />
        <QuickCard
          label="QUICK TEMPLATE"
          title={quickPassive?.name ?? "PASSIVE ONLY"}
          subtitle={quickPassive?.description ?? "Fast headers and exposure checks"}
          icon={FileText}
          onClick={() => quickPassive && applyPreset(quickPassive.id)}
          index={1}
        />
        <QuickCard
          label="FULL TEMPLATE"
          title={fullScan?.name ?? "ACTIVE + PASSIVE"}
          subtitle={fullScan?.description ?? "Comprehensive vulnerability audit"}
          icon={FileText}
          onClick={() => fullScan && applyPreset(fullScan.id)}
          index={2}
        />
        <QuickCard
          label="SCAN FOLDER"
          title="LOCAL PROJECT"
          subtitle="Secrets, config exposure, endpoint inventory"
          icon={FolderOpen}
          onClick={handleFolderScan}
          index={3}
        />
      </div>

      <Sheet open={headersOpen} onOpenChange={setHeadersOpen}>
        <SheetContent side="right" className="w-[560px] max-w-[560px] bg-[#ffffff] border-l border-[#e5e5e5] p-0">
          <SheetHeader className="border-b border-[#e5e5e5] px-5 py-4">
            <SheetTitle className="text-[12px] font-mono tracking-widest text-[#191919] font-bold flex items-center gap-2">
              <SlidersHorizontal size={14} />
              QUICK HEADERS
            </SheetTitle>
            <SheetDescription className="text-[10px] font-mono text-[#8f8f8f] leading-relaxed">
              Add request headers for authenticated APIs, tokens, or session cookies without leaving New Scan.
            </SheetDescription>
          </SheetHeader>
          <div className="px-5 py-4 space-y-3">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-[11px] font-mono tracking-wider text-[#191919] font-bold">HEADERS</p>
                <p className="text-[10px] font-mono text-[#8f8f8f] mt-0.5">
                  Authorization and Cookie values are redacted in scan summaries.
                </p>
              </div>
              <button
                type="button"
                onClick={() => setHeaderDraft([...headerDraft, { key: "", value: "" }])}
                className="flex items-center gap-1 text-[10px] font-mono tracking-wider text-[#525252] hover:text-[#191919]"
              >
                <Plus size={12} />
                ADD HEADER
              </button>
            </div>
            <div className="space-y-2">
              {headerDraft.length === 0 && (
                <div className="border border-dashed border-[#e5e5e5] px-4 py-5 text-[10px] font-mono text-[#8f8f8f]">
                  No headers configured yet.
                </div>
              )}
              {headerDraft.map((pair, index) => (
                <div key={`${pair.key}-${index}`} className="grid grid-cols-[1fr_1fr_auto] gap-2">
                  <input
                    type="text"
                    value={pair.key}
                    onChange={(e) => {
                      const next = [...headerDraft]
                      next[index] = { ...next[index], key: e.target.value }
                      setHeaderDraft(next)
                    }}
                    placeholder="Header name"
                    className="h-9 px-3 text-[11px] font-mono text-[#191919] bg-[#fafafa] border border-[#e5e5e5] focus:border-[#191919] focus:outline-none"
                  />
                  <input
                    type="text"
                    value={pair.value}
                    onChange={(e) => {
                      const next = [...headerDraft]
                      next[index] = { ...next[index], value: e.target.value }
                      setHeaderDraft(next)
                    }}
                    placeholder="Header value"
                    className="h-9 px-3 text-[11px] font-mono text-[#191919] bg-[#fafafa] border border-[#e5e5e5] focus:border-[#191919] focus:outline-none"
                  />
                  <button
                    type="button"
                    onClick={() => setHeaderDraft(headerDraft.filter((_, idx) => idx !== index))}
                    className="h-9 w-9 border border-[#e5e5e5] text-[#8f8f8f] hover:text-[#DC2626] hover:border-[#FECACA]"
                    aria-label="Remove header"
                  >
                    <Trash2 size={12} className="mx-auto" />
                  </button>
                </div>
              ))}
            </div>
          </div>
          <SheetFooter className="border-t border-[#e5e5e5] px-5 py-4">
            <button
              type="button"
              onClick={saveHeaderDraft}
              className="flex items-center justify-center gap-2 px-4 py-2 bg-[#191919] text-white text-[10px] font-mono tracking-widest font-bold hover:bg-[#333]"
            >
              <Save size={12} />
              SAVE HEADERS
            </button>
          </SheetFooter>
        </SheetContent>
      </Sheet>

      <Sheet open={loginOpen} onOpenChange={setLoginOpen}>
        <SheetContent side="right" className="w-[560px] max-w-[560px] bg-[#ffffff] border-l border-[#e5e5e5] p-0">
          <SheetHeader className="border-b border-[#e5e5e5] px-5 py-4">
            <SheetTitle className="text-[12px] font-mono tracking-widest text-[#191919] font-bold flex items-center gap-2">
              <LogIn size={14} />
              LOGIN FIRST
            </SheetTitle>
            <SheetDescription className="text-[10px] font-mono text-[#8f8f8f] leading-relaxed">
              Chaca will submit your login form once, keep the authenticated session cookies, then scan with that session.
            </SheetDescription>
          </SheetHeader>
          <div className="px-5 py-4 space-y-4">
            <label className="flex items-center justify-between gap-4 border border-[#e5e5e5] px-4 py-3">
              <div>
                <p className="text-[11px] font-mono tracking-wider text-[#191919] font-bold">ENABLE AUTHENTICATED SCAN</p>
                <p className="text-[10px] font-mono text-[#8f8f8f] mt-0.5">Use a login step before the scan starts.</p>
              </div>
              <button
                type="button"
                onClick={() => setLoginDraft((state) => ({ ...state, enabled: !state.enabled }))}
                className={cn(
                  "relative w-10 h-5 rounded-full transition-colors",
                  loginDraft.enabled ? "bg-[#191919]" : "bg-[#d4d4d4]"
                )}
                aria-label="Toggle authenticated scan"
              >
                <span
                  className={cn(
                    "absolute top-0.5 left-0.5 h-4 w-4 rounded-full bg-white transition-transform",
                    loginDraft.enabled && "translate-x-5"
                  )}
                />
              </button>
            </label>
            <DrawerField
              label="LOGIN URL"
              description="Full URL or relative path for the login form endpoint."
              value={loginDraft.loginUrl}
              onChange={(value) => setLoginDraft((state) => ({ ...state, loginUrl: value }))}
              placeholder="https://app.example.com/login"
            />
            <DrawerField
              label="EMAIL"
              description="Account email or username used to sign in."
              value={loginDraft.email}
              onChange={(value) => setLoginDraft((state) => ({ ...state, email: value }))}
              placeholder="security@example.com"
            />
            <DrawerField
              label="PASSWORD"
              description="Saved for this session only. It is intentionally not written to settings.json."
              value={loginDraft.password}
              onChange={(value) => setLoginDraft((state) => ({ ...state, password: value }))}
              placeholder="••••••••••••"
              type="password"
            />
            <div className="grid grid-cols-2 gap-3">
              <DrawerField
                label="EMAIL FIELD"
                description="Form field name sent for the email."
                value={loginDraft.emailField}
                onChange={(value) => setLoginDraft((state) => ({ ...state, emailField: value }))}
                placeholder="email"
              />
              <DrawerField
                label="PASSWORD FIELD"
                description="Form field name sent for the password."
                value={loginDraft.passwordField}
                onChange={(value) => setLoginDraft((state) => ({ ...state, passwordField: value }))}
                placeholder="password"
              />
            </div>
          </div>
          <SheetFooter className="border-t border-[#e5e5e5] px-5 py-4">
            <button
              type="button"
              onClick={saveLoginDraft}
              className="flex items-center justify-center gap-2 px-4 py-2 bg-[#191919] text-white text-[10px] font-mono tracking-widest font-bold hover:bg-[#333]"
            >
              <Save size={12} />
              SAVE LOGIN FLOW
            </button>
          </SheetFooter>
        </SheetContent>
      </Sheet>
    </>
  )
}

function ProActionButton({
  label,
  description,
  icon: Icon,
  onClick,
  enabled,
}: {
  label: string
  description: string
  icon: React.ComponentType<{ size?: number; className?: string }>
  onClick: () => void
  enabled: boolean
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      className={cn(
        "flex items-center gap-3 border px-3 py-2 text-left transition-colors",
        enabled
          ? "border-[#e0d5c8] bg-gradient-to-r from-[#fdfbf8] to-[#f8f4ee] hover:border-[#c4a44a]"
          : "border-[#e5e5e5] bg-[#fafafa] hover:border-[#191919]"
      )}
    >
      <div className="flex h-8 w-8 items-center justify-center border border-[#e5e5e5] bg-white">
        <Icon size={14} className={enabled ? "text-[#a08530]" : "text-[#525252]"} />
      </div>
      <div className="min-w-0">
        <div className="flex items-center gap-2">
          <span className="text-[10px] font-mono tracking-widest text-[#191919] font-bold">{label}</span>
          <span className="inline-flex items-center gap-1 px-1.5 py-0.5 text-[8px] font-mono tracking-widest font-bold bg-gradient-to-r from-[#c4a44a] to-[#a08530] text-white">
            <Crown size={7} />
            PRO
          </span>
        </div>
        <p className="text-[10px] font-mono text-[#8f8f8f] mt-0.5">{description}</p>
      </div>
    </button>
  )
}

function DrawerField({
  label,
  description,
  value,
  onChange,
  placeholder,
  type = "text",
}: {
  label: string
  description: string
  value: string
  onChange: (value: string) => void
  placeholder?: string
  type?: "text" | "password"
}) {
  return (
    <div>
      <label className="text-[10px] font-mono tracking-widest text-[#191919] font-bold block">{label}</label>
      <p className="text-[10px] font-mono text-[#8f8f8f] mt-1 mb-2 leading-relaxed">{description}</p>
      <input
        type={type}
        value={value}
        onChange={(e) => onChange(e.target.value)}
        placeholder={placeholder}
        className="w-full h-9 px-3 text-[11px] font-mono text-[#191919] bg-[#fafafa] border border-[#e5e5e5] focus:border-[#191919] focus:outline-none placeholder:text-[#c4c4c4]"
      />
    </div>
  )
}

function QuickCard({
  label,
  title,
  subtitle,
  icon: Icon,
  onClick,
  disabled,
  index,
}: {
  label: string
  title: string
  subtitle: string
  icon: React.ComponentType<{ size?: number; strokeWidth?: number; className?: string }>
  onClick?: () => void
  disabled?: boolean
  index: number
}) {
  return (
    <div
      role="button"
      tabIndex={disabled ? -1 : 0}
      onClick={disabled ? undefined : onClick}
      onKeyDown={(e) => !disabled && (e.key === "Enter" || e.key === " ") && onClick?.()}
      className={cn(
        "border border-[#e5e5e5] bg-[#ffffff] transition-colors group animate-stagger-in",
        disabled ? "opacity-60 cursor-default" : "hover:border-[#191919] cursor-pointer"
      )}
      style={{ animationDelay: `${index * 80}ms` }}
    >
      <div className="flex items-center justify-between px-4 py-3 border-b border-[#e5e5e5]">
        <span className="text-[10px] font-mono tracking-widest text-[#525252] font-bold">{label}</span>
      </div>
      <div className="p-4 flex flex-col gap-3">
        <div className="flex items-start gap-3">
          <div className="w-7 h-7 border border-[#e5e5e5] flex items-center justify-center shrink-0">
            <Icon size={12} className="text-[#525252]" strokeWidth={1.5} />
          </div>
          <div>
            <p className="text-[11px] font-mono tracking-wide text-[#191919] font-bold leading-tight">
              {title}
            </p>
            <p className="text-[10px] font-mono text-[#8f8f8f] mt-0.5 truncate max-w-[180px]">{subtitle}</p>
          </div>
        </div>
      </div>
    </div>
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
