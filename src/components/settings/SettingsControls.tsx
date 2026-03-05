import { cn } from "@/lib/utils"
import { Plus, Trash2 } from "lucide-react"

interface RowProps {
  label: string
  description?: string
  children: React.ReactNode
}

function SettingRow({ label, description, children }: RowProps) {
  return (
    <div className="flex items-start justify-between gap-8 py-3 border-b border-[#f0f0f0] last:border-b-0">
      <div className="flex-1 min-w-0">
        <span className="text-[11px] font-mono tracking-wider text-[#191919] font-bold block">
          {label}
        </span>
        {description && (
          <span className="text-[10px] font-mono text-[#8f8f8f] mt-0.5 block leading-relaxed">
            {description}
          </span>
        )}
      </div>
      <div className="shrink-0 flex items-center">{children}</div>
    </div>
  )
}

// --- Toggle ---

interface ToggleRowProps {
  label: string
  description?: string
  value: boolean
  onChange: (v: boolean) => void
}

export function ToggleRow({ label, description, value, onChange }: ToggleRowProps) {
  return (
    <SettingRow label={label} description={description}>
      <button
        onClick={() => onChange(!value)}
        className={cn(
          "relative w-9 h-5 rounded-full transition-colors duration-200",
          value ? "bg-[#191919]" : "bg-[#d4d4d4]"
        )}
        role="switch"
        aria-checked={value}
      >
        <span
          className={cn(
            "absolute top-0.5 left-0.5 w-4 h-4 rounded-full bg-white transition-transform duration-200",
            value && "translate-x-4"
          )}
        />
      </button>
    </SettingRow>
  )
}

// --- Number Input ---

interface InputRowProps {
  label: string
  description?: string
  value: number
  onChange: (v: number) => void
  min?: number
  max?: number
  step?: number
  suffix?: string
}

export function InputRow({
  label,
  description,
  value,
  onChange,
  min = 0,
  max = 999,
  step = 1,
  suffix,
}: InputRowProps) {
  return (
    <SettingRow label={label} description={description}>
      <div className="flex items-center gap-1.5">
        <input
          type="number"
          value={value}
          onChange={(e) => {
            const n = parseFloat(e.target.value)
            if (!isNaN(n)) onChange(Math.min(max, Math.max(min, n)))
          }}
          min={min}
          max={max}
          step={step}
          className="w-20 h-7 px-2 text-[11px] font-mono text-[#191919] bg-[#fafafa] border border-[#e5e5e5] focus:border-[#191919] focus:outline-none transition-colors text-right"
        />
        {suffix && (
          <span className="text-[10px] font-mono text-[#8f8f8f]">{suffix}</span>
        )}
      </div>
    </SettingRow>
  )
}

// --- Slider ---

interface SliderRowProps {
  label: string
  description?: string
  value: number
  onChange: (v: number) => void
  min: number
  max: number
  step?: number
  suffix?: string
}

export function SliderRow({
  label,
  description,
  value,
  onChange,
  min,
  max,
  step = 1,
  suffix,
}: SliderRowProps) {
  return (
    <SettingRow label={label} description={description}>
      <div className="flex items-center gap-3">
        <input
          type="range"
          value={value}
          onChange={(e) => onChange(parseFloat(e.target.value))}
          min={min}
          max={max}
          step={step}
          className="w-28 h-1 appearance-none bg-[#e5e5e5] rounded-full accent-[#191919] cursor-pointer [&::-webkit-slider-thumb]:appearance-none [&::-webkit-slider-thumb]:w-3 [&::-webkit-slider-thumb]:h-3 [&::-webkit-slider-thumb]:rounded-full [&::-webkit-slider-thumb]:bg-[#191919]"
        />
        <span className="text-[11px] font-mono text-[#191919] font-bold w-12 text-right tabular-nums">
          {step < 1 ? value.toFixed(1) : value}
          {suffix}
        </span>
      </div>
    </SettingRow>
  )
}

// --- Select ---

interface SelectRowProps {
  label: string
  description?: string
  value: string
  onChange: (v: string) => void
  options: { value: string; label: string }[]
}

export function SelectRow({ label, description, value, onChange, options }: SelectRowProps) {
  return (
    <SettingRow label={label} description={description}>
      <select
        value={value}
        onChange={(e) => onChange(e.target.value)}
        className="h-7 px-2 pr-6 text-[11px] font-mono text-[#191919] bg-[#fafafa] border border-[#e5e5e5] focus:border-[#191919] focus:outline-none transition-colors appearance-none cursor-pointer bg-[url('data:image/svg+xml;charset=utf-8,%3Csvg%20xmlns%3D%22http%3A%2F%2Fwww.w3.org%2F2000%2Fsvg%22%20width%3D%2210%22%20height%3D%226%22%3E%3Cpath%20d%3D%22M0%200l5%206%205-6z%22%20fill%3D%22%23666%22%2F%3E%3C%2Fsvg%3E')] bg-position-[right_6px_center] bg-no-repeat"
      >
        {options.map((o) => (
          <option key={o.value} value={o.value}>
            {o.label}
          </option>
        ))}
      </select>
    </SettingRow>
  )
}

// --- Text Input ---

interface TextRowProps {
  label: string
  description?: string
  value: string
  onChange: (v: string) => void
  placeholder?: string
}

export function TextRow({ label, description, value, onChange, placeholder }: TextRowProps) {
  return (
    <SettingRow label={label} description={description}>
      <input
        type="text"
        value={value}
        onChange={(e) => onChange(e.target.value)}
        placeholder={placeholder}
        className="w-56 h-7 px-2 text-[11px] font-mono text-[#191919] bg-[#fafafa] border border-[#e5e5e5] focus:border-[#191919] focus:outline-none transition-colors placeholder:text-[#c4c4c4]"
      />
    </SettingRow>
  )
}

// --- TextArea ---

interface TextAreaRowProps {
  label: string
  description?: string
  value: string
  onChange: (v: string) => void
  placeholder?: string
  rows?: number
}

export function TextAreaRow({
  label,
  description,
  value,
  onChange,
  placeholder,
  rows = 3,
}: TextAreaRowProps) {
  return (
    <div className="py-3 border-b border-[#f0f0f0] last:border-b-0">
      <div className="mb-2">
        <span className="text-[11px] font-mono tracking-wider text-[#191919] font-bold block">
          {label}
        </span>
        {description && (
          <span className="text-[10px] font-mono text-[#8f8f8f] mt-0.5 block leading-relaxed">
            {description}
          </span>
        )}
      </div>
      <textarea
        value={value}
        onChange={(e) => onChange(e.target.value)}
        placeholder={placeholder}
        rows={rows}
        className="w-full px-3 py-2 text-[11px] font-mono text-[#191919] bg-[#fafafa] border border-[#e5e5e5] focus:border-[#191919] focus:outline-none transition-colors resize-y placeholder:text-[#c4c4c4] leading-relaxed"
      />
    </div>
  )
}

// --- Key-Value Pairs ---

interface KeyValueRowProps {
  label: string
  description?: string
  pairs: { key: string; value: string }[]
  onChange: (pairs: { key: string; value: string }[]) => void
  keyPlaceholder?: string
  valuePlaceholder?: string
}

export function KeyValueRow({
  label,
  description,
  pairs,
  onChange,
  keyPlaceholder = "Key",
  valuePlaceholder = "Value",
}: KeyValueRowProps) {
  const addPair = () => onChange([...pairs, { key: "", value: "" }])
  const removePair = (idx: number) => onChange(pairs.filter((_, i) => i !== idx))
  const updatePair = (idx: number, field: "key" | "value", val: string) => {
    const next = [...pairs]
    next[idx] = { ...next[idx], [field]: val }
    onChange(next)
  }

  return (
    <div className="py-3 border-b border-[#f0f0f0] last:border-b-0">
      <div className="flex items-start justify-between mb-2">
        <div>
          <span className="text-[11px] font-mono tracking-wider text-[#191919] font-bold block">
            {label}
          </span>
          {description && (
            <span className="text-[10px] font-mono text-[#8f8f8f] mt-0.5 block leading-relaxed">
              {description}
            </span>
          )}
        </div>
        <button
          onClick={addPair}
          className="flex items-center gap-1 text-[10px] font-mono text-[#525252] hover:text-[#191919] transition-colors"
        >
          <Plus size={12} />
          ADD
        </button>
      </div>
      {pairs.length > 0 && (
        <div className="flex flex-col gap-1.5">
          {pairs.map((pair, idx) => (
            <div key={idx} className="flex items-center gap-1.5">
              <input
                type="text"
                value={pair.key}
                onChange={(e) => updatePair(idx, "key", e.target.value)}
                placeholder={keyPlaceholder}
                className="flex-1 h-7 px-2 text-[11px] font-mono text-[#191919] bg-[#fafafa] border border-[#e5e5e5] focus:border-[#191919] focus:outline-none transition-colors placeholder:text-[#c4c4c4]"
              />
              <input
                type="text"
                value={pair.value}
                onChange={(e) => updatePair(idx, "value", e.target.value)}
                placeholder={valuePlaceholder}
                className="flex-1 h-7 px-2 text-[11px] font-mono text-[#191919] bg-[#fafafa] border border-[#e5e5e5] focus:border-[#191919] focus:outline-none transition-colors placeholder:text-[#c4c4c4]"
              />
              <button
                onClick={() => removePair(idx)}
                className="text-[#8f8f8f] hover:text-[#DC2626] transition-colors p-1"
              >
                <Trash2 size={12} />
              </button>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}

// --- Section wrapper ---

interface SectionProps {
  title: string
  children: React.ReactNode
}

export function SettingsSection({ title, children }: SectionProps) {
  return (
    <div className="border border-[#e5e5e5] bg-[#ffffff]">
      <div className="px-5 py-3 border-b border-[#e5e5e5]">
        <span className="text-[11px] font-mono tracking-widest text-[#191919] font-bold">
          {title}
        </span>
      </div>
      <div className="px-5 py-2">{children}</div>
    </div>
  )
}
