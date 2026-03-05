import { useState } from "react"
import {
  LineChart,
  Line,
  XAxis,
  YAxis,
  ResponsiveContainer,
} from "recharts"
import { cn } from "@/lib/utils"
import type { ScanResult } from "@/store/scanStore"

interface ScanChartProps {
  history: ScanResult[]
}

type TimeRange = "LAST 5" | "LAST 10" | "ALL"
const timeRanges: TimeRange[] = ["LAST 5", "LAST 10", "ALL"]

export function ScanChart({ history }: ScanChartProps) {
  const [range, setRange] = useState<TimeRange>("LAST 5")

  const sliced =
    range === "LAST 5"
      ? history.slice(-5)
      : range === "LAST 10"
        ? history.slice(-10)
        : history

  const data = sliced.map((r, i) => {
    const date = r.timestamp
      ? new Date(r.timestamp).toLocaleDateString("en-US", { month: "numeric", day: "numeric" })
      : `#${i + 1}`
    return {
      date,
      vulns: r.vulnerabilities.length,
      score: r.security_score,
    }
  })

  const hasData = data.length > 0
  const maxVulns = hasData ? Math.max(...data.map((d) => d.vulns), 2) : 2

  return (
    <div className="flex-1 p-5 relative dot-grid-bg">
      <div className="flex items-start justify-between mb-2">
        <div>
          <p className="text-[11px] font-mono tracking-widest text-[#191919] font-bold">
            VULNERABILITY TREND
          </p>
          <p className="text-[10px] font-mono text-[#8f8f8f]">
            {hasData ? `${data.length} scan${data.length > 1 ? "s" : ""}` : "No scan history"}
          </p>
        </div>
        <div className="flex items-center gap-1 bg-[#ffffff] border border-[#e5e5e5] px-1">
          {timeRanges.map((r) => (
            <button
              key={r}
              onClick={() => setRange(r)}
              className={cn(
                "px-2 py-1 text-[10px] font-mono tracking-widest transition-colors",
                r === range
                  ? "text-[#191919] font-bold border-b-2 border-[#191919]"
                  : "text-[#8f8f8f] hover:text-[#191919]"
              )}
            >
              {r}
            </button>
          ))}
        </div>
      </div>

      <div className="h-[150px] bg-[#ffffff]/70 mt-2">
        {hasData ? (
          <ResponsiveContainer width="100%" height="100%">
            <LineChart data={data} margin={{ top: 10, right: 10, bottom: 0, left: -20 }}>
              <XAxis
                dataKey="date"
                tick={{ fontSize: 9, fontFamily: "Space Mono, monospace", fill: "#8f8f8f" }}
                axisLine={false}
                tickLine={false}
              />
              <YAxis
                tick={{ fontSize: 9, fontFamily: "Space Mono, monospace", fill: "#8f8f8f" }}
                axisLine={false}
                tickLine={false}
                domain={[0, maxVulns]}
                allowDecimals={false}
              />
              <Line
                type="linear"
                dataKey="vulns"
                stroke="#288034"
                strokeWidth={1.5}
                dot={({ cx, cy }: { cx?: number; cy?: number; [k: string]: unknown }) => (
                  <circle
                    key={`dot-${cx}-${cy}`}
                    cx={cx}
                    cy={cy}
                    r={3}
                    fill="#288034"
                    stroke="#ffffff"
                    strokeWidth={1.5}
                  />
                )}
                activeDot={{ r: 4, fill: "#288034", stroke: "#ffffff", strokeWidth: 2 }}
              />
            </LineChart>
          </ResponsiveContainer>
        ) : (
          <div className="h-full flex items-center justify-center">
            <p className="text-[11px] font-mono text-[#8f8f8f]">
              Run a scan to see trend data
            </p>
          </div>
        )}
      </div>
    </div>
  )
}
