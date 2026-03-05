import { cn } from "@/lib/utils"

interface DotProgressBarProps {
  value: number
  total?: number
  className?: string
}

export function DotProgressBar({ value, total = 16, className }: DotProgressBarProps) {
  const filled = Math.round((value / 100) * total)
  return (
    <div className={cn("flex gap-[2px] items-center flex-1", className)}>
      {Array.from({ length: total }).map((_, i) => (
        <span
          key={i}
          className={cn(
            "w-[7px] h-[7px] rounded-[1px] flex-shrink-0",
            i < filled ? "bg-[#191919]" : "bg-[#e5e5e5]"
          )}
        />
      ))}
    </div>
  )
}
