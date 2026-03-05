import { AppSidebar } from "./AppSidebar"
import { ScanHeader } from "./ScanHeader"

interface AppShellProps {
  children: React.ReactNode
}

export function AppShell({ children }: AppShellProps) {
  return (
    <div className="flex h-screen bg-[#f7f7f7] overflow-hidden">
      <AppSidebar />
      <div className="flex-1 flex flex-col overflow-hidden">
        <ScanHeader />
        <main className="flex-1 overflow-y-auto bg-[#f7f7f7]">{children}</main>
      </div>
    </div>
  )
}
