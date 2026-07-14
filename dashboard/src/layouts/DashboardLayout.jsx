import Sidebar from '../components/Sidebar'

export default function DashboardLayout({ children }) {
  return (
    <div className="flex min-h-screen bg-[var(--bg-primary)]">
      <Sidebar />
      <main className="flex-1 ml-0 md:ml-64 p-6 lg:p-8 max-w-[1600px] mx-auto w-full transition-all duration-300">
        <div className="animate-fade-in">
          {children}
        </div>
      </main>
    </div>
  )
}
