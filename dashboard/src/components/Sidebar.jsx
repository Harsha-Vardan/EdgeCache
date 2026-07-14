import { NavLink } from 'react-router-dom'
import { 
  LayoutDashboard, 
  Activity, 
  TerminalSquare, 
  ShieldAlert, 
  Settings, 
  ServerCrash,
  RadioTower,
  BarChart3,
  Network,
  DownloadCloud,
  ShieldCheck,
  Clock
} from 'lucide-react'
import { useEventStream } from '../hooks/useApi'

export default function Sidebar() {
  const { connected } = useEventStream()

  const navItems = [
    { to: '/', icon: <LayoutDashboard size={20} />, label: 'Dashboard' },
    { to: '/requests', icon: <Activity size={20} />, label: 'Request Monitor' },
    { to: '/logs', icon: <TerminalSquare size={20} />, label: 'Live Logs' },
    { to: '/blocked', icon: <ShieldAlert size={20} />, label: 'Blocked IPs' },
    { to: '/security', icon: <ShieldCheck size={20} />, label: 'Security' },
    { to: '/analytics', icon: <BarChart3 size={20} />, label: 'Analytics' },
    { to: '/timeline', icon: <Clock size={20} />, label: 'Event Timeline' },
    { to: '/health', icon: <ServerCrash size={20} />, label: 'System Health' },
    { to: '/simulate', icon: <RadioTower size={20} />, label: 'Traffic Sim' },
    { to: '/architecture', icon: <Network size={20} />, label: 'Architecture' },
    { to: '/config', icon: <Settings size={20} />, label: 'Configuration' },
    { to: '/export', icon: <DownloadCloud size={20} />, label: 'Export Data' },
  ]

  return (
    <div className="sidebar h-screen w-64 flex flex-col flex-shrink-0 fixed left-0 top-0">
      <div className="p-6 flex items-center gap-3 border-b border-[var(--border-primary)]">
        <div className="w-8 h-8 rounded bg-gradient-to-br from-cyan-500 to-violet-500 flex items-center justify-center shadow-[0_0_15px_rgba(6,182,212,0.5)]">
          <ShieldCheck size={20} className="text-white" />
        </div>
        <div className="sidebar-text font-bold text-lg tracking-tight bg-clip-text text-transparent bg-gradient-to-r from-white to-slate-400">
          EdgeGuard
        </div>
      </div>

      <div className="flex-1 overflow-y-auto p-4 flex flex-col gap-1">
        {navItems.map((item) => (
          <NavLink 
            key={item.to} 
            to={item.to} 
            className={({isActive}) => `sidebar-link ${isActive ? 'active' : ''}`}
          >
            {item.icon}
            <span className="sidebar-text">{item.label}</span>
          </NavLink>
        ))}
      </div>

      <div className="p-4 border-t border-[var(--border-primary)]">
        <div className={`connection-indicator ${!connected ? 'disconnected' : ''}`}>
          <div className="dot"></div>
          <span className="sidebar-text font-medium">
            {connected ? 'API Connected' : 'Disconnected'}
          </span>
        </div>
      </div>
    </div>
  )
}
