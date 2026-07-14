import { Activity, ShieldAlert, Zap, Server, Clock } from 'lucide-react'
import { useEventStream, formatNumber, formatUptime } from '../hooks/useApi'
import { 
  AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer,
  BarChart, Bar, LineChart, Line, Cell
} from 'recharts'

export default function Dashboard() {
  const { data } = useEventStream()

  if (!data) {
    return (
      <div className="flex items-center justify-center h-[60vh]">
        <div className="flex flex-col items-center gap-4">
          <div className="w-12 h-12 border-4 border-cyan-500 border-t-transparent rounded-full animate-spin"></div>
          <p className="text-slate-400 font-medium">Connecting to EdgeGuard API...</p>
        </div>
      </div>
    )
  }

  const { metrics, charts } = data
  const rpsData = charts.rps || []
  const currentRps = rpsData.length > 0 ? rpsData[rpsData.length - 1].v : 0

  return (
    <div className="space-y-6">
      <div className="page-header">
        <h1 className="page-title">Live Dashboard</h1>
        <p className="page-subtitle">Real-time metrics and traffic visualization.</p>
      </div>

      {/* Metrics Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-5 gap-4">
        <MetricCard 
          title="Requests / Sec" 
          value={formatNumber(currentRps)} 
          icon={<Zap size={24} className="text-amber-400" />}
          gradient="from-amber-500/20 to-orange-500/5 border-amber-500/30"
          delay="delay-1"
        />
        <MetricCard 
          title="Active Conns" 
          value={formatNumber(metrics.active_connections)} 
          icon={<Activity size={24} className="text-cyan-400" />}
          gradient="from-cyan-500/20 to-blue-500/5 border-cyan-500/30"
          delay="delay-2"
        />
        <MetricCard 
          title="Total Requests" 
          value={formatNumber(metrics.total_requests)} 
          icon={<Server size={24} className="text-violet-400" />}
          gradient="from-violet-500/20 to-fuchsia-500/5 border-violet-500/30"
          delay="delay-3"
        />
        <MetricCard 
          title="Blocked IPs" 
          value={formatNumber(metrics.blocked_ips)} 
          icon={<ShieldAlert size={24} className="text-rose-400" />}
          gradient="from-rose-500/20 to-red-500/5 border-rose-500/30"
          delay="delay-4"
        />
        <MetricCard 
          title="Uptime" 
          value={formatUptime(metrics.uptime_seconds)} 
          icon={<Clock size={24} className="text-emerald-400" />}
          gradient="from-emerald-500/20 to-teal-500/5 border-emerald-500/30"
          delay="delay-5"
        />
      </div>

      {/* Charts Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="lg:col-span-2 glass-card p-5 animate-slide-in delay-2">
          <h3 className="text-sm font-semibold text-slate-300 uppercase tracking-wider mb-4 flex items-center gap-2">
            <Activity size={16} className="text-cyan-400" />
            Requests Per Second
          </h3>
          <div className="h-64">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={charts.rps} margin={{ top: 5, right: 0, left: -20, bottom: 0 }}>
                <defs>
                  <linearGradient id="colorRps" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#06b6d4" stopOpacity={0.3}/>
                    <stop offset="95%" stopColor="#06b6d4" stopOpacity={0}/>
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" stroke="rgba(51, 65, 85, 0.5)" vertical={false} />
                <XAxis dataKey="t" tickFormatter={(t) => new Date(t * 1000).toLocaleTimeString([], {hour12:false, minute:'2-digit', second:'2-digit'})} stroke="#64748b" fontSize={12} tickMargin={10} />
                <YAxis stroke="#64748b" fontSize={12} tickFormatter={(v) => v >= 1000 ? (v/1000).toFixed(1)+'k' : v} />
                <Tooltip 
                  contentStyle={{ backgroundColor: 'rgba(15, 23, 42, 0.9)', borderColor: 'rgba(51, 65, 85, 0.5)', borderRadius: '8px' }}
                  labelFormatter={(t) => new Date(t * 1000).toLocaleTimeString()}
                />
                <Area type="monotone" dataKey="v" name="Requests/s" stroke="#06b6d4" strokeWidth={2} fillOpacity={1} fill="url(#colorRps)" isAnimationActive={false} />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>

        <div className="glass-card p-5 animate-slide-in delay-3">
          <h3 className="text-sm font-semibold text-slate-300 uppercase tracking-wider mb-4 flex items-center gap-2">
            <ShieldAlert size={16} className="text-rose-400" />
            Blocked RPS
          </h3>
          <div className="h-64">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={charts.blocked_rps} margin={{ top: 5, right: 0, left: -20, bottom: 0 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="rgba(51, 65, 85, 0.5)" vertical={false} />
                <XAxis dataKey="t" tickFormatter={(t) => new Date(t * 1000).toLocaleTimeString([], {minute:'2-digit', second:'2-digit'})} stroke="#64748b" fontSize={12} tickMargin={10} />
                <YAxis stroke="#64748b" fontSize={12} />
                <Tooltip 
                  contentStyle={{ backgroundColor: 'rgba(15, 23, 42, 0.9)', borderColor: 'rgba(244, 63, 94, 0.5)', borderRadius: '8px' }}
                  labelFormatter={(t) => new Date(t * 1000).toLocaleTimeString()}
                  cursor={{ fill: 'rgba(244, 63, 94, 0.1)' }}
                />
                <Bar dataKey="v" name="Blocked/s" fill="#f43f5e" radius={[2, 2, 0, 0]} isAnimationActive={false} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>

        <div className="lg:col-span-2 glass-card p-5 animate-slide-in delay-4">
          <h3 className="text-sm font-semibold text-slate-300 uppercase tracking-wider mb-4 flex items-center gap-2">
            <Server size={16} className="text-violet-400" />
            Active Connections
          </h3>
          <div className="h-64">
            <ResponsiveContainer width="100%" height="100%">
              <LineChart data={charts.connections} margin={{ top: 5, right: 0, left: -20, bottom: 0 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="rgba(51, 65, 85, 0.5)" vertical={false} />
                <XAxis dataKey="t" tickFormatter={(t) => new Date(t * 1000).toLocaleTimeString([], {minute:'2-digit', second:'2-digit'})} stroke="#64748b" fontSize={12} tickMargin={10} />
                <YAxis stroke="#64748b" fontSize={12} />
                <Tooltip 
                  contentStyle={{ backgroundColor: 'rgba(15, 23, 42, 0.9)', borderColor: 'rgba(139, 92, 246, 0.5)', borderRadius: '8px' }}
                  labelFormatter={(t) => new Date(t * 1000).toLocaleTimeString()}
                />
                <Line type="stepAfter" dataKey="v" name="Connections" stroke="#8b5cf6" strokeWidth={2} dot={false} isAnimationActive={false} />
              </LineChart>
            </ResponsiveContainer>
          </div>
        </div>

        <div className="glass-card p-5 animate-slide-in delay-5 flex flex-col">
          <h3 className="text-sm font-semibold text-slate-300 uppercase tracking-wider mb-4 flex items-center gap-2">
            <Activity size={16} className="text-amber-400" />
            Top Client IPs
          </h3>
          <div className="flex-1 overflow-hidden">
            {charts.top_ips.length === 0 ? (
              <div className="h-full flex items-center justify-center text-slate-500 text-sm">No traffic yet</div>
            ) : (
              <div className="space-y-3">
                {charts.top_ips.slice(0, 5).map((ipData, i) => (
                  <div key={ipData.ip} className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      <span className="text-xs font-mono text-slate-400 w-4">{i+1}.</span>
                      <span className="text-sm font-mono text-slate-200">{ipData.ip}</span>
                    </div>
                    <div className="flex items-center gap-3">
                      <span className="text-xs font-medium text-slate-300">{formatNumber(ipData.requests)} req</span>
                      {ipData.blocked > 0 && (
                        <span className="text-xs font-medium text-rose-400 bg-rose-500/10 px-1.5 py-0.5 rounded border border-rose-500/20">
                          {formatNumber(ipData.blocked)} blk
                        </span>
                      )}
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  )
}

function MetricCard({ title, value, icon, gradient, delay }) {
  return (
    <div className={`glass-card p-5 animate-fade-in ${delay} relative overflow-hidden group`}>
      <div className={`absolute inset-0 bg-gradient-to-br ${gradient} opacity-20 group-hover:opacity-30 transition-opacity`}></div>
      <div className="relative z-10 flex flex-col gap-3">
        <div className="flex items-center justify-between">
          <span className="label text-slate-400">{title}</span>
          <div className="p-2 rounded-lg bg-slate-800/50 border border-slate-700/50 backdrop-blur">
            {icon}
          </div>
        </div>
        <div className="value tracking-tight font-mono">{value}</div>
      </div>
    </div>
  )
}
