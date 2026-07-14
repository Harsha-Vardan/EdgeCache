import { Routes, Route } from 'react-router-dom'
import { useState, useCallback } from 'react'
import DashboardLayout from './layouts/DashboardLayout'
import Dashboard from './pages/Dashboard'
import RequestMonitor from './pages/RequestMonitor'
import LiveLogs from './pages/LiveLogs'
import BlockedIPs from './pages/BlockedIPs'
import Configuration from './pages/Configuration'
import SystemHealth from './pages/SystemHealth'
import TrafficSimulation from './pages/TrafficSimulation'
import Analytics from './pages/Analytics'
import Architecture from './pages/Architecture'
import MetricsExport from './pages/MetricsExport'
import SecurityDashboard from './pages/SecurityDashboard'
import Timeline from './pages/Timeline'

export default function App() {
  const [toasts, setToasts] = useState([])

  const addToast = useCallback((message, type = 'info') => {
    const id = Date.now()
    setToasts(prev => [...prev, { id, message, type }])
    setTimeout(() => {
      setToasts(prev => prev.filter(t => t.id !== id))
    }, 4000)
  }, [])

  return (
    <>
      <DashboardLayout>
        <Routes>
          <Route path="/" element={<Dashboard />} />
          <Route path="/requests" element={<RequestMonitor addToast={addToast} />} />
          <Route path="/logs" element={<LiveLogs />} />
          <Route path="/blocked" element={<BlockedIPs addToast={addToast} />} />
          <Route path="/config" element={<Configuration addToast={addToast} />} />
          <Route path="/health" element={<SystemHealth />} />
          <Route path="/simulate" element={<TrafficSimulation addToast={addToast} />} />
          <Route path="/analytics" element={<Analytics />} />
          <Route path="/architecture" element={<Architecture />} />
          <Route path="/export" element={<MetricsExport addToast={addToast} />} />
          <Route path="/security" element={<SecurityDashboard />} />
          <Route path="/timeline" element={<Timeline />} />
        </Routes>
      </DashboardLayout>

      {/* Toast Notifications */}
      <div className="toast-container">
        {toasts.map(toast => (
          <div key={toast.id} className={`toast toast-${toast.type}`}>
            {toast.message}
          </div>
        ))}
      </div>
    </>
  )
}
