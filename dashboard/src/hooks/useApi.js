import { useState, useEffect, useRef, useCallback } from 'react'

const API_BASE = '/api'

/**
 * Hook for Server-Sent Events — receives real-time dashboard updates
 */
export function useEventStream() {
  const [data, setData] = useState(null)
  const [connected, setConnected] = useState(false)
  const esRef = useRef(null)

  useEffect(() => {
    const connect = () => {
      const es = new EventSource(`${API_BASE}/stream`)
      esRef.current = es

      es.onopen = () => setConnected(true)

      es.onmessage = (event) => {
        try {
          const parsed = JSON.parse(event.data)
          setData(parsed)
        } catch (e) {
          console.error('SSE parse error:', e)
        }
      }

      es.onerror = () => {
        setConnected(false)
        es.close()
        // Reconnect after 3 seconds
        setTimeout(connect, 3000)
      }
    }

    connect()

    return () => {
      if (esRef.current) {
        esRef.current.close()
      }
    }
  }, [])

  return { data, connected }
}

/**
 * Generic fetch wrapper with error handling
 */
async function apiFetch(path, options = {}) {
  const url = `${API_BASE}${path}`
  const res = await fetch(url, {
    headers: { 'Content-Type': 'application/json', ...options.headers },
    ...options,
  })
  if (!res.ok) {
    throw new Error(`API Error: ${res.status} ${res.statusText}`)
  }
  const contentType = res.headers.get('content-type')
  if (contentType && contentType.includes('application/json')) {
    return res.json()
  }
  return res.text()
}

/**
 * API hooks for various endpoints
 */
export function useApi(path, interval = null) {
  const [data, setData] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)

  const fetchData = useCallback(async () => {
    try {
      const result = await apiFetch(path)
      setData(result)
      setError(null)
    } catch (e) {
      setError(e.message)
    } finally {
      setLoading(false)
    }
  }, [path])

  useEffect(() => {
    fetchData()
    if (interval) {
      const id = setInterval(fetchData, interval)
      return () => clearInterval(id)
    }
  }, [fetchData, interval])

  return { data, loading, error, refetch: fetchData }
}

/**
 * POST helper
 */
export async function apiPost(path, body = null) {
  return apiFetch(path, {
    method: 'POST',
    body: body ? JSON.stringify(body) : undefined,
  })
}

/**
 * Download helper
 */
export async function apiDownload(path, filename) {
  const res = await fetch(`${API_BASE}${path}`)
  const blob = await res.blob()
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = filename
  a.click()
  URL.revokeObjectURL(url)
}

/**
 * Format utilities
 */
export function formatUptime(seconds) {
  if (!seconds || seconds < 0) return '0s'
  const d = Math.floor(seconds / 86400)
  const h = Math.floor((seconds % 86400) / 3600)
  const m = Math.floor((seconds % 3600) / 60)
  const s = Math.floor(seconds % 60)
  if (d > 0) return `${d}d ${h}h ${m}m`
  if (h > 0) return `${h}h ${m}m ${s}s`
  if (m > 0) return `${m}m ${s}s`
  return `${s}s`
}

export function formatTimestamp(ts) {
  if (!ts) return '-'
  const date = new Date(ts * 1000)
  return date.toLocaleTimeString('en-US', { hour12: false })
}

export function formatNumber(n) {
  if (n === null || n === undefined) return '0'
  if (n >= 1000000) return (n / 1000000).toFixed(1) + 'M'
  if (n >= 1000) return (n / 1000).toFixed(1) + 'K'
  return n.toLocaleString()
}

export function timeAgo(ts) {
  if (!ts) return 'never'
  const diff = Date.now() / 1000 - ts
  if (diff < 5) return 'just now'
  if (diff < 60) return `${Math.floor(diff)}s ago`
  if (diff < 3600) return `${Math.floor(diff / 60)}m ago`
  if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`
  return `${Math.floor(diff / 86400)}d ago`
}
