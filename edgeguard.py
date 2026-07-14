import socket
import select
import time
import sys
import json
import logging
import threading
import os
from collections import deque, defaultdict

# --- CONFIGURATION ---
CONFIG_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'config.json')

def load_config():
    default_config = {
        "host": "0.0.0.0",
        "port": 8080,
        "backend_host": "127.0.0.1",
        "backend_port": 80,
        "request_limit": 10,
        "time_window": 5,
        "block_duration": 60,
        "api_port": 3001
    }
    try:
        with open(CONFIG_FILE, 'r') as f:
            user_config = json.load(f)
            default_config.update(user_config)
    except Exception as e:
        print(json.dumps({"level": "ERROR", "message": f"Config load error: {e}"}))
    return default_config

config = load_config()

# --- STRUCTURED LOGGING SETUP ---
class JSONFormatter(logging.Formatter):
    def format(self, record):
        log_record = {
            "timestamp": self.formatTime(record, self.datefmt),
            "level": record.levelname,
            "message": record.getMessage()
        }
        if hasattr(record, 'ip'):
            log_record['ip'] = record.ip
        if hasattr(record, 'event'):
            log_record['event'] = record.event
        return json.dumps(log_record)

logger = logging.getLogger("EdgeGuard")
logger.setLevel(logging.INFO)
file_handler = logging.FileHandler(os.path.join(os.path.dirname(os.path.abspath(__file__)), 'edgeguard.log'))
file_handler.setFormatter(JSONFormatter())
stream_handler = logging.StreamHandler(sys.stdout)
stream_handler.setFormatter(JSONFormatter())
logger.addHandler(file_handler)
logger.addHandler(stream_handler)


# --- TRAFFIC GOVERNOR (Enhanced with Rich Metrics) ---
class TrafficGovernor:
    def __init__(self):
        # Core rate limiting
        self.limit = config['request_limit']
        self.window = config['time_window']
        self.block_ttl = config['block_duration']
        self.request_history = {}        # ip -> deque of timestamps
        self.jail = {}                   # ip -> unjail_timestamp
        self.ip_stats = {}               # ip -> stats dict
        self.lock = threading.Lock()
        self.active_connections = 0
        self.total_requests = 0

        # --- Enhanced Metrics ---
        self.start_time = time.time()
        self.total_blocked = 0
        self.request_id_counter = 0

        # Request log (ring buffer for Request Monitor)
        self.request_log = deque(maxlen=10000)

        # Time series (per-second snapshots for charts)
        self.rps_history = deque(maxlen=300)        # 5 min of per-second data
        self.conn_history = deque(maxlen=300)
        self.blocked_rps_history = deque(maxlen=300)
        self._second_requests = 0
        self._second_blocked = 0

        # Status code distribution
        self.status_code_counts = defaultdict(int)

        # Timeline events
        self.timeline_events = deque(maxlen=1000)

        # Analytics
        self.peak_rps = 0
        self.total_response_time_ms = 0.0
        self.response_time_count = 0
        self.endpoint_counts = defaultdict(int)

        # Security metrics
        self.last_blocked_ip = None
        self.last_blocked_time = None
        self.last_unblocked_ip = None
        self.last_unblocked_time = None
        self.ip_block_counts = defaultdict(int)

        # Internal log buffer (for dashboard log viewer)
        self.log_buffer = deque(maxlen=5000)

        self._load_jail()

        # Start daemons
        self.cleanup_thread = threading.Thread(target=self._jail_cleanup_daemon, daemon=True)
        self.cleanup_thread.start()
        self.metrics_thread = threading.Thread(target=self._metrics_tick_daemon, daemon=True)
        self.metrics_thread.start()

    # --- Jail Persistence ---
    def _load_jail(self):
        try:
            jail_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'blocked_ips.txt')
            with open(jail_path, 'r') as f:
                for line in f:
                    parts = line.strip().split(',')
                    if len(parts) == 2:
                        ip, unjail_ts = parts[0], float(parts[1])
                        if unjail_ts > time.time():
                            self.jail[ip] = unjail_ts
        except FileNotFoundError:
            pass

    def save_jail(self):
        with self.lock:
            try:
                jail_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'blocked_ips.txt')
                with open(jail_path, 'w') as f:
                    current_time = time.time()
                    for ip, unjail_ts in self.jail.items():
                        if unjail_ts > current_time:
                            f.write(f"{ip},{unjail_ts}\n")
            except Exception as e:
                logger.error(f"Failed to save state: {e}", extra={'event': 'STATE_SAVE_ERROR'})

    # --- Daemon Threads ---
    def _jail_cleanup_daemon(self):
        """Sweeps expired jails every 5 seconds"""
        while True:
            time.sleep(5)
            current_time = time.time()
            expired_ips = []
            with self.lock:
                for ip, unjail_ts in list(self.jail.items()):
                    if current_time >= unjail_ts:
                        expired_ips.append(ip)
                        del self.jail[ip]
                        if ip in self.request_history:
                            del self.request_history[ip]

            for ip in expired_ips:
                logger.info(f"TTL expired via daemon sweep", extra={'ip': ip, 'event': 'UNJAILED'})
                self._add_log("INFO", f"IP {ip} automatically unjailed (TTL expired)", ip=ip, event="UNJAILED")
                self._add_timeline("ip_released", f"IP {ip} automatically unjailed", ip=ip)
                with self.lock:
                    self.last_unblocked_ip = ip
                    self.last_unblocked_time = current_time

    def _metrics_tick_daemon(self):
        """Snapshots per-second time-series data"""
        while True:
            time.sleep(1)
            now = int(time.time())
            with self.lock:
                rps = self._second_requests
                blocked_ps = self._second_blocked
                conns = self.active_connections

                self.rps_history.append({"t": now, "v": rps})
                self.conn_history.append({"t": now, "v": conns})
                self.blocked_rps_history.append({"t": now, "v": blocked_ps})

                if rps > self.peak_rps:
                    self.peak_rps = rps

                self._second_requests = 0
                self._second_blocked = 0

    # --- Core Rate Limiting ---
    def get_or_create_stats(self, ip):
        if ip not in self.ip_stats:
            self.ip_stats[ip] = {"requests": 0, "blocked_count": 0, "last_seen": 0, "first_seen": time.time()}
        return self.ip_stats[ip]

    def evaluate_request(self, ip):
        current_time = time.time()

        with self.lock:
            self.total_requests += 1
            self._second_requests += 1
            stats = self.get_or_create_stats(ip)
            stats["requests"] += 1
            stats["last_seen"] = current_time

            # Check Jail (TTL logic)
            if ip in self.jail:
                if current_time < self.jail[ip]:
                    stats["blocked_count"] += 1
                    self.total_blocked += 1
                    self._second_blocked += 1
                    return False
                else:
                    del self.jail[ip]
                    logger.info("TTL expired on evaluation", extra={'ip': ip, 'event': 'UNJAILED'})
                    self._add_log_unsafe("INFO", f"IP {ip} unjailed on evaluation", ip=ip, event="UNJAILED")
                    self._add_timeline_unsafe("ip_released", f"IP {ip} unjailed", ip=ip)
                    self.last_unblocked_ip = ip
                    self.last_unblocked_time = current_time
                    if ip in self.request_history:
                        del self.request_history[ip]

            if ip not in self.request_history:
                self.request_history[ip] = deque()

            history = self.request_history[ip]

            while history and current_time - history[0] > self.window:
                history.popleft()

            if len(history) >= self.limit:
                self.jail[ip] = current_time + self.block_ttl
                stats["blocked_count"] += 1
                self.total_blocked += 1
                self._second_blocked += 1
                self.ip_block_counts[ip] += 1
                self.last_blocked_ip = ip
                self.last_blocked_time = current_time
                logger.warning("Rate limit exceeded", extra={'ip': ip, 'event': 'BLOCKED'})
                self._add_log_unsafe("WARNING", f"IP {ip} rate limit exceeded — BLOCKED for {self.block_ttl}s", ip=ip, event="BLOCKED")
                self._add_timeline_unsafe("ip_blocked", f"IP {ip} blocked (rate limit exceeded)", ip=ip)
                return False

            history.append(current_time)
            logger.info("Connection allowed", extra={'ip': ip, 'event': 'ALLOWED'})
            return True

    # --- Connection Tracking ---
    def connection_opened(self):
        with self.lock:
            self.active_connections += 1

    def connection_closed(self):
        with self.lock:
            self.active_connections -= 1

    # --- Request Recording ---
    def next_request_id(self):
        with self.lock:
            self.request_id_counter += 1
            return self.request_id_counter

    def record_request(self, meta):
        """Record a completed request into the log"""
        with self.lock:
            self.request_log.append(meta)
            # Update status code counts
            sc = meta.get('status_code', 0)
            if sc > 0:
                self.status_code_counts[sc] += 1
            # Update response time tracking
            rt = meta.get('response_time_ms', 0)
            if rt > 0:
                self.total_response_time_ms += rt
                self.response_time_count += 1
            # Update endpoint counts
            path = meta.get('path', '/')
            if path:
                self.endpoint_counts[path] += 1
            # Add to timeline
            decision = meta.get('decision', 'allowed')
            ip = meta.get('client_ip', '?')
            method = meta.get('method', '?')
            status = meta.get('status_code', 0)
            self._add_timeline_unsafe(
                "request",
                f"{method} {path} → {status}" + (" [BLOCKED]" if decision == 'blocked' else ""),
                ip=ip, status=status, decision=decision
            )
            # Log it
            level = "WARNING" if decision == 'blocked' else "INFO"
            self._add_log_unsafe(
                level,
                f"{ip} {method} {path} → {status} ({rt:.1f}ms)",
                ip=ip, event="REQUEST", method=method, path=path, status=status
            )

    # --- Internal Log Buffer ---
    def _add_log(self, level, message, **extra):
        with self.lock:
            self._add_log_unsafe(level, message, **extra)

    def _add_log_unsafe(self, level, message, **extra):
        """Must be called with lock held"""
        entry = {
            "timestamp": time.time(),
            "level": level,
            "message": message,
        }
        entry.update(extra)
        self.log_buffer.append(entry)

    # --- Timeline Events ---
    def _add_timeline(self, event_type, message, **extra):
        with self.lock:
            self._add_timeline_unsafe(event_type, message, **extra)

    def _add_timeline_unsafe(self, event_type, message, **extra):
        """Must be called with lock held"""
        entry = {
            "timestamp": time.time(),
            "type": event_type,
            "message": message,
        }
        entry.update(extra)
        self.timeline_events.append(entry)

    # --- API Data Getters ---
    def get_dashboard_metrics(self):
        with self.lock:
            current_rps = self.rps_history[-1]["v"] if self.rps_history else 0
            return {
                "active_connections": self.active_connections,
                "total_requests": self.total_requests,
                "total_blocked": self.total_blocked,
                "blocked_ips": len(self.jail),
                "requests_per_sec": current_rps,
                "uptime_seconds": time.time() - self.start_time,
            }

    def get_request_log_page(self, page=1, per_page=50, search="", method="", status="", decision=""):
        with self.lock:
            items = list(self.request_log)
        # Reverse for newest first
        items.reverse()
        # Apply filters
        if search:
            search_lower = search.lower()
            items = [r for r in items if (
                search_lower in r.get('client_ip', '').lower() or
                search_lower in r.get('path', '').lower() or
                search_lower in r.get('method', '').lower()
            )]
        if method:
            items = [r for r in items if r.get('method', '').upper() == method.upper()]
        if status:
            try:
                sc = int(status)
                items = [r for r in items if r.get('status_code') == sc]
            except ValueError:
                pass
        if decision:
            items = [r for r in items if r.get('decision', '').lower() == decision.lower()]
        total = len(items)
        start = (page - 1) * per_page
        end = start + per_page
        return {
            "items": items[start:end],
            "total": total,
            "page": page,
            "per_page": per_page,
            "total_pages": max(1, (total + per_page - 1) // per_page),
        }

    def get_request_detail(self, request_id):
        with self.lock:
            for r in self.request_log:
                if r.get('id') == request_id:
                    return r
        return None

    def get_logs_page(self, page=1, per_page=100, level="", search=""):
        with self.lock:
            items = list(self.log_buffer)
        items.reverse()
        if level:
            items = [l for l in items if l.get('level', '').upper() == level.upper()]
        if search:
            search_lower = search.lower()
            items = [l for l in items if search_lower in l.get('message', '').lower()]
        total = len(items)
        start = (page - 1) * per_page
        end = start + per_page
        return {
            "items": items[start:end],
            "total": total,
            "page": page,
            "per_page": per_page,
        }

    def get_all_logs_text(self):
        with self.lock:
            items = list(self.log_buffer)
        lines = []
        for entry in items:
            ts = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(entry.get('timestamp', 0)))
            lines.append(f"[{ts}] [{entry.get('level', 'INFO')}] {entry.get('message', '')}")
        return "\n".join(lines)

    def get_blocked_ips_list(self):
        with self.lock:
            current_time = time.time()
            result = []
            for ip, unjail_ts in self.jail.items():
                remaining = max(0, unjail_ts - current_time)
                stats = self.ip_stats.get(ip, {})
                result.append({
                    "ip": ip,
                    "blocked_at": unjail_ts - self.block_ttl,
                    "unjail_at": unjail_ts,
                    "remaining_seconds": round(remaining, 1),
                    "reason": "Rate limit exceeded",
                    "total_requests": stats.get("requests", 0),
                    "blocked_count": stats.get("blocked_count", 0),
                    "block_incidents": self.ip_block_counts.get(ip, 0),
                })
            return result

    def unblock_ip(self, ip):
        with self.lock:
            if ip in self.jail:
                del self.jail[ip]
                if ip in self.request_history:
                    del self.request_history[ip]
                self.last_unblocked_ip = ip
                self.last_unblocked_time = time.time()
                self._add_log_unsafe("INFO", f"IP {ip} manually unblocked", ip=ip, event="MANUAL_UNBLOCK")
                self._add_timeline_unsafe("ip_released", f"IP {ip} manually unblocked", ip=ip)
                return True
            return False

    def get_config(self):
        return dict(config)

    def update_config(self, new_config):
        global config
        allowed_keys = ["backend_host", "backend_port", "request_limit", "time_window", "block_duration", "port"]
        with self.lock:
            for key in allowed_keys:
                if key in new_config:
                    config[key] = new_config[key]
            self.limit = config['request_limit']
            self.window = config['time_window']
            self.block_ttl = config['block_duration']
        # Persist
        try:
            with open(CONFIG_FILE, 'w') as f:
                json.dump(config, f, indent=2)
            self._add_log("INFO", "Configuration updated and saved", event="CONFIG_UPDATE")
            return True
        except Exception as e:
            self._add_log("ERROR", f"Failed to save config: {e}", event="CONFIG_ERROR")
            return False

    def get_system_health(self):
        try:
            import psutil
            cpu = psutil.cpu_percent(interval=0.1)
            mem = psutil.virtual_memory()
            ram_percent = mem.percent
            ram_used_mb = mem.used / (1024 * 1024)
            ram_total_mb = mem.total / (1024 * 1024)
        except ImportError:
            cpu = -1
            ram_percent = -1
            ram_used_mb = 0
            ram_total_mb = 0

        uptime = time.time() - self.start_time

        # Backend health check
        backend_status = self.check_backend_health()

        with self.lock:
            conns = self.active_connections
            socket_count = conns * 2  # Each connection has client + backend socket

        return {
            "cpu_percent": round(cpu, 1),
            "ram_percent": round(ram_percent, 1),
            "ram_used_mb": round(ram_used_mb, 1),
            "ram_total_mb": round(ram_total_mb, 1),
            "uptime_seconds": round(uptime, 1),
            "active_connections": conns,
            "socket_count": socket_count,
            "backend": backend_status,
        }

    def check_backend_health(self):
        """Check if backend is reachable"""
        start = time.time()
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(2.0)
            s.connect((config['backend_host'], config['backend_port']))
            latency_ms = (time.time() - start) * 1000
            s.close()
            return {
                "status": "online",
                "latency_ms": round(latency_ms, 1),
                "last_checked": time.time(),
                "host": config['backend_host'],
                "port": config['backend_port'],
            }
        except Exception:
            return {
                "status": "offline",
                "latency_ms": -1,
                "last_checked": time.time(),
                "host": config['backend_host'],
                "port": config['backend_port'],
            }

    def get_charts_data(self):
        with self.lock:
            return {
                "rps": list(self.rps_history),
                "connections": list(self.conn_history),
                "blocked_rps": list(self.blocked_rps_history),
                "top_ips": self._get_top_ips_unsafe(10),
                "status_codes": dict(self.status_code_counts),
            }

    def _get_top_ips_unsafe(self, n=10):
        """Must be called with lock held"""
        sorted_ips = sorted(self.ip_stats.items(), key=lambda x: x[1]["requests"], reverse=True)[:n]
        return [{"ip": ip, "requests": stats["requests"], "blocked": stats["blocked_count"]} for ip, stats in sorted_ips]

    def get_analytics(self):
        with self.lock:
            avg_response_time = (
                round(self.total_response_time_ms / self.response_time_count, 2)
                if self.response_time_count > 0 else 0
            )
            # Calculate average RPS
            if self.rps_history:
                avg_rps = round(sum(d["v"] for d in self.rps_history) / len(self.rps_history), 1)
            else:
                avg_rps = 0

            # Most requested endpoint
            most_requested = max(self.endpoint_counts.items(), key=lambda x: x[1]) if self.endpoint_counts else ("/", 0)

            # Top 10 client IPs
            top_ips = self._get_top_ips_unsafe(10)

            # Requests today (approximate - since startup)
            return {
                "total_requests_today": self.total_requests,
                "peak_rps": self.peak_rps,
                "avg_response_time_ms": avg_response_time,
                "avg_rps": avg_rps,
                "most_requested_endpoint": {"path": most_requested[0], "count": most_requested[1]},
                "top_client_ips": top_ips,
                "total_endpoints": len(self.endpoint_counts),
                "uptime_seconds": time.time() - self.start_time,
            }

    def get_security_metrics(self):
        with self.lock:
            # Most aggressive IP
            most_aggressive = None
            max_blocks = 0
            for ip, count in self.ip_block_counts.items():
                if count > max_blocks:
                    max_blocks = count
                    most_aggressive = ip

            # Average requests before blocking
            block_thresholds = []
            for ip, stats in self.ip_stats.items():
                if stats["blocked_count"] > 0:
                    block_thresholds.append(stats["requests"])
            avg_before_block = round(sum(block_thresholds) / len(block_thresholds), 1) if block_thresholds else 0

            return {
                "total_attacks_blocked": self.total_blocked,
                "currently_blocked_ips": len(self.jail),
                "most_aggressive_ip": most_aggressive,
                "most_aggressive_blocks": max_blocks,
                "avg_requests_before_block": avg_before_block,
                "last_blocked_ip": self.last_blocked_ip,
                "last_blocked_time": self.last_blocked_time,
                "last_unblocked_ip": self.last_unblocked_ip,
                "last_unblocked_time": self.last_unblocked_time,
                "unique_blocked_ips": len(self.ip_block_counts),
            }

    def get_timeline_events(self, limit=100):
        with self.lock:
            items = list(self.timeline_events)
        items.reverse()
        return items[:limit]

    def export_json(self):
        with self.lock:
            return json.dumps({
                "metrics": {
                    "active_connections": self.active_connections,
                    "total_requests": self.total_requests,
                    "total_blocked": self.total_blocked,
                    "blocked_ips": len(self.jail),
                    "uptime_seconds": time.time() - self.start_time,
                    "peak_rps": self.peak_rps,
                },
                "status_codes": dict(self.status_code_counts),
                "top_ips": self._get_top_ips_unsafe(20),
                "blocked_ips": [{
                    "ip": ip,
                    "unjail_at": ts,
                    "remaining": max(0, ts - time.time()),
                } for ip, ts in self.jail.items()],
                "config": dict(config),
            }, indent=2)

    def export_csv(self):
        with self.lock:
            lines = ["id,timestamp,client_ip,method,path,status_code,response_time_ms,bytes_sent,decision"]
            for r in self.request_log:
                lines.append(",".join([
                    str(r.get('id', '')),
                    str(r.get('timestamp', '')),
                    r.get('client_ip', ''),
                    r.get('method', ''),
                    r.get('path', ''),
                    str(r.get('status_code', '')),
                    str(round(r.get('response_time_ms', 0), 2)),
                    str(r.get('bytes_sent', 0)),
                    r.get('decision', ''),
                ]))
            return "\n".join(lines)

    def export_prometheus(self):
        with self.lock:
            lines = [
                f"# HELP edgeguard_active_connections Current active connections",
                f"# TYPE edgeguard_active_connections gauge",
                f"edgeguard_active_connections {self.active_connections}",
                f"# HELP edgeguard_total_requests Total requests processed",
                f"# TYPE edgeguard_total_requests counter",
                f"edgeguard_total_requests {self.total_requests}",
                f"# HELP edgeguard_total_blocked Total blocked requests",
                f"# TYPE edgeguard_total_blocked counter",
                f"edgeguard_total_blocked {self.total_blocked}",
                f"# HELP edgeguard_blocked_ips Currently blocked IPs",
                f"# TYPE edgeguard_blocked_ips gauge",
                f"edgeguard_blocked_ips {len(self.jail)}",
                f"# HELP edgeguard_peak_rps Peak requests per second",
                f"# TYPE edgeguard_peak_rps gauge",
                f"edgeguard_peak_rps {self.peak_rps}",
                f"# HELP edgeguard_uptime_seconds Proxy uptime in seconds",
                f"# TYPE edgeguard_uptime_seconds gauge",
                f"edgeguard_uptime_seconds {round(time.time() - self.start_time, 1)}",
            ]
            for code, count in self.status_code_counts.items():
                lines.append(f'edgeguard_status_code_total{{code="{code}"}} {count}')
            return "\n".join(lines)

    def get_sse_update(self):
        """Get a combined snapshot for SSE push"""
        with self.lock:
            recent_requests = list(self.request_log)[-10:]
            recent_logs = list(self.log_buffer)[-10:]
            recent_timeline = list(self.timeline_events)[-10:]
            current_rps = self.rps_history[-1]["v"] if self.rps_history else 0

            return {
                "metrics": {
                    "active_connections": self.active_connections,
                    "total_requests": self.total_requests,
                    "total_blocked": self.total_blocked,
                    "blocked_ips": len(self.jail),
                    "requests_per_sec": current_rps,
                    "uptime_seconds": time.time() - self.start_time,
                },
                "charts": {
                    "rps": list(self.rps_history)[-60:],
                    "connections": list(self.conn_history)[-60:],
                    "blocked_rps": list(self.blocked_rps_history)[-60:],
                    "top_ips": self._get_top_ips_unsafe(10),
                    "status_codes": dict(self.status_code_counts),
                },
                "recent_requests": recent_requests,
                "recent_logs": recent_logs,
                "recent_timeline": recent_timeline,
                "blocked_ips_list": [{
                    "ip": ip,
                    "remaining_seconds": round(max(0, ts - time.time()), 1),
                    "unjail_at": ts,
                    "requests": self.ip_stats.get(ip, {}).get("requests", 0),
                } for ip, ts in self.jail.items()],
            }


governor = TrafficGovernor()


# --- REVERSE PROXY & SELECT I/O ---
def main():
    # Start dashboard API server
    from dashboard_server import start_api_server
    api_port = config.get('api_port', 3001)
    start_api_server(governor, port=api_port)
    logger.info(f"Dashboard API server started on port {api_port}", extra={'event': 'API_START'})
    governor._add_log("INFO", f"Dashboard API server started on port {api_port}", event="API_START")
    governor._add_timeline("system", "EdgeGuard started")

    logger.info("Initializing EdgeGuard Select I/O Engine...", extra={'event': 'STARTUP'})
    governor._add_log("INFO", "EdgeGuard proxy engine starting...", event="STARTUP")

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.setblocking(False)

    host, port = config['host'], config['port']
    backend_host, backend_port = config['backend_host'], config['backend_port']

    try:
        server.bind((host, port))
        server.listen(100)
        logger.info(f"TCP Listener active on {host}:{port}", extra={'event': 'BIND'})
        governor._add_log("INFO", f"Proxy listening on {host}:{port}", event="BIND")
    except Exception as e:
        logger.error(f"Failed to bind socket: {e}", extra={'event': 'ERROR'})
        sys.exit(1)

    running = True

    # select() target lists
    inputs = [server]
    outputs = []

    # State tracking mappings
    client_to_backend = {}
    backend_to_client = {}
    message_queues = {}     # socket -> bytes to send
    socket_ips = {}         # socket -> ip
    blocked_sockets = set() # sockets awaiting 429 delivery

    # Request metadata tracking
    request_meta = {}       # client_socket -> {id, start_time, ip, method, path, ...}

    def cleanup_connection(s):
        """Clean up a socket and its paired partner"""
        # Record request if tracking
        if s in request_meta:
            meta = request_meta[s]
            if meta.get('start_time'):
                meta['response_time_ms'] = (time.time() - meta['start_time']) * 1000
            governor.record_request(meta)
            del request_meta[s]

        if s in blocked_sockets:
            blocked_sockets.discard(s)

        if s in inputs:
            inputs.remove(s)
        if s in outputs:
            outputs.remove(s)
        if s in message_queues:
            del message_queues[s]

        # Clean paired sockets if existing
        if s in client_to_backend:
            backend_sock = client_to_backend[s]
            # Don't recursively record — only client has meta
            if backend_sock in inputs:
                inputs.remove(backend_sock)
            if backend_sock in outputs:
                outputs.remove(backend_sock)
            if backend_sock in message_queues:
                del message_queues[backend_sock]
            if backend_sock in backend_to_client:
                del backend_to_client[backend_sock]
            try:
                backend_sock.close()
            except:
                pass
            del client_to_backend[s]
            governor.connection_closed()

        elif s in backend_to_client:
            client_sock = backend_to_client[s]
            # Record the client's request meta if it exists
            if client_sock in request_meta:
                meta = request_meta[client_sock]
                if meta.get('start_time'):
                    meta['response_time_ms'] = (time.time() - meta['start_time']) * 1000
                governor.record_request(meta)
                del request_meta[client_sock]
            if client_sock in inputs:
                inputs.remove(client_sock)
            if client_sock in outputs:
                outputs.remove(client_sock)
            if client_sock in message_queues:
                del message_queues[client_sock]
            if client_sock in socket_ips:
                del socket_ips[client_sock]
            if client_sock in blocked_sockets:
                blocked_sockets.discard(client_sock)
            try:
                client_sock.close()
            except:
                pass
            if client_sock in client_to_backend:
                del client_to_backend[client_sock]
            del backend_to_client[s]
            governor.connection_closed()

        if s in socket_ips:
            del socket_ips[s]

        try:
            s.close()
        except:
            pass

    try:
        while running:
            # Main non-blocking Event Loop
            readable, writable, exceptional = select.select(inputs, outputs, inputs, 1.0)

            for s in readable:
                if s is server:
                    # Handle new incoming socket
                    try:
                        client_socket, client_address = s.accept()
                    except OSError:
                        continue
                    client_socket.setblocking(False)
                    ip = client_address[0]

                    governor.connection_opened()
                    socket_ips[client_socket] = ip

                    allowed = governor.evaluate_request(ip)
                    if not allowed:
                        blocked_response = b"HTTP/1.1 429 Too Many Requests\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\nBlocked by EdgeGuard.\n"
                        inputs.append(client_socket)
                        outputs.append(client_socket)
                        message_queues[client_socket] = blocked_response
                        blocked_sockets.add(client_socket)
                        # Pre-record blocked request
                        req_id = governor.next_request_id()
                        request_meta[client_socket] = {
                            'id': req_id,
                            'timestamp': time.time(),
                            'start_time': time.time(),
                            'client_ip': ip,
                            'method': '',
                            'path': '',
                            'status_code': 429,
                            'response_time_ms': 0,
                            'bytes_sent': len(blocked_response),
                            'request_size': 0,
                            'decision': 'blocked',
                        }
                    else:
                        inputs.append(client_socket)
                        message_queues[client_socket] = b""

                else:
                    # Handle active reading
                    try:
                        data = s.recv(4096)
                    except ConnectionResetError:
                        data = b""

                    if data:
                        # Intercept blocked sockets — only parse their data for logging
                        if s in blocked_sockets:
                            header_line = data.split(b'\r\n')[0].decode('utf-8', errors='ignore')
                            parts = header_line.split(' ')
                            if s in request_meta:
                                if len(parts) >= 2:
                                    request_meta[s]['method'] = parts[0]
                                    request_meta[s]['path'] = parts[1]
                                request_meta[s]['request_size'] = len(data)
                            continue

                        # Check if this is a fresh client socket
                        if s in socket_ips and s not in client_to_backend and s not in backend_to_client:
                            header_line = data.split(b'\r\n')[0].decode('utf-8', errors='ignore')
                            parts = header_line.split(' ')
                            method = parts[0] if len(parts) > 0 else 'UNKNOWN'
                            path = parts[1] if len(parts) > 1 else '/'

                            if header_line.startswith("GET /metrics"):
                                # Internal metrics endpoint (Prometheus-style)
                                metrics = governor.get_dashboard_metrics()
                                body = (f"edgeguard_active_connections {metrics['active_connections']}\n"
                                        f"edgeguard_total_requests {metrics['total_requests']}\n"
                                        f"edgeguard_total_blocked {metrics['total_blocked']}\n"
                                        f"edgeguard_blocked_ips {metrics['blocked_ips']}\n")
                                resp = f"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {len(body)}\r\nConnection: close\r\n\r\n{body}"
                                message_queues[s] = resp.encode('utf-8')
                                if s not in outputs:
                                    outputs.append(s)
                                # Record this request
                                req_id = governor.next_request_id()
                                request_meta[s] = {
                                    'id': req_id,
                                    'timestamp': time.time(),
                                    'start_time': time.time(),
                                    'client_ip': socket_ips.get(s, '?'),
                                    'method': 'GET',
                                    'path': '/metrics',
                                    'status_code': 200,
                                    'response_time_ms': 0.1,
                                    'bytes_sent': len(body),
                                    'request_size': len(data),
                                    'decision': 'allowed',
                                }
                                continue

                            else:
                                # Normal traffic -> spin up proxy connection
                                req_id = governor.next_request_id()
                                request_meta[s] = {
                                    'id': req_id,
                                    'timestamp': time.time(),
                                    'start_time': time.time(),
                                    'client_ip': socket_ips.get(s, '?'),
                                    'method': method,
                                    'path': path,
                                    'status_code': 0,
                                    'response_time_ms': 0,
                                    'bytes_sent': 0,
                                    'request_size': len(data),
                                    'decision': 'allowed',
                                }
                                try:
                                    backend_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                                    backend_sock.setblocking(False)
                                    try:
                                        backend_sock.connect((backend_host, backend_port))
                                    except BlockingIOError:
                                        pass

                                    inputs.append(backend_sock)
                                    client_to_backend[s] = backend_sock
                                    backend_to_client[backend_sock] = s
                                    message_queues[backend_sock] = data
                                    if backend_sock not in outputs:
                                        outputs.append(backend_sock)
                                except Exception as e:
                                    logger.error(f"Failed to connect to backend: {e}", extra={'event': 'PROXY_ERROR'})
                                    resp = b"HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\nBackend Unavailable.\n"
                                    message_queues[s] = resp
                                    request_meta[s]['status_code'] = 502
                                    request_meta[s]['bytes_sent'] = len(resp)
                                    if s not in outputs:
                                        outputs.append(s)
                                    continue

                        # Route data symmetrically (proxy forwarding)
                        if s in client_to_backend:
                            target = client_to_backend[s]
                            if target in message_queues:
                                message_queues[target] += data
                            else:
                                message_queues[target] = data
                            if target not in outputs:
                                outputs.append(target)
                            # Track request size
                            client_sock = s
                            if client_sock in request_meta:
                                request_meta[client_sock]['request_size'] += len(data)

                        elif s in backend_to_client:
                            target = backend_to_client[s]
                            if target in message_queues:
                                message_queues[target] += data
                            else:
                                message_queues[target] = data
                            if target not in outputs:
                                outputs.append(target)
                            # Track response data
                            if target in request_meta:
                                request_meta[target]['bytes_sent'] += len(data)
                                # Parse status code from first backend response
                                if request_meta[target]['status_code'] == 0:
                                    try:
                                        resp_line = data.split(b'\r\n')[0].decode('utf-8', errors='ignore')
                                        rparts = resp_line.split(' ')
                                        if len(rparts) >= 2:
                                            request_meta[target]['status_code'] = int(rparts[1])
                                    except (ValueError, IndexError):
                                        pass
                    else:
                        cleanup_connection(s)

            for s in writable:
                try:
                    next_msg = message_queues.get(s, b"")
                    if next_msg:
                        sent = s.send(next_msg)
                        message_queues[s] = next_msg[sent:]
                    else:
                        if s in outputs:
                            outputs.remove(s)

                        # Close client if answered internally (429 or metrics)
                        if s in socket_ips and s not in client_to_backend:
                            cleanup_connection(s)

                except OSError:
                    cleanup_connection(s)

            for s in exceptional:
                cleanup_connection(s)

    except KeyboardInterrupt:
        logger.info("SIGINT Caught: Graceful Shutdown Initiated.", extra={'event': 'SHUTDOWN'})
        governor._add_log("INFO", "Graceful shutdown initiated", event="SHUTDOWN")
    finally:
        running = False
        logger.info("Flushing state and closing all sockets...", extra={'event': 'CLEANUP'})
        governor.save_jail()
        for s in inputs:
            try:
                s.close()
            except:
                pass
        logger.info("EdgeGuard shut down cleanly.", extra={'event': 'EXIT'})

if __name__ == "__main__":
    main()
