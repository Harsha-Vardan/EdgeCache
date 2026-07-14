"""
EdgeGuard Dashboard API Server
Provides REST API + Server-Sent Events for the React dashboard.
Runs in a daemon thread alongside the proxy.
"""
import socket
import threading
import time
import json
import random
import urllib.parse
from http.server import HTTPServer, BaseHTTPRequestHandler
from socketserver import ThreadingMixIn


# --- Traffic Simulator ---
class TrafficSimulator:
    """Generates synthetic traffic to the EdgeGuard proxy for demo purposes"""

    def __init__(self, target_host='127.0.0.1', target_port=8080):
        self.target_host = target_host
        self.target_port = target_port
        self.running = False
        self.mode = None
        self._threads = []

    def start(self, mode):
        self.stop()
        self.mode = mode
        self.running = True

        if mode == 'normal':
            t = threading.Thread(target=self._normal, daemon=True)
        elif mode == 'heavy':
            t = threading.Thread(target=self._heavy, daemon=True)
        elif mode == 'attack':
            t = threading.Thread(target=self._attack, daemon=True)
        else:
            return {"status": "error", "message": f"Unknown mode: {mode}"}

        t.start()
        self._threads.append(t)
        return {"status": "started", "mode": mode}

    def stop(self):
        self.running = False
        self.mode = None
        self._threads = []
        return {"status": "stopped"}

    def get_status(self):
        return {"running": self.running, "mode": self.mode}

    def _send_http(self, path='/'):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(2.0)
                s.connect((self.target_host, self.target_port))
                req = f"GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\nUser-Agent: EdgeGuard-Simulator\r\n\r\n"
                s.sendall(req.encode())
                s.recv(4096)
        except Exception:
            pass

    def _normal(self):
        """1-2 requests per second, varied paths"""
        paths = ['/', '/api/data', '/login', '/about', '/contact', '/api/users', '/dashboard']
        while self.running:
            self._send_http(random.choice(paths))
            time.sleep(random.uniform(0.5, 1.5))

    def _heavy(self):
        """5-8 requests per second"""
        paths = ['/', '/api/data', '/api/users', '/api/products', '/login', '/search', '/api/stats']
        while self.running:
            self._send_http(random.choice(paths))
            time.sleep(random.uniform(0.12, 0.25))

    def _attack(self):
        """20+ requests per second — will trigger rate limiting"""
        while self.running:
            for _ in range(5):
                self._send_http('/api/data')
            time.sleep(0.05)


# --- Threaded HTTP Server ---
class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


# --- API Request Handler ---
class DashboardAPIHandler(BaseHTTPRequestHandler):
    governor = None
    simulator = None

    # Suppress default logging to terminal
    def log_message(self, format, *args):
        pass

    def _set_cors_headers(self):
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')

    def _send_json(self, data, status=200):
        body = json.dumps(data).encode('utf-8')
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(body)))
        self._set_cors_headers()
        self.end_headers()
        self.wfile.write(body)

    def _send_text(self, text, content_type='text/plain', filename=None):
        body = text.encode('utf-8')
        self.send_response(200)
        self.send_header('Content-Type', content_type)
        self.send_header('Content-Length', str(len(body)))
        if filename:
            self.send_header('Content-Disposition', f'attachment; filename="{filename}"')
        self._set_cors_headers()
        self.end_headers()
        self.wfile.write(body)

    def _parse_qs(self):
        parsed = urllib.parse.urlparse(self.path)
        return dict(urllib.parse.parse_qsl(parsed.query))

    def do_OPTIONS(self):
        self.send_response(204)
        self._set_cors_headers()
        self.end_headers()

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        params = self._parse_qs()

        # --- Route Dispatch ---
        if path == '/api/metrics':
            self._send_json(self.governor.get_dashboard_metrics())

        elif path == '/api/requests':
            page = int(params.get('page', 1))
            per_page = int(params.get('per_page', 50))
            search = params.get('search', '')
            method = params.get('method', '')
            status = params.get('status', '')
            decision = params.get('decision', '')
            self._send_json(self.governor.get_request_log_page(page, per_page, search, method, status, decision))

        elif path.startswith('/api/requests/'):
            try:
                req_id = int(path.split('/')[-1])
                detail = self.governor.get_request_detail(req_id)
                if detail:
                    self._send_json(detail)
                else:
                    self._send_json({"error": "Not found"}, 404)
            except ValueError:
                self._send_json({"error": "Invalid ID"}, 400)

        elif path == '/api/logs':
            page = int(params.get('page', 1))
            per_page = int(params.get('per_page', 100))
            level = params.get('level', '')
            search = params.get('search', '')
            self._send_json(self.governor.get_logs_page(page, per_page, level, search))

        elif path == '/api/logs/download':
            text = self.governor.get_all_logs_text()
            self._send_text(text, 'text/plain', 'edgeguard_logs.txt')

        elif path == '/api/blocked':
            self._send_json(self.governor.get_blocked_ips_list())

        elif path == '/api/config':
            self._send_json(self.governor.get_config())

        elif path == '/api/health':
            self._send_json(self.governor.get_system_health())

        elif path == '/api/backend/status':
            self._send_json(self.governor.check_backend_health())

        elif path == '/api/charts':
            self._send_json(self.governor.get_charts_data())

        elif path == '/api/analytics':
            self._send_json(self.governor.get_analytics())

        elif path == '/api/security':
            self._send_json(self.governor.get_security_metrics())

        elif path == '/api/timeline':
            limit = int(params.get('limit', 100))
            self._send_json(self.governor.get_timeline_events(limit))

        elif path == '/api/export/json':
            self._send_text(self.governor.export_json(), 'application/json', 'edgeguard_metrics.json')

        elif path == '/api/export/csv':
            self._send_text(self.governor.export_csv(), 'text/csv', 'edgeguard_requests.csv')

        elif path == '/api/export/prometheus':
            self._send_text(self.governor.export_prometheus(), 'text/plain', 'edgeguard_metrics.prom')

        elif path == '/api/simulate/status':
            self._send_json(self.simulator.get_status() if self.simulator else {"running": False})

        elif path == '/api/stream':
            self._handle_sse()

        else:
            self._send_json({"error": "Not found", "path": path}, 404)

    def do_POST(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path

        # Read body
        content_length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(content_length) if content_length > 0 else b""

        if path == '/api/config':
            try:
                new_config = json.loads(body) if body else {}
                success = self.governor.update_config(new_config)
                self._send_json({"success": success, "config": self.governor.get_config()})
            except json.JSONDecodeError:
                self._send_json({"error": "Invalid JSON"}, 400)

        elif path.startswith('/api/blocked/') and path.endswith('/unblock'):
            parts = path.split('/')
            ip = parts[3] if len(parts) >= 5 else ''
            ip = urllib.parse.unquote(ip)
            success = self.governor.unblock_ip(ip)
            self._send_json({"success": success, "ip": ip})

        elif path.startswith('/api/simulate/'):
            mode = path.split('/')[-1]
            if self.simulator:
                if mode == 'clear' or mode == 'stop':
                    result = self.simulator.stop()
                else:
                    result = self.simulator.start(mode)
                self._send_json(result)
            else:
                self._send_json({"error": "Simulator not available"}, 500)

        else:
            self._send_json({"error": "Not found"}, 404)

    def _handle_sse(self):
        """Server-Sent Events endpoint for real-time dashboard updates"""
        self.send_response(200)
        self.send_header('Content-Type', 'text/event-stream')
        self.send_header('Cache-Control', 'no-cache')
        self.send_header('Connection', 'keep-alive')
        self._set_cors_headers()
        self.end_headers()

        try:
            while True:
                data = self.governor.get_sse_update()
                payload = f"data: {json.dumps(data)}\n\n"
                self.wfile.write(payload.encode('utf-8'))
                self.wfile.flush()
                time.sleep(1)
        except (BrokenPipeError, ConnectionResetError, OSError):
            pass  # Client disconnected


# --- Server Start Functions ---
def start_api_server(governor, port=3001):
    """Start the dashboard API server in a daemon thread"""
    proxy_port = governor.get_config().get('port', 8080)
    simulator = TrafficSimulator(target_host='127.0.0.1', target_port=proxy_port)

    DashboardAPIHandler.governor = governor
    DashboardAPIHandler.simulator = simulator

    server = ThreadedHTTPServer(('0.0.0.0', port), DashboardAPIHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    return server
