#!/usr/bin/env python3
"""
EdgeGuard Load Test / Benchmark Script

Stdlib-only (no aiohttp). Uses concurrent.futures + raw sockets to generate
load against the EdgeGuard proxy and/or a direct backend for comparison.

Usage:
    # Quick dev test (5s)
    python benchmark.py --quick

    # Full benchmark (30s, documented run)
    python benchmark.py --duration 30 --concurrent 100

    # JSON output for CI
    python benchmark.py --duration 30 --concurrent 100 --json

    # Custom target (skip auto-started backend)
    python benchmark.py --target http://myserver:8080 --duration 60

Methodology:
    - Spins up a dummy HTTP backend (unless --target is specified)
    - Fires concurrent HTTP requests via ThreadPoolExecutor
    - Measures per-request latency, computes p50/p95/p99 percentiles
    - Reports RPS, status code distribution, and % blocked (429s)
    - If proxy is running, compares direct-vs-proxy overhead
"""
import argparse
import json
import os
import platform
import socket
import statistics
import sys
import threading
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from http.server import HTTPServer, BaseHTTPRequestHandler


# --- Dummy Backend ---
class DummyHandler(BaseHTTPRequestHandler):
    """Minimal HTTP handler — returns 200 OK instantly."""

    def do_GET(self):
        body = b"OK"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        pass  # Suppress logs


def start_dummy_backend(port):
    """Start a dummy HTTP server in a daemon thread."""
    server = HTTPServer(('127.0.0.1', port), DummyHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    # Wait for it to be ready
    for _ in range(50):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(0.5)
                s.connect(('127.0.0.1', port))
                return server
        except (ConnectionRefusedError, OSError):
            time.sleep(0.05)
    return server


# --- HTTP Request via Raw Socket ---
def send_request(host, port, path="/"):
    """
    Send a single HTTP GET request via raw socket.
    Returns (latency_ms, status_code).
    """
    start = time.perf_counter()
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(5.0)
            s.connect((host, port))
            request = f"GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
            s.sendall(request.encode('utf-8'))

            response = b""
            while True:
                try:
                    chunk = s.recv(4096)
                    if not chunk:
                        break
                    response += chunk
                except socket.timeout:
                    break

            elapsed = (time.perf_counter() - start) * 1000  # ms

            # Parse status code
            resp_str = response.decode('utf-8', errors='ignore')
            if resp_str:
                status_line = resp_str.split('\r\n')[0]
                parts = status_line.split(' ')
                status_code = int(parts[1]) if len(parts) >= 2 else 0
            else:
                status_code = 0

            return elapsed, status_code

    except (ConnectionRefusedError, ConnectionResetError, socket.timeout, OSError):
        elapsed = (time.perf_counter() - start) * 1000
        return elapsed, 0


# --- Load Test Engine ---
def run_load_test(host, port, concurrent, duration, path="/"):
    """
    Run a load test for `duration` seconds with `concurrent` threads.
    Returns a results dict with latencies, status codes, RPS, etc.
    """
    latencies = []
    status_codes = Counter()
    start_time = time.time()
    request_count = 0
    lock = threading.Lock()

    def worker():
        nonlocal request_count
        local_latencies = []
        local_statuses = Counter()

        while time.time() - start_time < duration:
            lat, status = send_request(host, port, path)
            local_latencies.append(lat)
            local_statuses[status] += 1

        with lock:
            latencies.extend(local_latencies)
            status_codes.update(local_statuses)

    with ThreadPoolExecutor(max_workers=concurrent) as executor:
        futures = [executor.submit(worker) for _ in range(concurrent)]
        for f in futures:
            f.result()

    total_time = time.time() - start_time
    total_reqs = len(latencies)
    rps = total_reqs / total_time if total_time > 0 else 0

    if latencies:
        latencies.sort()
        p50 = latencies[int(len(latencies) * 0.50)]
        p95 = latencies[int(len(latencies) * 0.95)]
        p99 = latencies[int(len(latencies) * 0.99)]
        avg = statistics.mean(latencies)
        min_lat = latencies[0]
        max_lat = latencies[-1]
    else:
        p50 = p95 = p99 = avg = min_lat = max_lat = 0

    blocked = status_codes.get(429, 0)
    errors = status_codes.get(0, 0)
    success = sum(v for k, v in status_codes.items() if 200 <= k < 400)
    blocked_pct = (blocked / total_reqs * 100) if total_reqs > 0 else 0

    return {
        "total_requests": total_reqs,
        "duration_seconds": round(total_time, 2),
        "rps": round(rps, 2),
        "latency_ms": {
            "p50": round(p50, 2),
            "p95": round(p95, 2),
            "p99": round(p99, 2),
            "avg": round(avg, 2),
            "min": round(min_lat, 2),
            "max": round(max_lat, 2),
        },
        "status_codes": dict(status_codes),
        "success_count": success,
        "blocked_count": blocked,
        "blocked_pct": round(blocked_pct, 2),
        "error_count": errors,
    }


# --- Output Formatting ---
def print_results(label, results):
    """Pretty-print benchmark results to console."""
    print(f"\n{'='*60}")
    print(f"  {label}")
    print(f"{'='*60}")
    print(f"  Total Requests : {results['total_requests']:,}")
    print(f"  Duration       : {results['duration_seconds']:.1f}s")
    print(f"  Throughput     : {results['rps']:,.1f} req/s")
    print()
    print(f"  Latency (ms):")
    lat = results['latency_ms']
    print(f"    p50          : {lat['p50']:>8.2f} ms")
    print(f"    p95          : {lat['p95']:>8.2f} ms")
    print(f"    p99          : {lat['p99']:>8.2f} ms")
    print(f"    avg          : {lat['avg']:>8.2f} ms")
    print(f"    min          : {lat['min']:>8.2f} ms")
    print(f"    max          : {lat['max']:>8.2f} ms")
    print()
    print(f"  Status Codes   : {results['status_codes']}")
    print(f"  Success        : {results['success_count']:,}")
    print(f"  Blocked (429)  : {results['blocked_count']:,} ({results['blocked_pct']:.1f}%)")
    print(f"  Errors         : {results['error_count']:,}")
    print(f"{'='*60}")


def get_system_info():
    """Collect system info for benchmark metadata."""
    return {
        "platform": platform.platform(),
        "python_version": platform.python_version(),
        "cpu_count": os.cpu_count(),
        "machine": platform.machine(),
    }


# --- Main ---
def main():
    parser = argparse.ArgumentParser(
        description="EdgeGuard Load Test / Benchmark Script",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python benchmark.py --quick                         # 5s dev test
  python benchmark.py --duration 30 --concurrent 100  # Full benchmark
  python benchmark.py --json --duration 30             # JSON output for CI
  python benchmark.py --target http://host:port        # Custom target
        """
    )
    parser.add_argument('--duration', type=int, default=30,
                        help='Test duration in seconds (default: 30)')
    parser.add_argument('--concurrent', type=int, default=50,
                        help='Number of concurrent workers (default: 50)')
    parser.add_argument('--quick', action='store_true',
                        help='Quick dev test (5s, 20 workers)')
    parser.add_argument('--target', type=str, default=None,
                        help='Target URL (e.g., http://127.0.0.1:8080). '
                             'If not specified, auto-starts a dummy backend.')
    parser.add_argument('--proxy-port', type=int, default=8080,
                        help='EdgeGuard proxy port (default: 8080)')
    parser.add_argument('--backend-port', type=int, default=8081,
                        help='Backend port for direct comparison (default: 8081)')
    parser.add_argument('--json', action='store_true',
                        help='Output results as JSON')
    parser.add_argument('--output', type=str, default=None,
                        help='Save JSON results to file')
    parser.add_argument('--skip-direct', action='store_true',
                        help='Skip direct-to-backend test (only test proxy)')
    parser.add_argument('--path', type=str, default='/',
                        help='Request path (default: /)')

    args = parser.parse_args()

    if args.quick:
        args.duration = 5
        args.concurrent = 20

    # System info
    sys_info = get_system_info()

    if not args.json:
        print("\n" + "=" * 60)
        print("          EdgeGuard Benchmark / Load Test")
        print("=" * 60)
        print(f"\n  Duration     : {args.duration}s")
        print(f"  Concurrency  : {args.concurrent} workers")
        print(f"  Path         : {args.path}")
        print(f"  System       : {sys_info['platform']}")
        print(f"  Python       : {sys_info['python_version']}")
        print(f"  CPUs         : {sys_info['cpu_count']}")

    # Start dummy backend if no custom target
    backend_server = None
    if args.target is None:
        if not args.json:
            print(f"\n  Starting dummy backend on port {args.backend_port}...")
        backend_server = start_dummy_backend(args.backend_port)

    all_results = {
        "metadata": {
            "timestamp": time.strftime('%Y-%m-%d %H:%M:%S'),
            "duration_seconds": args.duration,
            "concurrent_workers": args.concurrent,
            "path": args.path,
            "system": sys_info,
            "caveat": "Single-machine benchmark — client, proxy, and backend "
                      "share the same CPU/network stack. Numbers represent "
                      "relative performance, not production throughput.",
        },
        "results": {},
    }

    # --- Direct-to-backend test ---
    if not args.skip_direct and args.target is None:
        if not args.json:
            print(f"\n  Running direct-to-backend test ({args.duration}s)...")

        direct_results = run_load_test(
            '127.0.0.1', args.backend_port,
            args.concurrent, args.duration, args.path
        )
        all_results["results"]["direct"] = direct_results

        if not args.json:
            print_results("Direct to Backend (baseline)", direct_results)

    # --- Through-proxy test ---
    if args.target:
        # Parse target URL
        target = args.target.replace('http://', '').replace('https://', '')
        if ':' in target:
            host, port = target.split(':')
            port = int(port.split('/')[0])
        else:
            host = target
            port = 80
    else:
        host = '127.0.0.1'
        port = args.proxy_port

    # Check if proxy is reachable
    proxy_reachable = False
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1.0)
            s.connect((host, port))
            proxy_reachable = True
    except (ConnectionRefusedError, OSError):
        pass

    if proxy_reachable:
        if not args.json:
            print(f"\n  Running through-proxy test ({args.duration}s on {host}:{port})...")

        proxy_results = run_load_test(
            host, port,
            args.concurrent, args.duration, args.path
        )
        all_results["results"]["proxy"] = proxy_results

        if not args.json:
            print_results(f"Through EdgeGuard Proxy ({host}:{port})", proxy_results)

            # Overhead analysis
            if "direct" in all_results["results"]:
                direct = all_results["results"]["direct"]
                overhead_p50 = proxy_results['latency_ms']['p50'] - direct['latency_ms']['p50']
                overhead_p99 = proxy_results['latency_ms']['p99'] - direct['latency_ms']['p99']
                rps_ratio = (proxy_results['rps'] / direct['rps'] * 100) if direct['rps'] > 0 else 0

                print(f"\n{'='*60}")
                print(f"  Overhead Analysis")
                print(f"{'='*60}")
                print(f"  p50 overhead   : {overhead_p50:+.2f} ms")
                print(f"  p99 overhead   : {overhead_p99:+.2f} ms")
                print(f"  RPS retained   : {rps_ratio:.1f}% of direct")
                print(f"  Blocked (429)  : {proxy_results['blocked_count']:,} "
                      f"({proxy_results['blocked_pct']:.1f}%)")
                print(f"{'='*60}")

                all_results["overhead"] = {
                    "p50_ms": round(overhead_p50, 2),
                    "p99_ms": round(overhead_p99, 2),
                    "rps_retained_pct": round(rps_ratio, 1),
                }
    else:
        if not args.json:
            print(f"\n  [!] EdgeGuard proxy not running on {host}:{port} -- skipping proxy test.")
            print(f"    Start it with: python edgeguard.py")

    # --- Output ---
    if args.json:
        print(json.dumps(all_results, indent=2))
    elif not args.json:
        print(f"\n  Benchmark complete.\n")

    if args.output:
        with open(args.output, 'w') as f:
            json.dump(all_results, f, indent=2)
        if not args.json:
            print(f"  Results saved to {args.output}")


if __name__ == "__main__":
    main()
