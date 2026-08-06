"""
Shared pytest fixtures for EdgeGuard test suite.

Provides isolated TrafficGovernor instances, dummy HTTP backends,
and dashboard API server fixtures for integration tests.
"""
import sys
import os
import json
import time
import socket
import threading
import tempfile
import shutil
from http.server import HTTPServer, BaseHTTPRequestHandler

import pytest

# Add project root to path so we can import edgeguard modules
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)


def get_free_port():
    """Get a random available port."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]


class DummyBackendHandler(BaseHTTPRequestHandler):
    """Simple HTTP handler that returns 200 OK for any request."""

    def do_GET(self):
        body = b"OK from dummy backend"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Server", "DummyBackend/1.0")
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        self.do_GET()

    def log_message(self, format, *args):
        pass  # Suppress request logs during tests


@pytest.fixture
def fresh_governor():
    """
    Creates an isolated TrafficGovernor instance with test-friendly config.
    Uses a temporary directory for jail persistence to avoid polluting the project.
    """
    # We need to manipulate the module-level config before creating a governor
    import edgeguard

    # Save original config
    original_config = dict(edgeguard.config)

    # Override with test config
    test_config = {
        "host": "127.0.0.1",
        "port": get_free_port(),
        "backend_host": "127.0.0.1",
        "backend_port": get_free_port(),
        "request_limit": 5,
        "time_window": 2,
        "block_duration": 10,
        "api_port": get_free_port(),
    }
    edgeguard.config.update(test_config)

    # Create a temporary directory for jail file and config persistence
    tmp_dir = tempfile.mkdtemp(prefix="edgeguard_test_")

    # Patch CONFIG_FILE so update_config doesn't overwrite the real config.json
    original_config_file = edgeguard.CONFIG_FILE
    edgeguard.CONFIG_FILE = os.path.join(tmp_dir, 'config.json')

    governor = edgeguard.TrafficGovernor()

    yield governor

    # Cleanup — restore original config and CONFIG_FILE path
    edgeguard.config.update(original_config)
    edgeguard.CONFIG_FILE = original_config_file
    shutil.rmtree(tmp_dir, ignore_errors=True)


@pytest.fixture
def test_config():
    """Returns a minimal test configuration dict."""
    return {
        "host": "127.0.0.1",
        "port": get_free_port(),
        "backend_host": "127.0.0.1",
        "backend_port": get_free_port(),
        "request_limit": 5,
        "time_window": 2,
        "block_duration": 10,
        "api_port": get_free_port(),
    }


@pytest.fixture
def dummy_backend():
    """
    Starts a dummy HTTP backend server on a random port.
    Returns (host, port) tuple. Server is automatically shut down after the test.
    """
    port = get_free_port()
    server = HTTPServer(('127.0.0.1', port), DummyBackendHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    # Wait for server to be ready
    for _ in range(50):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(0.5)
                s.connect(('127.0.0.1', port))
                break
        except (ConnectionRefusedError, OSError):
            time.sleep(0.05)

    yield ('127.0.0.1', port)

    server.shutdown()


@pytest.fixture
def api_server(fresh_governor):
    """
    Starts the dashboard API server backed by a fresh governor.
    Returns (governor, api_base_url) tuple.
    """
    from dashboard_server import start_api_server

    port = get_free_port()
    server = start_api_server(fresh_governor, port=port)

    # Wait for API server to be ready
    api_base = f"http://127.0.0.1:{port}"
    for _ in range(50):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(0.5)
                s.connect(('127.0.0.1', port))
                break
        except (ConnectionRefusedError, OSError):
            time.sleep(0.05)

    yield (fresh_governor, api_base)

    server.shutdown()
