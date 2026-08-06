"""
Integration tests for the EdgeGuard Dashboard API Server.

Tests the REST API endpoints by starting a real HTTP server
backed by a TrafficGovernor instance and making actual HTTP requests.
"""
import json
import urllib.request
import urllib.error
import pytest


def api_get(base_url, path):
    """Helper: GET request to API, returns (status_code, parsed_json_or_text)."""
    url = f"{base_url}{path}"
    try:
        req = urllib.request.Request(url)
        with urllib.request.urlopen(req, timeout=5) as resp:
            body = resp.read().decode('utf-8')
            content_type = resp.headers.get('Content-Type', '')
            if 'application/json' in content_type:
                return resp.status, json.loads(body)
            return resp.status, body
    except urllib.error.HTTPError as e:
        body = e.read().decode('utf-8')
        try:
            return e.code, json.loads(body)
        except json.JSONDecodeError:
            return e.code, body


def api_post(base_url, path, data=None):
    """Helper: POST request to API."""
    url = f"{base_url}{path}"
    body = json.dumps(data).encode('utf-8') if data else b""
    req = urllib.request.Request(url, data=body, method='POST')
    req.add_header('Content-Type', 'application/json')
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            return resp.status, json.loads(resp.read().decode('utf-8'))
    except urllib.error.HTTPError as e:
        body = e.read().decode('utf-8')
        try:
            return e.code, json.loads(body)
        except json.JSONDecodeError:
            return e.code, body


class TestMetricsEndpoint:
    def test_returns_200_with_json(self, api_server):
        governor, base_url = api_server
        status, data = api_get(base_url, '/api/metrics')
        assert status == 200
        assert isinstance(data, dict)

    def test_contains_expected_fields(self, api_server):
        governor, base_url = api_server
        status, data = api_get(base_url, '/api/metrics')
        for key in ['active_connections', 'total_requests', 'total_blocked',
                     'blocked_ips', 'requests_per_sec', 'uptime_seconds']:
            assert key in data, f"Missing key: {key}"


class TestBlockedEndpoint:
    def test_returns_list(self, api_server):
        governor, base_url = api_server
        status, data = api_get(base_url, '/api/blocked')
        assert status == 200
        assert isinstance(data, list)

    def test_blocked_ip_appears_after_rate_limit(self, api_server):
        governor, base_url = api_server
        ip = "10.99.0.1"
        # Trigger jail
        for _ in range(governor.limit + 1):
            governor.evaluate_request(ip)

        status, data = api_get(base_url, '/api/blocked')
        blocked_ips = [entry['ip'] for entry in data]
        assert ip in blocked_ips


class TestHealthEndpoint:
    def test_returns_200(self, api_server):
        governor, base_url = api_server
        status, data = api_get(base_url, '/api/health')
        assert status == 200

    def test_contains_system_fields(self, api_server):
        governor, base_url = api_server
        status, data = api_get(base_url, '/api/health')
        assert 'uptime_seconds' in data
        assert 'active_connections' in data
        assert 'backend' in data
        assert data['backend']['status'] in ('online', 'offline')


class TestConfigEndpoint:
    def test_get_config(self, api_server):
        governor, base_url = api_server
        status, data = api_get(base_url, '/api/config')
        assert status == 200
        assert 'request_limit' in data
        assert 'time_window' in data

    def test_post_config_updates(self, api_server):
        governor, base_url = api_server
        status, data = api_post(base_url, '/api/config', {"request_limit": 50})
        assert status == 200
        assert data.get('success') is True
        assert data['config']['request_limit'] == 50


class TestChartsEndpoint:
    def test_returns_time_series_data(self, api_server):
        governor, base_url = api_server
        status, data = api_get(base_url, '/api/charts')
        assert status == 200
        assert 'rps' in data
        assert 'connections' in data
        assert 'blocked_rps' in data
        assert 'top_ips' in data
        assert 'status_codes' in data


class TestAnalyticsEndpoint:
    def test_returns_analytics(self, api_server):
        governor, base_url = api_server
        status, data = api_get(base_url, '/api/analytics')
        assert status == 200
        assert 'total_requests_today' in data
        assert 'peak_rps' in data


class TestSecurityEndpoint:
    def test_returns_security_metrics(self, api_server):
        governor, base_url = api_server
        status, data = api_get(base_url, '/api/security')
        assert status == 200
        assert 'total_attacks_blocked' in data
        assert 'currently_blocked_ips' in data


class TestTimelineEndpoint:
    def test_returns_list(self, api_server):
        governor, base_url = api_server
        status, data = api_get(base_url, '/api/timeline')
        assert status == 200
        assert isinstance(data, list)


class TestExportEndpoints:
    def test_json_export(self, api_server):
        governor, base_url = api_server
        status, data = api_get(base_url, '/api/export/json')
        assert status == 200
        # Should be valid JSON string (returned as attachment)
        if isinstance(data, str):
            parsed = json.loads(data)
            assert 'metrics' in parsed

    def test_csv_export(self, api_server):
        governor, base_url = api_server
        status, data = api_get(base_url, '/api/export/csv')
        assert status == 200
        assert 'client_ip' in data  # CSV header

    def test_prometheus_export(self, api_server):
        governor, base_url = api_server
        status, data = api_get(base_url, '/api/export/prometheus')
        assert status == 200
        assert 'edgeguard_total_requests' in data


class TestCORSHeaders:
    def test_cors_present_on_response(self, api_server):
        governor, base_url = api_server
        url = f"{base_url}/api/metrics"
        req = urllib.request.Request(url)
        with urllib.request.urlopen(req, timeout=5) as resp:
            cors = resp.headers.get('Access-Control-Allow-Origin')
            assert cors == '*', "CORS header should be present"


class TestErrorHandling:
    def test_404_on_unknown_path(self, api_server):
        governor, base_url = api_server
        status, data = api_get(base_url, '/api/nonexistent')
        assert status == 404

    def test_unblock_nonexistent_ip(self, api_server):
        governor, base_url = api_server
        status, data = api_post(base_url, '/api/blocked/10.99.99.99/unblock')
        assert status == 200
        assert data.get('success') is False


class TestRequestsEndpoint:
    def test_returns_paginated_log(self, api_server):
        governor, base_url = api_server
        # Record some requests
        for i in range(3):
            governor.record_request({
                'id': governor.next_request_id(),
                'timestamp': __import__('time').time(),
                'client_ip': '10.0.0.1',
                'method': 'GET',
                'path': f'/page{i}',
                'status_code': 200,
                'response_time_ms': 1.0,
                'bytes_sent': 50,
                'decision': 'allowed',
            })

        status, data = api_get(base_url, '/api/requests?page=1&per_page=10')
        assert status == 200
        assert 'items' in data
        assert 'total' in data
        assert data['total'] >= 3

    def test_search_filter(self, api_server):
        governor, base_url = api_server
        governor.record_request({
            'id': governor.next_request_id(),
            'timestamp': __import__('time').time(),
            'client_ip': '192.168.50.1',
            'method': 'POST',
            'path': '/unique-test-path',
            'status_code': 201,
            'response_time_ms': 2.0,
            'bytes_sent': 30,
            'decision': 'allowed',
        })

        status, data = api_get(base_url, '/api/requests?search=unique-test-path')
        assert status == 200
        assert data['total'] >= 1


class TestLogsEndpoint:
    def test_returns_log_entries(self, api_server):
        governor, base_url = api_server
        # record_request writes to internal log buffer (evaluate_request alone does not)
        governor.record_request({
            'id': governor.next_request_id(),
            'timestamp': __import__('time').time(),
            'client_ip': '10.0.0.1',
            'method': 'GET',
            'path': '/',
            'status_code': 200,
            'response_time_ms': 1.0,
            'bytes_sent': 50,
            'decision': 'allowed',
        })

        status, data = api_get(base_url, '/api/logs')
        assert status == 200
        assert 'items' in data
        assert data['total'] >= 1

    def test_log_download(self, api_server):
        governor, base_url = api_server
        governor.evaluate_request("10.0.0.1")

        status, data = api_get(base_url, '/api/logs/download')
        assert status == 200
        assert isinstance(data, str)
