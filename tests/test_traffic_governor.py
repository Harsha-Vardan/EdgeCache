"""
Unit tests for TrafficGovernor — the core rate-limiting engine.

Tests cover:
- Rate limiting logic (allow/block thresholds)
- Jail (blocking) and TTL expiry
- Per-IP independence
- Connection tracking
- Request recording and metrics
- Thread safety under concurrent access
- Configuration updates
- Export formats (Prometheus, CSV)
"""
import time
import threading
import pytest


class TestRateLimiting:
    """Tests for the core rate-limiting / jail logic."""

    def test_allow_requests_under_limit(self, fresh_governor):
        """Requests below the configured limit should all be allowed."""
        limit = fresh_governor.limit  # 5 in test config
        for i in range(limit - 1):
            assert fresh_governor.evaluate_request("10.0.0.1") is True, (
                f"Request {i+1}/{limit-1} should be allowed"
            )

    def test_block_after_exceeding_limit(self, fresh_governor):
        """The request that exceeds the limit should be blocked."""
        limit = fresh_governor.limit
        ip = "10.0.0.2"

        # Send exactly `limit` requests (all allowed — the limit-th fills the window)
        for i in range(limit):
            fresh_governor.evaluate_request(ip)

        # The next request should be blocked
        result = fresh_governor.evaluate_request(ip)
        assert result is False, "Request exceeding rate limit should be blocked"

    def test_jail_blocks_subsequent_requests(self, fresh_governor):
        """Once jailed, all subsequent requests from that IP are blocked."""
        ip = "10.0.0.3"
        limit = fresh_governor.limit

        # Trigger jail
        for _ in range(limit + 1):
            fresh_governor.evaluate_request(ip)

        # Subsequent requests should all be blocked
        for _ in range(5):
            assert fresh_governor.evaluate_request(ip) is False, (
                "Jailed IP should be blocked on subsequent requests"
            )

    def test_jail_expires_after_ttl(self, fresh_governor):
        """After block_duration expires, the IP should be allowed again."""
        ip = "10.0.0.4"
        limit = fresh_governor.limit

        # Trigger jail
        for _ in range(limit + 1):
            fresh_governor.evaluate_request(ip)

        assert fresh_governor.evaluate_request(ip) is False, "Should be jailed"

        # Simulate time passing beyond block_duration
        with fresh_governor.lock:
            fresh_governor.jail[ip] = time.time() - 1  # Set unjail time in the past

        # Should be allowed now
        assert fresh_governor.evaluate_request(ip) is True, (
            "IP should be allowed after jail TTL expires"
        )

    def test_multiple_ips_independent(self, fresh_governor):
        """Different IPs should have independent rate-limit counters."""
        limit = fresh_governor.limit

        # Fill up IP-A's quota
        for _ in range(limit):
            fresh_governor.evaluate_request("192.168.1.1")

        # IP-B should still be allowed
        assert fresh_governor.evaluate_request("192.168.1.2") is True, (
            "Different IP should have independent rate limit"
        )

    def test_unblock_ip(self, fresh_governor):
        """unblock_ip() should remove an IP from jail immediately."""
        ip = "10.0.0.5"
        limit = fresh_governor.limit

        # Trigger jail
        for _ in range(limit + 1):
            fresh_governor.evaluate_request(ip)

        assert fresh_governor.evaluate_request(ip) is False, "Should be jailed"

        # Manually unblock
        result = fresh_governor.unblock_ip(ip)
        assert result is True, "unblock_ip should return True for jailed IP"

        # Should be allowed now
        assert fresh_governor.evaluate_request(ip) is True, (
            "Unblocked IP should be allowed"
        )

    def test_unblock_returns_false_for_unknown_ip(self, fresh_governor):
        """unblock_ip() should return False if the IP isn't jailed."""
        result = fresh_governor.unblock_ip("10.99.99.99")
        assert result is False

    def test_window_sliding_allows_after_cooldown(self, fresh_governor):
        """After the time window passes, the same IP should be allowed again."""
        ip = "10.0.0.6"
        limit = fresh_governor.limit
        window = fresh_governor.window

        # Send requests up to (but not exceeding) the limit
        for _ in range(limit - 1):
            fresh_governor.evaluate_request(ip)

        # Simulate the time window expiring by backdating all request history
        with fresh_governor.lock:
            if ip in fresh_governor.request_history:
                old_time = time.time() - window - 1
                fresh_governor.request_history[ip].clear()
                # Add old timestamps that will be purged
                for _ in range(limit - 1):
                    fresh_governor.request_history[ip].append(old_time)

        # New request should be allowed (old ones expired from window)
        assert fresh_governor.evaluate_request(ip) is True


class TestConnectionTracking:
    """Tests for active connection counter."""

    def test_connection_opened_increments(self, fresh_governor):
        assert fresh_governor.active_connections == 0
        fresh_governor.connection_opened()
        assert fresh_governor.active_connections == 1
        fresh_governor.connection_opened()
        assert fresh_governor.active_connections == 2

    def test_connection_closed_decrements(self, fresh_governor):
        fresh_governor.connection_opened()
        fresh_governor.connection_opened()
        fresh_governor.connection_closed()
        assert fresh_governor.active_connections == 1


class TestRequestRecording:
    """Tests for request log, status codes, and endpoint tracking."""

    def test_record_request_populates_log(self, fresh_governor):
        meta = {
            'id': 1,
            'timestamp': time.time(),
            'start_time': time.time(),
            'client_ip': '10.0.0.1',
            'method': 'GET',
            'path': '/api/data',
            'status_code': 200,
            'response_time_ms': 5.2,
            'bytes_sent': 100,
            'decision': 'allowed',
        }
        fresh_governor.record_request(meta)

        with fresh_governor.lock:
            assert len(fresh_governor.request_log) == 1
            assert fresh_governor.request_log[0]['path'] == '/api/data'

    def test_status_code_counts(self, fresh_governor):
        for status in [200, 200, 200, 429, 502]:
            fresh_governor.record_request({
                'id': fresh_governor.next_request_id(),
                'timestamp': time.time(),
                'client_ip': '10.0.0.1',
                'method': 'GET',
                'path': '/',
                'status_code': status,
                'response_time_ms': 1.0,
                'bytes_sent': 10,
                'decision': 'allowed',
            })

        with fresh_governor.lock:
            assert fresh_governor.status_code_counts[200] == 3
            assert fresh_governor.status_code_counts[429] == 1
            assert fresh_governor.status_code_counts[502] == 1

    def test_endpoint_counts(self, fresh_governor):
        for path in ['/', '/api/data', '/api/data', '/login']:
            fresh_governor.record_request({
                'id': fresh_governor.next_request_id(),
                'timestamp': time.time(),
                'client_ip': '10.0.0.1',
                'method': 'GET',
                'path': path,
                'status_code': 200,
                'response_time_ms': 1.0,
                'bytes_sent': 10,
                'decision': 'allowed',
            })

        with fresh_governor.lock:
            assert fresh_governor.endpoint_counts['/api/data'] == 2
            assert fresh_governor.endpoint_counts['/'] == 1

    def test_request_detail_by_id(self, fresh_governor):
        req_id = fresh_governor.next_request_id()
        fresh_governor.record_request({
            'id': req_id,
            'timestamp': time.time(),
            'client_ip': '10.0.0.1',
            'method': 'POST',
            'path': '/submit',
            'status_code': 201,
            'response_time_ms': 12.5,
            'bytes_sent': 50,
            'decision': 'allowed',
        })

        detail = fresh_governor.get_request_detail(req_id)
        assert detail is not None
        assert detail['method'] == 'POST'
        assert detail['path'] == '/submit'

    def test_request_detail_returns_none_for_missing(self, fresh_governor):
        assert fresh_governor.get_request_detail(99999) is None


class TestMetricsAndExports:
    """Tests for metrics getters and export formats."""

    def test_dashboard_metrics_structure(self, fresh_governor):
        metrics = fresh_governor.get_dashboard_metrics()
        expected_keys = {
            'active_connections', 'total_requests', 'total_blocked',
            'blocked_ips', 'requests_per_sec', 'uptime_seconds'
        }
        assert expected_keys.issubset(set(metrics.keys())), (
            f"Missing keys: {expected_keys - set(metrics.keys())}"
        )

    def test_analytics_structure(self, fresh_governor):
        analytics = fresh_governor.get_analytics()
        assert 'total_requests_today' in analytics
        assert 'peak_rps' in analytics
        assert 'avg_response_time_ms' in analytics
        assert 'most_requested_endpoint' in analytics

    def test_security_metrics_structure(self, fresh_governor):
        security = fresh_governor.get_security_metrics()
        assert 'total_attacks_blocked' in security
        assert 'currently_blocked_ips' in security
        assert 'most_aggressive_ip' in security

    def test_export_prometheus_format(self, fresh_governor):
        # Generate some traffic first
        for _ in range(3):
            fresh_governor.evaluate_request("10.0.0.1")

        prom_text = fresh_governor.export_prometheus()
        assert "edgeguard_total_requests" in prom_text
        assert "edgeguard_active_connections" in prom_text
        assert "# HELP" in prom_text
        assert "# TYPE" in prom_text
        # Verify counter type annotation
        assert "counter" in prom_text.lower() or "gauge" in prom_text.lower()

    def test_export_csv_format(self, fresh_governor):
        # Record a request so CSV has data
        fresh_governor.record_request({
            'id': 1, 'timestamp': time.time(), 'client_ip': '10.0.0.1',
            'method': 'GET', 'path': '/', 'status_code': 200,
            'response_time_ms': 5.0, 'bytes_sent': 100, 'decision': 'allowed',
        })

        csv_text = fresh_governor.export_csv()
        lines = csv_text.strip().split('\n')
        assert len(lines) == 2, "Should have header + 1 data row"
        header = lines[0]
        assert 'client_ip' in header
        assert 'status_code' in header
        assert 'method' in header

    def test_export_json_is_valid(self, fresh_governor):
        import json
        json_text = fresh_governor.export_json()
        data = json.loads(json_text)
        assert 'metrics' in data
        assert 'config' in data
        assert 'blocked_ips' in data

    def test_blocked_ips_list_structure(self, fresh_governor):
        ip = "10.0.0.10"
        # Trigger jail
        for _ in range(fresh_governor.limit + 1):
            fresh_governor.evaluate_request(ip)

        blocked = fresh_governor.get_blocked_ips_list()
        assert len(blocked) >= 1
        entry = blocked[0]
        assert 'ip' in entry
        assert 'remaining_seconds' in entry
        assert 'reason' in entry
        assert entry['ip'] == ip


class TestConfigUpdate:
    """Tests for live configuration updates."""

    def test_config_update_changes_limits(self, fresh_governor):
        original_limit = fresh_governor.limit
        fresh_governor.update_config({"request_limit": 100})
        assert fresh_governor.limit == 100
        assert fresh_governor.limit != original_limit

    def test_config_update_changes_window(self, fresh_governor):
        fresh_governor.update_config({"time_window": 30})
        assert fresh_governor.window == 30

    def test_config_update_changes_block_duration(self, fresh_governor):
        fresh_governor.update_config({"block_duration": 300})
        assert fresh_governor.block_ttl == 300

    def test_config_ignores_unknown_keys(self, fresh_governor):
        original_limit = fresh_governor.limit
        fresh_governor.update_config({"unknown_key": "value"})
        assert fresh_governor.limit == original_limit  # Unchanged


class TestThreadSafety:
    """
    Verifies that TrafficGovernor is safe under concurrent access.

    This matters because the proxy's select() loop and the dashboard API server
    run in separate threads, both accessing governor state. TrafficGovernor uses
    threading.Lock() around all public methods — these tests verify no races.
    """

    def test_concurrent_evaluate_request(self, fresh_governor):
        """Multiple threads calling evaluate_request simultaneously should not crash."""
        errors = []
        results = {'allowed': 0, 'blocked': 0}
        lock = threading.Lock()

        def worker(ip_suffix):
            try:
                for _ in range(20):
                    result = fresh_governor.evaluate_request(f"10.0.{ip_suffix}.1")
                    with lock:
                        if result:
                            results['allowed'] += 1
                        else:
                            results['blocked'] += 1
            except Exception as e:
                errors.append(str(e))

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=10)

        assert len(errors) == 0, f"Thread errors: {errors}"
        assert results['allowed'] + results['blocked'] == 200

    def test_concurrent_read_write(self, fresh_governor):
        """Readers (metrics/exports) running alongside writers (evaluate_request) should not crash."""
        errors = []

        def writer():
            try:
                for i in range(50):
                    fresh_governor.evaluate_request(f"10.1.0.{i % 256}")
                    fresh_governor.record_request({
                        'id': fresh_governor.next_request_id(),
                        'timestamp': time.time(),
                        'client_ip': f'10.1.0.{i % 256}',
                        'method': 'GET', 'path': '/',
                        'status_code': 200, 'response_time_ms': 1.0,
                        'bytes_sent': 10, 'decision': 'allowed',
                    })
            except Exception as e:
                errors.append(f"Writer: {e}")

        def reader():
            try:
                for _ in range(50):
                    fresh_governor.get_dashboard_metrics()
                    fresh_governor.get_charts_data()
                    fresh_governor.get_analytics()
                    fresh_governor.get_security_metrics()
                    fresh_governor.export_prometheus()
            except Exception as e:
                errors.append(f"Reader: {e}")

        threads = (
            [threading.Thread(target=writer) for _ in range(3)] +
            [threading.Thread(target=reader) for _ in range(3)]
        )
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=15)

        assert len(errors) == 0, f"Concurrent read/write errors: {errors}"


class TestTimelineAndLogs:
    """Tests for internal log buffer and timeline events."""

    def test_timeline_events_recorded_on_block(self, fresh_governor):
        ip = "10.0.0.20"
        for _ in range(fresh_governor.limit + 1):
            fresh_governor.evaluate_request(ip)

        events = fresh_governor.get_timeline_events(limit=50)
        block_events = [e for e in events if e.get('type') == 'ip_blocked']
        assert len(block_events) >= 1, "Should have at least one ip_blocked timeline event"

    def test_log_buffer_populated(self, fresh_governor):
        # record_request writes to the internal log buffer (evaluate_request alone does not)
        fresh_governor.record_request({
            'id': fresh_governor.next_request_id(),
            'timestamp': time.time(),
            'client_ip': '10.0.0.30',
            'method': 'GET',
            'path': '/',
            'status_code': 200,
            'response_time_ms': 1.0,
            'bytes_sent': 10,
            'decision': 'allowed',
        })
        logs = fresh_governor.get_logs_page(page=1, per_page=10)
        assert logs['total'] >= 1

    def test_log_filtering_by_level(self, fresh_governor):
        ip = "10.0.0.31"
        # Generate both INFO (allowed) and WARNING (blocked) logs
        for _ in range(fresh_governor.limit + 1):
            fresh_governor.evaluate_request(ip)

        warning_logs = fresh_governor.get_logs_page(page=1, per_page=100, level="WARNING")
        assert warning_logs['total'] >= 1, "Should have WARNING-level logs after blocking"

    def test_logs_download_text(self, fresh_governor):
        # Trigger a block event which writes to internal log buffer
        ip = "10.0.0.32"
        for _ in range(fresh_governor.limit + 1):
            fresh_governor.evaluate_request(ip)
        text = fresh_governor.get_all_logs_text()
        assert isinstance(text, str)
        assert len(text) > 0
