# EdgeGuard (EdgeCache)

EdgeGuard is a lightweight, high-performance Traffic Governance Engine and Reverse Proxy built entirely in Python. It is designed to sit in front of your backend services to protect them from abuse, rate-limit excessive requests, and provide real-time metrics, all while maintaining minimal overhead using non-blocking I/O.

## Features

* **Asynchronous Select I/O**: Utilizes Python's `select` module for true non-blocking, event-driven networking capable of handling many concurrent connections on a single thread.
* **Smart Rate Limiting**: Implements a sliding window rate-limiting algorithm to track requests per IP address.
* **Automated Jail (IP Blocking)**: Automatically blocks IP addresses that exceed the configured request limits for a specified TTL (Time To Live).
* **Daemon Cleanup**: A background daemon continuously sweeps and unjails IP addresses once their block duration expires.
* **Persistent State**: Saves jailed IP addresses to disk (`blocked_ips.txt`) during shutdown and reloads them on startup to ensure protection survives restarts.
* **Real-time Metrics**: Exposes a `/metrics` endpoint (HTTP endpoint built directly into the TCP socket) for monitoring active connections, total requests, and currently blocked IPs.
* **Configurable**: Fully customizable via `config.json` (host, ports, limits, windows, block durations).
* **Structured Logging**: Outputs logs in JSON format for easy ingestion into log aggregators, keeping track of connections, blocks, and system events.

## Architecture

EdgeGuard operates as a transparent TCP reverse proxy.
1. It listens for incoming connections on a configurable port (default `8080`).
2. When a connection is established, the embedded `TrafficGovernor` evaluates the client's IP against the rate limits and jail history.
3. If allowed, EdgeGuard asynchronously opens a connection to the configured backend (e.g., an Apache web server on port `80`) and forwards the traffic transparently in both directions.
4. If rate-limited, EdgeGuard intercepts the request, returns an HTTP 429 "Too Many Requests" response directly to the client, and immediately closes the connection without ever touching the backend.

## Getting Started

### Prerequisites

* Python 3.10+
* (Optional) Docker and Docker Compose

### Running Locally (Native)

1. Clone the repository.
2. Ensure you have a backend service running (by default, EdgeGuard expects a service on `127.0.0.1:80`). You can tweak this in `config.json`.
3. Run the engine:
   ```bash
   python edgeguard.py
   ```

### Running with Docker

EdgeGuard includes a `Dockerfile` and `docker-compose.yml` for easy containerization. This is the recommended way to run it in production-like environments or on WSL/Linux.

1. Build and start the container in detached mode:
   ```bash
   docker-compose up -d --build
   ```
2. View the structured logs:
   ```bash
   docker-compose logs -f edgeguard
   ```

## Configuration

Modify `config.json` to tune the engine to your needs:

```json
{
    "host": "0.0.0.0",
    "port": 8080,
    "backend_host": "127.0.0.1",
    "backend_port": 80,
    "request_limit": 10,
    "time_window": 5,
    "block_duration": 60
}
```
* **`request_limit`**: Maximum number of requests allowed within the `time_window`.
* **`time_window`**: The sliding window timeframe in seconds over which requests are counted.
* **`block_duration`**: How long (in seconds) an IP should be jailed if it exceeds the limit. (e.g., 10 requests in 5 seconds results in a 60-second block).

## Testing

A `test_client.py` script is included to simulate traffic and verify the rate-limiting and jailing mechanisms.

1. Start EdgeGuard.
2. In a separate terminal, run the test script:
   ```bash
   python test_client.py
   ```
This script will hammer the server with requests to intentionally trigger the rate limiter and demonstrate the HTTP 429 response and the automatic unjailing process.

## Checking Metrics

You can retrieve real-time operational metrics by sending an HTTP GET request to `/metrics` directly on the EdgeGuard port:

```bash
curl http://localhost:8080/metrics
```
*Example Output:*
```text
edgeguard_active_connections 0
edgeguard_total_requests 142
edgeguard_blocked_ips 1
```

## Disclaimer

This is an MVP (Minimum Viable Product) traffic governance engine. While it handles concurrency well using select I/O, it is designed primarily for educational purposes, small services, and demonstrating networking concepts in Python. For enterprise-scale DDoS protection, consider established solutions like Cloudflare, HAProxy, or NGINX.
