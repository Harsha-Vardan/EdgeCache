import socket
import select
import time
import sys
import json
import logging
import threading
from collections import deque

# --- CONFIGURATION ---
CONFIG_FILE = 'config.json'

def load_config():
    default_config = {
        "host": "0.0.0.0",
        "port": 8080,
        "backend_host": "127.0.0.1",
        "backend_port": 80,
        "request_limit": 10,
        "time_window": 5,
        "block_duration": 60
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
file_handler = logging.FileHandler('edgeguard.log')
file_handler.setFormatter(JSONFormatter())
stream_handler = logging.StreamHandler(sys.stdout)
stream_handler.setFormatter(JSONFormatter())
logger.addHandler(file_handler)
logger.addHandler(stream_handler)


# --- TRAFFIC GOVERNOR ---
class TrafficGovernor:
    def __init__(self):
        self.limit = config['request_limit']
        self.window = config['time_window']
        self.block_ttl = config['block_duration']
        
        # ip -> deque of timestamps
        self.request_history = {}  
        # ip -> unjail_timestamp
        self.jail = {}     
        # ip -> stats dict
        self.ip_stats = {}        
        self.lock = threading.Lock()
        
        self.active_connections = 0
        self.total_requests = 0
        
        self._load_jail()

        # Start cleanup daemon
        self.cleanup_thread = threading.Thread(target=self._jail_cleanup_daemon, daemon=True)
        self.cleanup_thread.start()

    def _load_jail(self):
        try:
            with open('blocked_ips.txt', 'r') as f:
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
                with open('blocked_ips.txt', 'w') as f:
                    current_time = time.time()
                    for ip, unjail_ts in self.jail.items():
                        if unjail_ts > current_time:
                            f.write(f"{ip},{unjail_ts}\n")
            except Exception as e:
                logger.error(f"Failed to save state: {e}", extra={'event': 'STATE_SAVE_ERROR'})

    def _jail_cleanup_daemon(self):
        while True:
            time.sleep(10) # Run cleanup sweep every 10 seconds
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

    def get_or_create_stats(self, ip):
        if ip not in self.ip_stats:
            self.ip_stats[ip] = {"requests": 0, "blocked_count": 0, "last_seen": 0}
        return self.ip_stats[ip]

    def evaluate_request(self, ip):
        current_time = time.time()
        
        with self.lock:
            self.total_requests += 1
            stats = self.get_or_create_stats(ip)
            stats["requests"] += 1
            stats["last_seen"] = current_time
            
            # Check Jail (TTL logic)
            if ip in self.jail:
                if current_time < self.jail[ip]:
                    stats["blocked_count"] += 1
                    return False
                else:
                    del self.jail[ip]
                    logger.info("TTL expired on evaluation", extra={'ip': ip, 'event': 'UNJAILED'})
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
                logger.warning("Rate limit exceeded", extra={'ip': ip, 'event': 'BLOCKED'})
                return False
                
            history.append(current_time)
            logger.info("Connection allowed", extra={'ip': ip, 'event': 'ALLOWED'})
            return True

    def connection_opened(self):
        with self.lock:
            self.active_connections += 1

    def connection_closed(self):
        with self.lock:
            self.active_connections -= 1

    def get_metrics(self):
        with self.lock:
            return {
                "active_connections": self.active_connections,
                "total_requests": self.total_requests,
                "blocked_ips": len(self.jail)
            }


governor = TrafficGovernor()

# --- REVERSE PROXY & SELECT I/O ---
def main():
    logger.info("Initializing EdgeGuard Select I/O Engine...", extra={'event': 'STARTUP'})
    
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.setblocking(False)
    
    host, port = config['host'], config['port']
    backend_host, backend_port = config['backend_host'], config['backend_port']
    
    try:
        server.bind((host, port))
        server.listen(100)
        logger.info(f"TCP Listener active on {host}:{port}", extra={'event': 'BIND'})
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
    message_queues = {} # socket -> bytes to send
    socket_ips = {}     # socket -> ip
    
    def cleanup_connection(s):
        if s in inputs:
            inputs.remove(s)
        if s in outputs:
            outputs.remove(s)
        if s in message_queues:
            del message_queues[s]
            
        # Clean paired sockets if existing
        if s in client_to_backend:
            backend_sock = client_to_backend[s]
            cleanup_connection(backend_sock)
            del client_to_backend[s]
            governor.connection_closed()
            
        elif s in backend_to_client:
            client_sock = backend_to_client[s]
            cleanup_connection(client_sock)
            del backend_to_client[s]
            
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
                    client_socket, client_address = s.accept()
                    client_socket.setblocking(False)
                    ip = client_address[0]
                    
                    governor.connection_opened()
                    socket_ips[client_socket] = ip
                    
                    allowed = governor.evaluate_request(ip)
                    if not allowed:
                        inputs.append(client_socket)
                        outputs.append(client_socket)
                        message_queues[client_socket] = b"HTTP/1.1 429 Too Many Requests\r\nConnection: close\r\n\r\nBlocked by EdgeGuard.\n"
                    else:
                        inputs.append(client_socket)
                        message_queues[client_socket] = b""
                        
                else:
                    # Handle active reading (proxy or client payload)
                    try:
                        data = s.recv(4096)
                    except ConnectionResetError:
                        data = b""
                        
                    if data:
                        # Check if this is a fresh client socket that hasn't triggered backend connect
                        if s in socket_ips and s not in client_to_backend and s not in backend_to_client:
                            
                            header_line = data.split(b'\r\n')[0].decode('utf-8', errors='ignore')
                            
                            if header_line.startswith("GET /metrics"):
                                metrics = governor.get_metrics()
                                body = (f"edgeguard_active_connections {metrics['active_connections']}\n"
                                        f"edgeguard_total_requests {metrics['total_requests']}\n"
                                        f"edgeguard_blocked_ips {metrics['blocked_ips']}\n")
                                resp = f"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {len(body)}\r\nConnection: close\r\n\r\n{body}"
                                message_queues[s] = resp.encode('utf-8')
                                if s not in outputs:
                                    outputs.append(s)
                                continue # Short circuit; do not proxy this edge route
                                
                            else:
                                # Normal traffic -> spin up proxy connection asynchronously
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
                                    message_queues[backend_sock] = b""
                                except Exception as e:
                                    logger.error(f"Failed to connect to backend: {e}", extra={'event': 'PROXY_ERROR'})
                                    resp = b"HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\nBackend Unavailable.\n"
                                    message_queues[s] += resp
                                    if s not in outputs:
                                        outputs.append(s)
                                    continue

                        # Route data symmetrically
                        if s in client_to_backend:
                            target = client_to_backend[s]
                            message_queues[target] += data
                            if target not in outputs:
                                outputs.append(target)
                        elif s in backend_to_client:
                            target = backend_to_client[s]
                            message_queues[target] += data
                            if target not in outputs:
                                outputs.append(target)

                    else:
                        cleanup_connection(s)

            for s in writable:
                try:
                    next_msg = message_queues.get(s, b"")
                    if next_msg:
                        sent = s.send(next_msg)
                        message_queues[s] = next_msg[sent:]
                    else:
                        outputs.remove(s)
                        
                        # Close client if it was purely answered internally (429 or metrics)
                        if s in socket_ips and s not in client_to_backend:
                            cleanup_connection(s)
                            
                except OSError as e:
                    cleanup_connection(s)

            for s in exceptional:
                cleanup_connection(s)

    except KeyboardInterrupt:
        logger.info("SIGINT Caught: Graceful Shutdown Initiated.", extra={'event': 'SHUTDOWN'})
    finally:
        running = False
        logger.info("Flushing state and closing all sockets...", extra={'event': 'CLEANUP'})
        governor.save_jail()
        for s in inputs:
            s.close()
        logger.info("EdgeGuard shut down cleanly.", extra={'event': 'EXIT'})

if __name__ == "__main__":
    main()
