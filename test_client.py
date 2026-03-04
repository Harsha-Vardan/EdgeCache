import socket
import threading
import time

TARGET_HOST = '127.0.0.1'
TARGET_PORT = 8080

def send_request(thread_id, req_id, path="/"):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(2.0)
            s.connect((TARGET_HOST, TARGET_PORT))
            req = f"GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
            s.sendall(req.encode('utf-8'))
            
            response = b""
            while True:
                chunk = s.recv(4096)
                if not chunk:
                    break
                response += chunk
                
            resp_str = response.decode('utf-8', errors='ignore')
            headers, _, body = resp_str.partition('\r\n\r\n')
            status_line = headers.split('\r\n')[0]
            
            server_name = ""
            for line in headers.split('\r\n'):
                if line.lower().startswith('server:'):
                    server_name = line
                    
            if path == "/metrics":
                print(f"[Metrics Target] -> {status_line}\n{body}")
            else:
                desc = f"{status_line}"
                if server_name:
                    desc += f" ({server_name})"
                print(f"[Req-{req_id:>2}] {desc}")
    except Exception as e:
        print(f"[Req-{req_id:>2}] Error: {e}")

if __name__ == "__main__":
    print("=== Testing Professional EdgeGuard ===")
    
    print("\n[Phase 1] Rapid connections firing (Limit configured as 10 per 5s)")
    threads = []
    for i in range(12):
        t = threading.Thread(target=send_request, args=(1, i+1))
        threads.append(t)
        t.start()
        time.sleep(0.05)
    
    for t in threads:
        t.join()

    print("\n[Phase 2] Confirming Prometheus /metrics logic...")
    send_request(2, 99, path="/metrics")
    
    print("\nTest simulation completed.")
