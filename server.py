# server.py
# Updated directory server with commands: start [--bg], status, stop.
# Enhanced help descriptions. Fixed global ip_counter issue.
# Changed internal IP range to 100.64.0.0/24 to avoid conflicts.
# Made PID_FILE, LOG_FILE, and PEERS_FILE absolute paths.
# Create empty peers.json on startup if missing.

import socket
import json
import threading
import os
import time
import sys
import argparse

def load_peers(peers_file):
    peers = {}
    ip_counter = 1
    if os.path.exists(peers_file):
        with open(peers_file, 'r') as f:
            peers = json.load(f)
        if peers:
            ip_counter = max(int(info['internal_ip'].split('.')[-1]) for info in peers.values()) + 1
        # Reset last_hello for persisted online peers
        now = time.time()
        for info in peers.values():
            if info.get('online', False):
                info['last_hello'] = now
            else:
                info['online'] = False  # Ensure offline if not set
                info['last_hello'] = 0
    else:
        # Create empty if not exists
        with open(peers_file, 'w') as f:
            json.dump(peers, f)
    return peers, ip_counter

TIMEOUT = 60  # seconds

def save_peers(peers_file):
    with open(peers_file, 'w') as f:
        json.dump(peers, f)

def handle_client(conn, addr):
    try:
        data = conn.recv(4096).decode('utf-8')
        req = json.loads(data)
        
        response = {}
        
        if req["action"] == "register":
            name = req["name"]
            if name in peers:
                response = {"status": "error", "msg": "Name already taken"}
            else:
                global ip_counter
                internal_ip = f"100.64.0.{ip_counter}"
                peers[name] = {
                    "pubkey": req["pubkey"],
                    "endpoint": f"{addr[0]}:{req['port']}",
                    "internal_ip": internal_ip,
                    "online": True,
                    "last_hello": time.time()
                }
                ip_counter += 1
                save_peers(PEERS_FILE)
                response = {"status": "ok", "internal_ip": internal_ip}
        
        elif req["action"] == "hello":
            name = req["name"]
            if name not in peers:
                response = {"status": "error", "msg": "Unknown name"}
            else:
                peers[name]["endpoint"] = f"{addr[0]}:{req['port']}"
                peers[name]["last_hello"] = time.time()
                peers[name]["online"] = True
                save_peers(PEERS_FILE)
                response = {"status": "ok"}
        
        elif req["action"] == "get_peers":
            peer_list = []
            for name, info in peers.items():
                if info["online"]:
                    peer_list.append({
                        "name": name,
                        "pubkey": info["pubkey"],
                        "endpoint": info["endpoint"],
                        "internal_ip": info["internal_ip"],
                        "allowed_ips": info["internal_ip"] + "/32"
                    })
            response = {"status": "ok", "peers": peer_list}
        
        conn.send(json.dumps(response).encode('utf-8'))
    except Exception as e:
        print(f"Error handling client: {e}")
    finally:
        conn.close()

def timeout_checker():
    while True:
        now = time.time()
        for info in peers.values():
            if info["last_hello"] < now - TIMEOUT:
                info["online"] = False
        save_peers(PEERS_FILE)
        time.sleep(30)  # Check every 30s

def start_server(host='0.0.0.0', port=10000):
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((host, port))
    server_socket.listen(5)
    print(f"Server listening on {host}:{port}")
    
    threading.Thread(target=timeout_checker, daemon=True).start()
    
    while True:
        conn, addr = server_socket.accept()
        threading.Thread(target=handle_client, args=(conn, addr)).start()

def daemonize(log_file):
    try:
        pid = os.fork()
        if pid > 0:
            sys.exit(0)
    except OSError as e:
        print(f"Fork #1 failed: {e}")
        sys.exit(1)
    
    os.chdir('/')
    os.setsid()
    os.umask(0)
    
    try:
        pid = os.fork()
        if pid > 0:
            sys.exit(0)
    except OSError as e:
        print(f"Fork #2 failed: {e}")
        sys.exit(1)
    
    sys.stdout.flush()
    sys.stderr.flush()
    
    with open('/dev/null', 'r') as dev_null:
        os.dup2(dev_null.fileno(), sys.stdin.fileno())
    with open(log_file, 'a') as log:
        os.dup2(log.fileno(), sys.stdout.fileno())
        os.dup2(log.fileno(), sys.stderr.fileno())
    
    pid = os.getpid()
    with open(PID_FILE, 'w') as f:
        f.write(str(pid))

def is_running():
    if os.path.exists(PID_FILE):
        try:
            with open(PID_FILE, 'r') as f:
                pid = int(f.read().strip())
            os.kill(pid, 0)
            return True
        except (OSError, ValueError):
            return False
    return False

def stop():
    if is_running():
        with open(PID_FILE, 'r') as f:
            pid = int(f.read().strip())
        try:
            os.kill(pid, 15)  # SIGTERM
            print("Server stopped.")
            os.remove(PID_FILE)
        except OSError as e:
            print(f"Failed to stop server: {e}")
    else:
        print("Server not running.")

def status():
    running = is_running()
    print(f"Server running: {running}")
    if os.path.exists(PEERS_FILE):
        with open(PEERS_FILE, 'r') as f:
            peers_data = json.load(f)
        print("Registered peers:")
        for name, info in peers_data.items():
            online_str = "Online" if info.get('online', False) else "Offline"
            print(f"- {name}: {info['internal_ip']}, {online_str}, Endpoint: {info.get('endpoint', 'N/A')}")
    else:
        print("No peers registered.")

def main():
    global PID_FILE, SERVER_LOG_FILE, PEERS_FILE, peers, ip_counter
    PID_FILE = os.path.abspath('server.pid')
    SERVER_LOG_FILE = os.path.abspath('server.log')
    PEERS_FILE = os.path.abspath('peers.json')
    peers, ip_counter = load_peers(PEERS_FILE)
    
    parser = argparse.ArgumentParser(
        description="""Simple Tailscale-like directory server.

This server acts as a central registry for peers in a WireGuard-based overlay network. It handles peer registration, assigns unique internal IPs, tracks online status via periodic heartbeats, and provides lists of online peers for clients to configure their WireGuard tunnels. Peers connect directly to each other for data traffic (P2P mesh), with the server only used for coordination.

Key features:
- Persistent storage in peers.json
- Automatic offline detection after 60s without heartbeat
- Endpoint updates for dynamic IPs
- No authentication (use in trusted environments)

Usage: python server.py <command> [options]
""",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    subparsers = parser.add_subparsers(dest='command', required=True)
    
    # Start command
    start_parser = subparsers.add_parser('start', help='Start the server daemon')
    start_parser.add_argument('--bg', action='store_true', help='Run the server in background mode (daemonizes the process, logs to server.log)')
    start_parser.set_defaults(func=start_server)
    
    # Status command
    status_parser = subparsers.add_parser('status', help='Check server status and list registered peers')
    status_parser.set_defaults(func=status)
    
    # Stop command
    stop_parser = subparsers.add_parser('stop', help='Stop the server daemon')
    stop_parser.set_defaults(func=stop)
    
    args = parser.parse_args()
    
    if args.command == 'start':
        if args.bg:
            daemonize(SERVER_LOG_FILE)
        args.func()
    elif args.command == 'status':
        args.func()
    elif args.command == 'stop':
        args.func()

if __name__ == "__main__":
    main()

