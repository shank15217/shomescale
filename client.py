# client.py
# Updated client with --bg for start, and status command.
# Enhanced help descriptions.
# Fixed wg-quick up/down by using absolute path for config and standardized to wg0.conf
# Fixed syncconf by generating conf without Interface for sync.
# Added chmod 0600 for conf files to avoid world accessible warning.
# Made PID_FILE and LOG_FILE absolute paths.
# Fixed syntax error in install_wireguard for elrepo install call.
# Added verification of listening port after update, with restart if mismatch.

import socket
import json
import subprocess
import os
import argparse
import time
import hashlib
import sys
import re

CONFIG_FILE = 'config.json'
WG_CONF_FILE = 'wg0.conf'
WG_INTERFACE = 'wg0'  # Default interface
HEARTBEAT_INTERVAL = 30  # seconds
PEER_CHECK_INTERVAL = 60  # seconds
HOSTS_FILE = '/etc/hosts'
MARKER_BEGIN = '# BEGIN SimpleTailscale Hosts'
MARKER_END = '# END SimpleTailscale Hosts'

def get_distro_info():
    info = {}
    if os.path.exists('/etc/os-release'):
        with open('/etc/os-release') as f:
            for line in f:
                if '=' in line:
                    key, val = line.strip().split('=', 1)
                    info[key] = val.strip('"')
    return info

def is_wireguard_installed():
    try:
        subprocess.check_call(['wg', '--version'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return True
    except (subprocess.CalledProcessError, FileNotFoundError):
        return False

def install_wireguard():
    if is_wireguard_installed():
        return
    print("WireGuard not found. Attempting to install...")
    
    distro_info = get_distro_info()
    distro_id = distro_info.get('ID', '').lower()
    id_like = distro_info.get('ID_LIKE', '').lower()
    version_id = distro_info.get('VERSION_ID', '')
    
    if 'ubuntu' in distro_id or 'debian' in distro_id or 'debian' in id_like:
        try:
            subprocess.check_call(['sudo', 'apt', 'update'], stdout=subprocess.DEVNULL)
            subprocess.check_call(['sudo', 'apt', 'install', 'wireguard', '-y'])
            print("WireGuard installed successfully on Ubuntu/Debian.")
        except subprocess.CalledProcessError as e:
            print(f"Failed to install WireGuard: {e}")
            sys.exit(1)
    
    elif 'rhel' in id_like or distro_id in ['rhel', 'rocky', 'centos', 'almalinux', 'redhat']:
        try:
            major_ver = int(version_id.split('.')[0]) if version_id else 0
            if major_ver >= 9:
                subprocess.check_call(['sudo', 'dnf', 'install', 'wireguard-tools', '-y'])
            else:
                subprocess.check_call(['sudo', 'dnf', 'install', 'https://dl.fedoraproject.org/pub/epel/epel-release-latest-8.noarch.rpm', '-y'])
                subprocess.check_call(['sudo', 'dnf', 'install', 'https://www.elrepo.org/elrepo-release-8.el8.elrepo.noarch.rpm', '-y'])
                subprocess.check_call(['sudo', 'dnf', 'install', 'kmod-wireguard', 'wireguard-tools', '-y'])
            print("WireGuard installed successfully on RedHat/Rocky-based system.")
        except subprocess.CalledProcessError as e:
            print(f"Failed to install WireGuard: {e}")
            sys.exit(1)
    
    else:
        print("Unsupported distribution. Please install WireGuard manually.")
        sys.exit(1)
    
    if not is_wireguard_installed():
        print("Installation failed. Please install WireGuard manually.")
        sys.exit(1)

def generate_keys():
    privkey = subprocess.check_output(['wg', 'genkey']).decode('utf-8').strip()
    pubkey = subprocess.check_output(['wg', 'pubkey'], input=privkey.encode('utf-8')).decode('utf-8').strip()
    return privkey, pubkey

def load_config():
    if os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE, 'r') as f:
            return json.load(f)
    return None

def save_config(config):
    with open(CONFIG_FILE, 'w') as f:
        json.dump(config, f)

def send_request(server_host, server_port, req):
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((server_host, server_port))
    client_socket.send(json.dumps(req).encode('utf-8'))
    resp_data = client_socket.recv(4096).decode('utf-8')
    response = json.loads(resp_data)
    client_socket.close()
    return response

def register(server_host, server_port, name, listen_port):
    install_wireguard()  # Check and install before generating keys
    config = load_config()
    if config:
        print("Already registered. Use 'start' to run the daemon.")
        return
    
    privkey, pubkey = generate_keys()
    
    req = {
        "action": "register",
        "name": name,
        "pubkey": pubkey,
        "port": listen_port
    }
    response = send_request(server_host, server_port, req)
    
    if response["status"] == "ok":
        config = {
            "name": name,
            "privkey": privkey,
            "pubkey": pubkey,
            "internal_ip": response["internal_ip"],
            "listen_port": listen_port
        }
        save_config(config)
        print(f"Registered successfully. Internal IP: {config['internal_ip']}")
    else:
        print(f"Registration failed: {response.get('msg', 'Unknown error')}")

def get_peers(server_host, server_port):
    req = {"action": "get_peers"}
    response = send_request(server_host, server_port, req)
    if response["status"] == "ok":
        return response["peers"]
    else:
        raise Exception("Failed to get peers")

def generate_conf(config, peers, include_interface=True):
    conf_content = ""
    if include_interface:
        conf_content = f"""[Interface]
Address = {config['internal_ip']}/24
PrivateKey = {config['privkey']}
ListenPort = {config['listen_port']}
"""
    
    for peer in peers:
        if peer['name'] == config['name']:
            continue
        conf_content += f"""
[Peer]
PublicKey = {peer['pubkey']}
AllowedIPs = {peer['allowed_ips']}
Endpoint = {peer['endpoint']}
PersistentKeepalive = 25
"""
    return conf_content

def update_wireguard(conf_content_full, conf_content_sync):
    # For sync, use conf_content_sync (no interface)
    temp_conf = 'wg_temp.conf'
    with open(temp_conf, 'w') as f:
        f.write(conf_content_sync)
    os.chmod(temp_conf, 0o600)
    
    abs_conf = os.path.abspath(WG_CONF_FILE)
    
    try:
        # Check if interface exists (use sudo for consistency, though root)
        subprocess.check_call(['sudo', 'wg', 'show', WG_INTERFACE], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        # If exists, syncconf
        subprocess.check_call(['sudo', 'wg', 'syncconf', WG_INTERFACE, temp_conf])
        print("WireGuard config synced.")
    except subprocess.CalledProcessError:
        # If not, quick up with full conf
        with open(WG_CONF_FILE, 'w') as f:
            f.write(conf_content_full)
        os.chmod(WG_CONF_FILE, 0o600)
        subprocess.check_call(['sudo', 'wg-quick', 'up', abs_conf])
        print("WireGuard interface brought up.")
    
    os.remove(temp_conf)
    
    # Update main conf with full
    with open(WG_CONF_FILE, 'w') as f:
        f.write(conf_content_full)
    os.chmod(WG_CONF_FILE, 0o600)

def verify_listening_port(config):
    try:
        output = subprocess.check_output(['sudo', 'wg', 'show', WG_INTERFACE]).decode('utf-8')
        match = re.search(r'listening port: (\d+)', output)
        if match:
            actual_port = int(match.group(1))
            if actual_port == config['listen_port']:
                print(f"Verified: Listening on configured port {actual_port}.")
                return True
            else:
                print(f"Warning: Listening on {actual_port} instead of configured {config['listen_port']}. Restarting interface...")
                return False
        else:
            print("Could not find listening port in wg show output.")
            return False
    except subprocess.CalledProcessError as e:
        print(f"Error checking listening port: {e}")
        return False

def restart_wireguard(abs_conf):
    try:
        subprocess.check_call(['sudo', 'wg-quick', 'down', abs_conf])
        subprocess.check_call(['sudo', 'wg-quick', 'up', abs_conf])
        print("WireGuard interface restarted.")
    except subprocess.CalledProcessError as e:
        print(f"Failed to restart WireGuard: {e}")

def is_interface_up():
    try:
        subprocess.check_call(['sudo', 'wg', 'show', WG_INTERFACE], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return True
    except subprocess.CalledProcessError:
        return False

def update_hosts(peers):
    # Generate new hosts section
    new_section = [MARKER_BEGIN]
    for peer in peers:
        new_section.append(f"{peer['internal_ip']} {peer['name']}")
    new_section.append(MARKER_END)
    new_section_str = '\n'.join(new_section) + '\n'
    
    # Print changes
    print("\nUpdated hosts entries:")
    for line in new_section[1:-1]:
        print(line)
    
    # Read current hosts file
    try:
        with open(HOSTS_FILE, 'r') as f:
            lines = f.readlines()
    except FileNotFoundError:
        lines = []
    
    # Remove old section if exists
    in_section = False
    new_lines = []
    for line in lines:
        stripped = line.strip()
        if stripped == MARKER_BEGIN:
            in_section = True
            continue
        if stripped == MARKER_END:
            in_section = False
            continue
        if not in_section:
            new_lines.append(line)
    
    # Append new section
    if new_lines and not new_lines[-1].endswith('\n'):
        new_lines.append('\n')
    new_lines.append(new_section_str)
    
    # Write back using sudo tee
    new_content = ''.join(new_lines)
    try:
        process = subprocess.Popen(['sudo', 'tee', HOSTS_FILE], stdin=subprocess.PIPE, stdout=subprocess.DEVNULL)
        process.communicate(input=new_content.encode('utf-8'))
        if process.returncode == 0:
            print(f"Successfully updated {HOSTS_FILE}.")
        else:
            print(f"Failed to update {HOSTS_FILE} (return code {process.returncode}).")
    except Exception as e:
        print(f"Error updating {HOSTS_FILE}: {e}")

def daemon(server_host, server_port):
    install_wireguard()  # Ensure installed before daemon starts
    config = load_config()
    if not config:
        print("Not registered. Run 'register' first.")
        return
    
    last_peers_hash = None
    last_peer_check = 0
    print("Starting daemon...")
    
    while True:
        try:
            # Send hello
            req = {
                "action": "hello",
                "name": config["name"],
                "port": config["listen_port"]
            }
            response = send_request(server_host, server_port, req)
            if response["status"] != "ok":
                print("Hello failed:", response.get("msg"))
            
            # Check peers periodically
            now = time.time()
            if now - last_peer_check > PEER_CHECK_INTERVAL:
                peers = get_peers(server_host, server_port)
                peers_json = json.dumps(peers, sort_keys=True)
                peers_hash = hashlib.sha256(peers_json.encode()).hexdigest()
                
                if peers_hash != last_peers_hash:
                    print("Peers changed, updating WireGuard and /etc/hosts...")
                    conf_content_full = generate_conf(config, peers, include_interface=True)
                    conf_content_sync = generate_conf(config, peers, include_interface=False)
                    update_wireguard(conf_content_full, conf_content_sync)
                    
                    # Verify listening port and restart if necessary
                    abs_conf = os.path.abspath(WG_CONF_FILE)
                    if not verify_listening_port(config):
                        restart_wireguard(abs_conf)
                        if verify_listening_port(config):
                            print("Port verified after restart.")
                        else:
                            print("Port verification failed even after restart. Check for port conflicts.")
                    
                    update_hosts(peers)
                    
                    last_peers_hash = peers_hash
                
                last_peer_check = now
            
        except Exception as e:
            print(f"Daemon error: {e}")
        
        time.sleep(HEARTBEAT_INTERVAL)

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

def is_daemon_running():
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
    if is_interface_up():
        try:
            abs_conf = os.path.abspath(WG_CONF_FILE)
            subprocess.check_call(['sudo', 'wg-quick', 'down', abs_conf])
            print("WireGuard interface down.")
        except subprocess.CalledProcessError as e:
            print(f"Failed to bring down WireGuard: {e}")
    else:
        print("WireGuard interface not up.")
    
    # Clean up hosts
    try:
        with open(HOSTS_FILE, 'r') as f:
            lines = f.readlines()
    except FileNotFoundError:
        return
    
    in_section = False
    new_lines = []
    for line in lines:
        stripped = line.strip()
        if stripped == MARKER_BEGIN:
            in_section = True
            continue
        if stripped == MARKER_END:
            in_section = False
            continue
        if not in_section:
            new_lines.append(line)
    
    new_content = ''.join(new_lines)
    process = subprocess.Popen(['sudo', 'tee', HOSTS_FILE], stdin=subprocess.PIPE, stdout=subprocess.DEVNULL)
    process.communicate(input=new_content.encode('utf-8'))
    if process.returncode == 0:
        print(f"Cleaned up {HOSTS_FILE}.")
    else:
        print(f"Failed to clean up {HOSTS_FILE}.")
    
    # Stop daemon if running
    if is_daemon_running():
        with open(PID_FILE, 'r') as f:
            pid = int(f.read().strip())
        try:
            os.kill(pid, 15)  # SIGTERM
            print("Daemon stopped.")
            os.remove(PID_FILE)
        except OSError as e:
            print(f"Failed to stop daemon: {e}")
    else:
        print("Daemon not running.")

def status(server_host=None, server_port=10000):
    config = load_config()
    running = is_daemon_running()
    interface_up = is_interface_up()
    
    print(f"Daemon running: {running}")
    print(f"WireGuard interface up: {interface_up}")
    
    if config:
        print(f"Name: {config['name']}")
        print(f"Internal IP: {config['internal_ip']}")
        print(f"Listen Port: {config['listen_port']}")
    else:
        print("Not registered.")
    
    if server_host:
        try:
            peers = get_peers(server_host, server_port)
            print("Online peers:")
            for peer in peers:
                print(f"- {peer['name']}: {peer['internal_ip']}, Endpoint: {peer['endpoint']}")
        except Exception as e:
            print(f"Failed to fetch peers: {e}")
    else:
        print("Provide --server to fetch online peers.")

def main():
    global PID_FILE, CLIENT_LOG_FILE
    PID_FILE = os.path.abspath('client.pid')
    CLIENT_LOG_FILE = os.path.abspath('client.log')
    
    parser = argparse.ArgumentParser(
        description="""Simple Tailscale-like client for WireGuard overlay network.

This client registers with a central directory server, sets up WireGuard tunnels to other peers, and maintains connections via periodic heartbeats and updates. It creates a P2P mesh network where data flows directly between peers, with automatic /etc/hosts updates for name resolution.

Key features:
- Auto-installs WireGuard if missing (supports Ubuntu/Debian, RedHat/Rocky)
- Generates WireGuard keys on registration
- Daemon mode for heartbeats (every 30s) and peer checks (every 60s)
- Updates WireGuard config without downtime (using wg syncconf)
- Manages /etc/hosts entries with markers for easy cleanup
- Background mode (--bg) daemonizes with logs to client.log

Usage: python client.py <command> [options]

Note: Requires sudo for WireGuard operations and /etc/hosts updates (assume passwordless sudo or run with sudo).
""",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    subparsers = parser.add_subparsers(dest='command', required=True)
    
    # Register command
    reg_parser = subparsers.add_parser('register', help='Register this node with the server')
    reg_parser.add_argument('--server', required=True, help='Server hostname or IP address')
    reg_parser.add_argument('--server-port', type=int, default=10000, help='Server TCP port (default: 10000)')
    reg_parser.add_argument('--name', required=True, help='Unique name for this node')
    reg_parser.add_argument('--listen-port', type=int, default=51820, help='UDP port for WireGuard to listen on (default: 51820; ensure port-forwarded if behind NAT)')
    reg_parser.set_defaults(func=register)
    
    # Start daemon command
    start_parser = subparsers.add_parser('start', help='Start the client daemon for heartbeats and auto-updates')
    start_parser.add_argument('--server', required=True, help='Server hostname or IP address')
    start_parser.add_argument('--server-port', type=int, default=10000, help='Server TCP port (default: 10000)')
    start_parser.add_argument('--bg', action='store_true', help='Run the daemon in background mode (daemonizes the process, logs to client.log)')
    start_parser.set_defaults(func=daemon)
    
    # Stop command
    stop_parser = subparsers.add_parser('stop', help='Stop the daemon, bring down WireGuard interface, and clean up /etc/hosts')
    stop_parser.set_defaults(func=stop)
    
    # Status command
    status_parser = subparsers.add_parser('status', help='Check client status, daemon/interface state, and optionally fetch online peers')
    status_parser.add_argument('--server', help='Server hostname or IP to fetch current online peers')
    status_parser.add_argument('--server-port', type=int, default=10000, help='Server TCP port (default: 10000)')
    status_parser.set_defaults(func=status)
    
    args = parser.parse_args()
    if hasattr(args, 'func'):
        if args.command == 'register':
            args.func(args.server, args.server_port, args.name, args.listen_port)
        elif args.command == 'start':
            if args.bg:
                daemonize(CLIENT_LOG_FILE)
            args.func(args.server, args.server_port)
        elif args.command == 'stop':
            args.func()
        elif args.command == 'status':
            args.func(args.server, args.server_port)

if __name__ == "__main__":
    main()
