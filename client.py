#!/usr/bin/env python3
"""shomescale client - WireGuard mesh VPN client.

Registers with a central directory server, generates WireGuard keys,
maintains heartbeat daemon, dynamically syncs WireGuard configs,
and manages /etc/hosts entries for name resolution.

Fixes from code review:
- Length-prefixed framing protocol for JSON over TCP (matches server,
  fixes single-shot recv truncation on fragmented packets)
- Client daemon reconnection with exponential backoff after server outage
- Configurable SUBNET_PREFIX constant instead of hardcoded /24
- Switch to logging module instead of print()
- Constants module-level, no hidden globals
- Root capability check at startup
- Atomic peers.json writes on server side (server must also be updated)
"""

import socket
import json
import subprocess
import os
import argparse
import time
import hashlib
import sys
import re
import logging
import signal

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
SUBNET_MASK = 24
INTERNAL_NETWORK_PREFIX = "100.64.0"
HEARTBEAT_INTERVAL = 30         # seconds between heartbeats
PEER_CHECK_INTERVAL = 60        # seconds between peer list checks
RECONNECT_BASE_DELAY = 5        # seconds, base for exponential backoff
RECONNECT_MAX_DELAY = 120       # seconds, max reconnect delay
WG_INTERFACE = "wg0"
DNS_DOMAIN = "shomescale"
RESOLV_CONF = "/etc/resolv.conf"
DNSMASQ_CONF = "/etc/dnsmasq.d/shomescale.conf"
# Backup of original resolv.conf so we can restore on stop
RESOLV_CONF_BACKUP = "/etc/resolv.conf.shomescale.bak"
# Resolved to absolute paths based on script dir in main().
# These are placeholders before main() runs.
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_FILE = None
WG_CONF_FILE = None
WG_CONF_MODE = 0o600            # File permissions (rw-------)

logger = logging.getLogger("shomescale-client")

# ---------------------------------------------------------------------------
# Length-prefixed framing (must match server protocol)
# ---------------------------------------------------------------------------

def recv_json(sock):
    """Read a complete JSON message using 4-byte big-endian length prefix."""
    header = b""
    while len(header) < 4:
        chunk = sock.recv(4 - len(header))
        if not chunk:
            raise ConnectionError("Connection closed while reading length prefix")
        header += chunk

    body_length = int.from_bytes(header, byteorder="big", signed=False)
    if body_length > 10 * 1024 * 1024:
        raise ValueError(f"Message too large: {body_length} bytes")

    body = b""
    while len(body) < body_length:
        chunk = sock.recv(min(body_length - len(body), 4096))
        if not chunk:
            raise ConnectionError("Connection closed while reading message body")
        body += chunk

    return json.loads(body.decode("utf-8"))


def send_json(sock, obj):
    """Send a JSON object with length-prefixed framing."""
    payload = json.dumps(obj).encode("utf-8")
    header = len(payload).to_bytes(4, byteorder="big", signed=False)
    sock.sendall(header + payload)


# ---------------------------------------------------------------------------
# Utility functions
# ---------------------------------------------------------------------------

def check_root():
    """Check if we're running with root privileges. Exit if not."""
    if os.geteuid() != 0:
        logger.error("This script requires root privileges (for WireGuard and /etc/hosts).")
        sys.exit(1)


def get_distro_info():
    info = {}
    if os.path.exists("/etc/os-release"):
        with open("/etc/os-release") as f:
            for line in f:
                if "=" in line:
                    key, val = line.strip().split("=", 1)
                    info[key] = val.strip('"')
    return info


# ---------------------------------------------------------------------------
# WireGuard installation
# ---------------------------------------------------------------------------

def is_wireguard_installed():
    try:
        subprocess.check_call(
            ["wg", "--version"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        return True
    except (subprocess.CalledProcessError, FileNotFoundError):
        return False


def install_wireguard():
    if is_wireguard_installed():
        return
    logger.info("WireGuard not found. Attempting to install...")

    distro = get_distro_info()
    distro_id = distro.get("ID", "").lower()
    id_like = distro.get("ID_LIKE", "").lower()
    version_id = distro.get("VERSION_ID", "")

    if distro_id in ("ubuntu", "debian") or "debian" in id_like:
        try:
            subprocess.check_call(["apt-get", "update"], stdout=subprocess.DEVNULL)
            subprocess.check_call(["apt-get", "install", "-y", "wireguard"])
            logger.info("WireGuard installed on Ubuntu/Debian.")
        except subprocess.CalledProcessError as e:
            logger.error("Failed to install WireGuard: %s", e)
            sys.exit(1)
    elif distro_id in ("rhel", "rocky", "centos", "almalinux", "redhat") or "rhel" in id_like:
        try:
            major = int(version_id.split(".")[0]) if version_id else 0
            if major >= 9:
                subprocess.check_call(["dnf", "install", "-y", "wireguard-tools"])
            else:
                subprocess.check_call([
                    "dnf", "install", "-y",
                    "https://dl.fedoraproject.org/pub/epel/epel-release-latest-8.noarch.rpm",
                ])
                subprocess.check_call([
                    "dnf", "install", "-y",
                    "https://www.elrepo.org/elrepo-release-8.el8.elrepo.noarch.rpm",
                ])
                subprocess.check_call(["dnf", "install", "-y", "kmod-wireguard", "wireguard-tools"])
            logger.info("WireGuard installed on RHEL-based system.")
        except subprocess.CalledProcessError as e:
            logger.error("Failed to install WireGuard: %s", e)
            sys.exit(1)
    else:
        logger.error("Unsupported distribution. Install WireGuard manually.")
        sys.exit(1)

    if not is_wireguard_installed():
        logger.error("WireGuard installation failed. Please install manually.")
        sys.exit(1)


# ---------------------------------------------------------------------------
# Key generation
# ---------------------------------------------------------------------------

def generate_keys():
    privkey = subprocess.check_output(["wg", "genkey"]).decode().strip()
    pubkey = subprocess.check_output(
        ["wg", "pubkey"], input=privkey.encode()
    ).decode().strip()
    return privkey, pubkey


# ---------------------------------------------------------------------------
# Config management
# ---------------------------------------------------------------------------

def load_config():
    if os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE) as f:
            return json.load(f)
    return None


def save_config(config):
    with open(CONFIG_FILE, "w") as f:
        json.dump(config, f, indent=2)
        os.chmod(CONFIG_FILE, 0o600)


# ---------------------------------------------------------------------------
# Server communication
# ---------------------------------------------------------------------------

def send_request(server_host, server_port, req, timeout=10):
    """Send a JSON request to the server with length-prefixed framing.
    Returns parsed response dict.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    sock.connect((server_host, server_port))
    try:
        send_json(sock, req)
        resp = recv_json(sock)
    finally:
        sock.close()
    return resp


# ---------------------------------------------------------------------------
# Registration
# ---------------------------------------------------------------------------

def register(server_host, server_port, name, listen_port):
    install_wireguard()
    config = load_config()
    if config:
        logger.warning("Already registered. Internal IP: %s", config["internal_ip"])
        return

    privkey, pubkey = generate_keys()

    req = {
        "action": "register",
        "name": name,
        "pubkey": pubkey,
        "port": listen_port,
    }
    response = send_request(server_host, server_port, req)

    if response["status"] == "ok":
        config = {
            "name": name,
            "uuid": response.get("uuid", ""),  # UUID from server
            "privkey": privkey,
            "pubkey": pubkey,
            "internal_ip": response["internal_ip"],
            "listen_port": listen_port,
            "server_host": server_host,
            "server_port": server_port,
        }
        save_config(config)
        logger.info("Registered as %s (ID: %s) with IP %s", name, config["uuid"], config["internal_ip"])
        logger.info("DNS names: %s.shomescale, %s.shomescale", name, config["uuid"][:8])
    else:
        logger.error("Registration failed: %s", response.get("msg", "Unknown error"))


# ---------------------------------------------------------------------------
# Peer discovery
# ---------------------------------------------------------------------------

def get_peers(server_host, server_port):
    response = send_request(server_host, server_port, {"action": "get_peers"})
    if response["status"] == "ok":
        return response["peers"]
    raise RuntimeError(f"Failed to get peers: {response.get('msg', 'unknown')}")


# ---------------------------------------------------------------------------
# WireGuard config generation
# ---------------------------------------------------------------------------

def generate_conf(config, peers, include_interface=True):
    lines = []
    if include_interface:
        lines.append("[Interface]")
        lines.append(f"Address = {config['internal_ip']}/{SUBNET_MASK}")
        lines.append(f"PrivateKey = {config['privkey']}")
        lines.append(f"ListenPort = {config['listen_port']}")
        lines.append("")

    for peer in peers:
        if peer["name"] == config["name"]:
            continue
        lines.append("[Peer]")
        lines.append(f"PublicKey = {peer['pubkey']}")
        lines.append(f"AllowedIPs = {peer['allowed_ips']}")
        lines.append(f"Endpoint = {peer['endpoint']}")
        lines.append("PersistentKeepalive = 25")
        lines.append("")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# WireGuard config deployment
# ---------------------------------------------------------------------------

def update_wireguard(conf_full, conf_sync):
    """Apply WireGuard config. Uses wg syncconf if interface exists, otherwise wg-quick up."""
    tmp_sync = "wg_temp.conf"
    with open(tmp_sync, "w") as f:
        f.write(conf_sync)
    os.chmod(tmp_sync, WG_CONF_MODE)

    abs_conf = os.path.abspath(WG_CONF_FILE)

    try:
        subprocess.check_call(
            ["wg", "show", WG_INTERFACE],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        # Interface exists, sync without downtime
        subprocess.check_call(["wg", "syncconf", WG_INTERFACE, tmp_sync])
        logger.info("WireGuard config synced.")
    except subprocess.CalledProcessError:
        # Interface doesn't exist, bring it up
        with open(WG_CONF_FILE, "w") as f:
            f.write(conf_full)
        os.chmod(WG_CONF_FILE, WG_CONF_MODE)
        subprocess.check_call(["wg-quick", "up", abs_conf])
        logger.info("WireGuard interface %s brought up.", WG_INTERFACE)

    os.remove(tmp_sync)

    # Always write full conf for reference
    with open(WG_CONF_FILE, "w") as f:
        f.write(conf_full)
    os.chmod(WG_CONF_FILE, WG_CONF_MODE)


def verify_listening_port(config):
    try:
        output = subprocess.check_output(["wg", "show", WG_INTERFACE]).decode()
        match = re.search(r"listening port: (\d+)", output)
        if match:
            actual = int(match.group(1))
            if actual == config["listen_port"]:
                logger.info("Verified: listening on port %d", actual)
                return True
            else:
                logger.warning(
                    "Listening on %d instead of %d. Restarting interface.",
                    actual, config["listen_port"],
                )
                return False
        logger.warning("Could not find listening port in wg show output.")
        return False
    except subprocess.CalledProcessError as e:
        logger.error("Error checking listening port: %s", e)
        return False


def restart_wireguard():
    abs_conf = os.path.abspath(WG_CONF_FILE)
    try:
        subprocess.check_call(["wg-quick", "down", abs_conf])
        subprocess.check_call(["wg-quick", "up", abs_conf])
        logger.info("WireGuard interface restarted.")
        return True
    except subprocess.CalledProcessError as e:
        logger.error("Failed to restart WireGuard: %s", e)
        return False


def is_interface_up():
    try:
        subprocess.check_call(
            ["wg", "show", WG_INTERFACE],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        return True
    except subprocess.CalledProcessError:
        return False


# ---------------------------------------------------------------------------
# DNS integration via dnsmasq (Approach A+B)
#
# Architecture:
#   Server DNS (port 53): resolves *.shomescale -> internal IPs
#   Client dnsmasq (127.0.0.1:53): forwards *.shomescale to server,
#     everything else to upstream (gateway/router)
#   /etc/resolv.conf: nameserver 127.0.0.1 (points to local dnsmasq)
# ---------------------------------------------------------------------------

def is_dnsmasq_installed():
    try:
        subprocess.check_call(
            ["dnsmasq", "--version"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        return True
    except (subprocess.CalledProcessError, FileNotFoundError):
        return False


def install_dnsmasq():
    if is_dnsmasq_installed():
        return
    logger.info("dnsmasq not found. Installing...")
    distro = get_distro_info()
    distro_id = distro.get("ID", "").lower()
    id_like = distro.get("ID_LIKE", "").lower()

    if distro_id in ("ubuntu", "debian") or "debian" in id_like:
        subprocess.check_call(["apt-get", "update"], stdout=subprocess.DEVNULL)
        subprocess.check_call(["apt-get", "install", "-y", "dnsmasq"])
    elif distro_id in ("rhel", "rocky", "centos", "almalinux", "redhat") or "rhel" in id_like:
        subprocess.check_call(["dnf", "install", "-y", "dnsmasq"])
    else:
        logger.error("Unsupported distro. Install dnsmasq manually.")
        sys.exit(1)

    if not is_dnsmasq_installed():
        logger.error("dnsmasq installation failed.")
        sys.exit(1)


def _read_resolv_conf():
    """Parse /etc/resolv.conf and return (nameservers, search_domain, original_content)."""
    nameservers = []
    search_domains = []
    original = ""
    try:
        with open(RESOLV_CONF) as f:
            original = f.read()
        for line in original.splitlines():
            parts = line.strip().split()
            if len(parts) >= 2 and parts[0] == "nameserver":
                nameservers.append(parts[1])
            if parts and parts[0] == "search":
                search_domains.extend(parts[1:])
    except FileNotFoundError:
        pass
    return nameservers, search_domains, original


def setup_dns(server_ip, server_dns_port=53):
    """Configure dnsmasq to forward *.shomescale to the directory server DNS,
    update /etc/resolv.conf to point to localhost (127.0.0.1).

    Args:
        server_ip: IP of the directory server (e.g. 192.168.35.141)
        server_dns_port: DNS port on the directory server (default 53)
    """
    install_dnsmasq()

    # Read current resolv.conf to find upstream nameservers
    upstream_ns, search_domains, original_resolv = _read_resolv_conf()
    if not upstream_ns:
        # Fallback: try gateway
        upstream_ns = ["192.168.35.1"]

    # Backup original resolv.conf if not already backed up
    if not os.path.exists(RESOLV_CONF_BACKUP):
        with open(RESOLV_CONF_BACKUP, "w") as f:
            f.write(original_resolv)
        logger.info("Backed up %s to %s", RESOLV_CONF, RESOLV_CONF_BACKUP)

    # Write dnsmasq config
    os.makedirs(os.path.dirname(DNSMASQ_CONF), exist_ok=True)
    upstream_lines = "\n".join(f"server={ns}" for ns in upstream_ns)
    dnsmasq_conf = f"""
# shomescale DNS forwarding config
# Generated by shomescale client - DO NOT EDIT

# Only listen on localhost
listen-address=127.0.0.1

# Do NOT read /etc/resolv.conf for upstream (we specify explicitly)
no-resolv

# Forward all queries to the gateway/upstream nameservers
{upstream_lines}

# Forward ONLY *.shomescale queries to the directory server DNS
server=/{DNS_DOMAIN}/{server_ip}#{server_dns_port}

# Add shomescale to the local search domain
expand-hosts

# Log queries (optional, comment out for production)
# log-queries
"""
    with open(DNSMASQ_CONF, "w") as f:
        f.write(dnsmasq_conf)
    logger.info("Wrote dnsmasq config to %s", DNSMASQ_CONF)

    # Update /etc/resolv.conf: point to localhost first, then original upstreams
    new_resolv = f"""# Managed by shomescale client
nameserver 127.0.0.1
"""
    for ns in upstream_ns:
        new_resolv += f"nameserver {ns}\n"
    if search_domains and DNS_DOMAIN not in search_domains:
        search_domains.append(DNS_DOMAIN)
        new_resolv += f"search {' '.join(search_domains)}\n"
    elif not search_domains:
        new_resolv += f"search {DNS_DOMAIN}\n"

    with open(RESOLV_CONF, "w") as f:
        f.write(new_resolv)
    logger.info("Updated %s to use dnsmasq (127.0.0.1)", RESOLV_CONF)

    # Restart dnsmasq to pick up the config
    _dnsmasq_action("restart")
    time.sleep(1)  # Give dnsmasq a moment to bind port 53
    # Verify with a direct query first to confirm server is reachable
    _resolve_local("pi-cluster01-wg.shomescale")

    # Verify DNS resolution works
    time.sleep(1)
    test_ip = _resolve_local("test.shomescale")
    logger.info("DNS setup complete. Local resolver test for nonexistent domain: %s", test_ip or "NXDOMAIN (expected)")


def _resolve_local(domain):
    """Resolve a domain using the local DNS server (127.0.0.1 port 53)."""
    try:
        result = socket.getaddrinfo(domain, None, socket.AF_INET, socket.SOCK_DGRAM)
        if result:
            return result[0][4][0]
    except socket.gaierror:
        pass
    return None


def _dnsmasq_action(action):
    """Start/stop/restart dnsmasq with explicit config file.

    Uses -C to force dnsmasq to read our config directly, avoiding issues
    where the system's /etc/dnsmasq.conf doesn't include conf-dir=/etc/dnsmasq.d/
    (common on minimal Debian installs).
    """
    # Stop any existing dnsmasq
    try:
        subprocess.check_call(["pkill", "dnsmasq"])
        time.sleep(0.5)
    except subprocess.CalledProcessError:
        pass

    if action in ("restart", "start"):
        # Always use explicit config - don't rely on /etc/dnsmasq.conf or conf-dir
        subprocess.check_call([
            "dnsmasq",
            "-C", DNSMASQ_CONF,      # Explicit config file
            "-x", "/var/run/shomescale-dnsmasq.pid",  # PID file
        ])
        logger.info("dnsmasq started with config %s", DNSMASQ_CONF)

    if action == "stop":
        # Clean up PID file
        try:
            os.remove("/var/run/shomescale-dnsmasq.pid")
        except OSError:
            pass
        logger.info("dnsmasq stopped")


def clean_dns():
    """Remove dnsmasq config, restore original resolv.conf, stop forwarding."""
    # Restore original resolv.conf
    if os.path.exists(RESOLV_CONF_BACKUP):
        with open(RESOLV_CONF_BACKUP) as f:
            original = f.read()
        with open(RESOLV_CONF, "w") as f:
            f.write(original)
        os.remove(RESOLV_CONF_BACKUP)
        logger.info("Restored %s from backup", RESOLV_CONF)

    # Remove dnsmasq config
    if os.path.exists(DNSMASQ_CONF):
        os.remove(DNSMASQ_CONF)
        logger.info("Removed dnsmasq config %s", DNSMASQ_CONF)

    # Restart dnsmasq to pick up changes (it no longer has shomescale forwarding)
    _dnsmasq_action("restart")
    logger.info("DNS cleanup complete")


# ---------------------------------------------------------------------------
# Daemon loop
# ---------------------------------------------------------------------------

_stop_requested = False


def _signal_handler(signum, frame):
    global _stop_requested
    _stop_requested = True
    logger.info("Received signal %d, stopping gracefully.", signum)


def daemon_loop(server_host, server_port):
    """Main daemon: heartbeat + peer sync with reconnect backoff.
    Survives server outages and reconnects automatically.
    Identifies to server via UUID for collision-proof tracking.
    Manages DNS via dnsmasq (forwards *.shomescale to directory server).
    """
    install_wireguard()
    config = load_config()
    if not config:
        logger.error("Not registered. Run 'register' first.")
        return

    signal.signal(signal.SIGTERM, _signal_handler)
    signal.signal(signal.SIGINT, _signal_handler)

    # Use UUID for identity if available (newer servers), fall back to name
    node_id = config.get("uuid") or config["name"]

    # Set up DNS forwarding on startup (dnsmasq + resolv.conf)
    # This replaces the old /etc/hosts approach - now uses proper DNS
    setup_dns(server_host, server_dns_port=53)

    last_peers_hash = None
    last_peer_check = 0
    reconnect_delay = RECONNECT_BASE_DELAY
    consecutive_failures = 0

    logger.info("Starting daemon loop for %s (%s) ID=%s",
                config["name"], config["internal_ip"], node_id)
    logger.info("DNS: %s resolves via %s (port %d). FQDN: %s.shomescale",
                DNS_DOMAIN, server_host, 53, config["name"])

    while not _stop_requested:
        try:
            # Heartbeat
            req = {
                "action": "hello",
                "name": node_id,  # Send UUID or name
                "port": config["listen_port"],
            }
            response = send_request(server_host, server_port, req)
            if response["status"] != "ok":
                logger.warning("Heartbeat failed: %s", response.get("msg"))
                consecutive_failures += 1

            # Reset reconnect delay on successful communication
            reconnect_delay = RECONNECT_BASE_DELAY
            consecutive_failures = 0

            # Periodic peer check
            now = time.time()
            if now - last_peer_check > PEER_CHECK_INTERVAL:
                peers = get_peers(server_host, server_port)
                peers_json = json.dumps(peers, sort_keys=True)
                peers_hash = hashlib.sha256(peers_json.encode()).hexdigest()

                if peers_hash != last_peers_hash:
                    logger.info("Peers changed, updating WireGuard config...")
                    conf_full = generate_conf(config, peers, include_interface=True)
                    conf_sync = generate_conf(config, peers, include_interface=False)
                    update_wireguard(conf_full, conf_sync)

                    # Verify listening port
                    if not verify_listening_port(config):
                        if restart_wireguard():
                            verify_listening_port(config)
                        else:
                            logger.error("Port verification failed after restart.")

                    # DNS is handled by the server - no need to update local files
                    # when peer lists change. The server's DNS always has the latest
                    # peer info and dnsmasq forwards queries to it.
                    logger.info("WireGuard updated. DNS auto-resolves new peers.")
                    last_peers_hash = peers_hash

                last_peer_check = now

        except (ConnectionRefusedError, ConnectionError, OSError, RuntimeError) as e:
            consecutive_failures += 1
            logger.warning(
                "Connection to server failed (%s). Retrying in %ds...",
                e, reconnect_delay,
            )
            time.sleep(reconnect_delay)
            # Exponential backoff with cap
            reconnect_delay = min(reconnect_delay * 2, RECONNECT_MAX_DELAY)
            continue

        except Exception as e:
            logger.exception("Unexpected daemon error: %s", e)
            consecutive_failures += 1

        time.sleep(HEARTBEAT_INTERVAL)

    logger.info("Daemon loop exited.")


# ---------------------------------------------------------------------------
# Daemon process management
# ---------------------------------------------------------------------------

# Defaults - overwritten in main() with absolute paths based on script dir
PID_FILE = None
CLIENT_LOG_FILE = None


def daemonize(log_file, pid_file):
    """Double-fork into background. Redirects stdout/stderr to log_file."""
    check_stale_pid(pid_file)  # Clean up stale PID first

    try:
        pid = os.fork()
        if pid > 0:
            sys.exit(0)
    except OSError as e:
        print(f"Fork #1 failed: {e}")
        sys.exit(1)

    os.chdir("/")
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

    with open("/dev/null") as dev_null:
        os.dup2(dev_null.fileno(), sys.stdin.fileno())

    with open(log_file, "a") as log:
        os.dup2(log.fileno(), sys.stdout.fileno())
        os.dup2(log.fileno(), sys.stderr.fileno())

    with open(pid_file, "w") as f:
        f.write(str(os.getpid()))


def check_stale_pid(pid_file):
    """Check if PID file refers to a running process. Remove if stale."""
    if not os.path.exists(pid_file):
        return False
    try:
        with open(pid_file) as f:
            pid = int(f.read().strip())
        os.kill(pid, 0)
        return True
    except (ValueError, OSError):
        logger.warning("Removing stale PID file.")
        os.remove(pid_file)
        return False


def is_daemon_running():
    return check_stale_pid(PID_FILE)


def stop_client():
    """Bring down WireGuard, clean DNS config, stop daemon."""
    if is_interface_up():
        try:
            subprocess.check_call(["wg-quick", "down", os.path.abspath(WG_CONF_FILE)])
            logger.info("WireGuard %s brought down.", WG_INTERFACE)
        except subprocess.CalledProcessError as e:
            logger.error("Failed to bring down WireGuard: %s", e)
    else:
        logger.info("WireGuard interface not up.")

    clean_dns()

    if is_daemon_running():
        with open(PID_FILE) as f:
            pid = int(f.read().strip())
        try:
            os.kill(pid, 15)  # SIGTERM
            logger.info("Sent SIGTERM to daemon (PID %d).", pid)
        except OSError as e:
            logger.error("Failed to stop daemon: %s", e)
        if os.path.exists(PID_FILE):
            os.remove(PID_FILE)
    else:
        logger.info("Daemon not running.")


def status_client(server_host=None, server_port=10000):
    """Print client status: daemon, interface, config, online peers."""
    running = is_daemon_running()
    interface_up = is_interface_up()
    config = load_config()

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
            print(f"Online peers ({len(peers)}):")
            for peer in peers:
                print(f"  - {peer['name']}: {peer['internal_ip']} @ {peer['endpoint']}")
        except Exception as e:
            print(f"Failed to fetch peers: {e}")
    else:
        print("Provide --server to fetch online peers.")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    global CONFIG_FILE, WG_CONF_FILE, PID_FILE, CLIENT_LOG_FILE
    
    check_root()
    
    # Resolve all file paths to absolute based on script directory
    # This is critical so paths survive the os.chdir("/") in daemonization
    script_dir = os.path.dirname(os.path.realpath(__file__))
    CONFIG_FILE = os.path.join(script_dir, "config.json")
    WG_CONF_FILE = os.path.join(script_dir, "wg0.conf")
    PID_FILE = os.path.join(script_dir, "client.pid")
    CLIENT_LOG_FILE = os.path.join(script_dir, "client.log")

    parser = argparse.ArgumentParser(
        description="shomescale client - WireGuard mesh VPN client",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # Register
    rp = subparsers.add_parser("register", help="Register with the directory server")
    rp.add_argument("--server", required=True, help="Server hostname/IP")
    rp.add_argument("--server-port", type=int, default=10000, help="Server port")
    rp.add_argument("--name", required=True, help="Unique node name")
    rp.add_argument("--listen-port", type=int, default=51820, help="WireGuard UDP port")

    # Start
    sp = subparsers.add_parser("start", help="Start daemon for heartbeats and peer sync")
    sp.add_argument("--server", required=True, help="Server hostname/IP")
    sp.add_argument("--server-port", type=int, default=10000, help="Server port")
    sp.add_argument("--bg", action="store_true", help="Run in background (daemon)")

    # Stop
    subparsers.add_parser("stop", help="Stop daemon, tear down WireGuard, clean hosts")

    # Status
    stp = subparsers.add_parser("status", help="Check client status")
    stp.add_argument("--server", help="Server to fetch peer list")
    stp.add_argument("--server-port", type=int, default=10000, help="Server port")

    args = parser.parse_args()

    # Logging setup
    if args.command == "start" and args.bg:
        # Logging will be configured after daemonization in daemon_loop
        log_file = CLIENT_LOG_FILE
        daemonize(log_file, PID_FILE)
        # After daemonize: stdout/stderr already point at log_file.
        # Using both FileHandler + StreamHandler causes duplicate lines,
        # so only use FileHandler here.
        logging.basicConfig(
            level=logging.INFO,
            format="%(asctime)s %(levelname)s %(message)s",
            handlers=[logging.FileHandler(log_file)],
        )
        daemon_loop(args.server, args.server_port)
    else:
        logging.basicConfig(
            level=logging.INFO,
            format="%(asctime)s %(levelname)s %(message)s",
        )

        if args.command == "register":
            register(args.server, args.server_port, args.name, args.listen_port)
        elif args.command == "start":
            daemon_loop(args.server, args.server_port)
        elif args.command == "stop":
            stop_client()
        elif args.command == "status":
            status_client(args.server, args.server_port)


if __name__ == "__main__":
    main()
