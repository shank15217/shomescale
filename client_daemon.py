"""shomescale client: daemon loop and background helpers."""

import hashlib
import json
import logging
import os
import signal
import socket
import sys
import time

import shared
from shomescale_protocol import send_json, recv_json
from client_wireguard import (ensure as ensure_wg, generate_conf, is_up,
                               verify_listening_port, restart as wg_restart,
                               update as wg_update, wg_down)
from client_dns import setup_dns, clean_dns

logger = logging.getLogger("shomescale-daemon")

_stop_requested = False

def _signal_handler(signum, frame):
    global _stop_requested
    _stop_requested = True
    logger.info("Received signal %d, stopping gracefully.", signum)

def load_config(config_file):
    if os.path.exists(config_file):
        with open(config_file) as f:
            return json.load(f)
    return None

def send_request(server_host, server_port, req, timeout=10):
    """Send a JSON request to the server with length-prefixed framing."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    sock.connect((server_host, server_port))
    try:
        send_json(sock, req)
        resp = recv_json(sock)
    finally:
        sock.close()
    return resp

def fetch_my_keys(server_host, server_port, node_id):
    """Fetch current keypair from server. Updates config if server gen is newer."""
    keys_resp = send_request(server_host, server_port, {
        "action": "get_keys", "uuid": node_id
    })
    if keys_resp["status"] == "ok" and "keys" in keys_resp:
        return keys_resp["keys"]
    return None

def run(config, config_file, server_host, server_port):
    """Main daemon: heartbeat + peer sync + DNS setup + key rotation.
    Identifies to server via UUID for collision-proof tracking.
    """
    ensure_wg()

    signal.signal(signal.SIGTERM, _signal_handler)
    signal.signal(signal.SIGINT, _signal_handler)

    # Use UUID for identity if available (newer servers), fall back to name
    node_id = config.get("uuid") or config["name"]

    # Set up DNS forwarding (dnsmasq + resolv.conf)
    setup_dns(server_host, server_dns_port=53)

    # Fetch current keypair from server (handles key rotation recovery)
    keys = fetch_my_keys(server_host, server_port, node_id)
    if keys:
        local_gen = config.get("key_generation", 0)
        server_gen = keys["key_generation"]
        if server_gen > local_gen:
            logger.info("Key update: gen %d -> %d", local_gen, server_gen)
            config["privkey"] = keys["privkey"]
            config["pubkey"] = keys["pubkey"]
            config["key_generation"] = server_gen
            with open(config_file, "w") as f:
                json.dump(config, f, indent=2)
                os.chmod(config_file, 0o600)

    last_peers_hash = None
    last_key_gen = config.get("key_generation", 0)
    last_peer_check = 0
    reconnect_delay = shared.RECONNECT_BASE_DELAY
    consecutive_failures = 0
    wg_conf_file = os.path.join(os.path.dirname(config_file), "wg0.conf")

    logger.info("Starting daemon loop for %s (%s) ID=%s",
                config["name"], config["internal_ip"], node_id)
    logger.info("DNS: %s resolves via %s (port %d). FQDN: %s.shomescale",
                shared.DNS_DOMAIN, server_host, 53, config["name"])

    while not _stop_requested:
        try:
            req = {"action": "hello", "name": node_id, "port": config["listen_port"]}
            response = send_request(server_host, server_port, req)
            if response["status"] != "ok":
                logger.warning("Heartbeat failed: %s", response.get("msg"))
                consecutive_failures += 1

            reconnect_delay = shared.RECONNECT_BASE_DELAY
            consecutive_failures = 0

            now = time.time()
            if now - last_peer_check > shared.PEER_CHECK_INTERVAL:
                # Fetch my latest keys from server
                keys = fetch_my_keys(server_host, server_port, node_id)
                if keys:
                    server_gen = keys["key_generation"]
                    if server_gen > last_key_gen:
                        logger.info("Key rotation detected: gen %d -> %d",
                                   last_key_gen, server_gen)
                        config["privkey"] = keys["privkey"]
                        config["pubkey"] = keys["pubkey"]
                        config["key_generation"] = server_gen
                        with open(config_file, "w") as f:
                            json.dump(config, f, indent=2)
                            os.chmod(config_file, 0o600)
                        last_key_gen = server_gen
                        # Force WG update regardless of peer hash
                        last_peers_hash = None

                # Fetch peer list
                peers_resp = send_request(server_host, server_port, {"action": "get_peers"})
                if peers_resp["status"] == "ok":
                    peers = peers_resp["peers"]
                    peers_json = json.dumps(peers, sort_keys=True)
                    peers_hash = hashlib.sha256(peers_json.encode()).hexdigest()

                    if peers_hash != last_peers_hash:
                        logger.info("Peers changed, updating WireGuard config...")
                        conf_full = generate_conf(config, peers, include_interface=True)
                        conf_sync = generate_conf(config, peers, include_interface=False)
                        wg_update(conf_full, conf_sync, wg_conf_file=wg_conf_file)

                        if not verify_listening_port(config):
                            wg_restart(wg_conf_file)
                            verify_listening_port(config)

                        logger.info("WireGuard updated. DNS auto-resolves new peers.")
                        last_peers_hash = peers_hash

                    last_peer_check = now

        except (ConnectionRefusedError, ConnectionError, OSError, RuntimeError) as e:
            consecutive_failures += 1
            logger.warning("Connection to server failed (%s). Retrying in %ds...",
                           e, reconnect_delay)
            time.sleep(reconnect_delay)
            reconnect_delay = min(reconnect_delay * 2, shared.RECONNECT_MAX_DELAY)
            continue

        except Exception as e:
            logger.exception("Unexpected daemon error: %s", e)
            consecutive_failures += 1

        time.sleep(shared.HEARTBEAT_INTERVAL)

    logger.info("Daemon loop exited.")

def stop(config_file):
    """Bring down WireGuard, clean DNS config."""
    if is_up():
        wg_conf_file = os.path.join(os.path.dirname(config_file), "wg0.conf")
        wg_down(wg_conf_file)
    clean_dns()

def daemonize(log_file, pid_file):
    """Double-fork into background."""
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

def daemonize_check_stale(pid_file):
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
