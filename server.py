#!/usr/bin/env python3
"""shomescale server - Thin CLI entry point.

Usage:
    python3 server.py start [--bg] [--host HOST] [--port PORT]
                            [--web-port PORT] [--dns-port PORT]
    python3 server.py status
    python3 server.py stop
"""

import argparse
import json
import logging
import os
import socket
import sys
import threading

import shared
from shomescale_protocol import send_json, recv_json
from shomescale_store import PeersStore
from shomescale_dns import DNSServer
from shomescale_web import run_web_server

logger = logging.getLogger("shomescale-server")


# ---------------------------------------------------------------------------
# Client handler
# ---------------------------------------------------------------------------

def handle_client(conn, addr, store):
    try:
        req = recv_json(conn)
    except (ConnectionError, Exception) as e:
        logger.debug("Bad request from %s: %s", addr, e)
        conn.close()
        return

    try:
        action = req.get("action")
        response = {}

        if action == "register":
            ok, response = store.register(
                req["name"],
                req["pubkey"],
                f"{addr[0]}:{req['port']}",
            )
        elif action == "hello":
            ok, response = store.hello(
                req["name"],
                f"{addr[0]}:{req['port']}",
            )
        elif action == "get_peers":
            # Pass requesting peer's identity for ACL filtering
            response = {"status": "ok", "peers": store.get_peers(
                source_name=req.get("name"),
            )}
        elif action == "reload_acls":
            store.reload_acls()
            response = {"status": "ok", "msg": "ACLs reloaded"}
        elif action == "get_status":
            response = {"status": "ok", "data": store.get_status()}
        else:
            response = {"status": "error", "msg": f"Unknown action: {action}"}
        send_json(conn, response)
    except KeyError as e:
        logger.warning("Missing key in request from %s: %s", addr, e)
        try:
            send_json(conn, {"status": "error", "msg": f"Missing field: {e}"})
        except Exception:
            pass
    except Exception as e:
        logger.exception("Error handling client %s", addr)
        try:
            send_json(conn, {"status": "error", "msg": str(e)})
        except Exception:
            pass
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Timeout checker
# ---------------------------------------------------------------------------

def run_timeout_checker(store):
    while True:
        store.timeout_check()
        time.sleep(shared.CHECK_INTERVAL)


# ---------------------------------------------------------------------------
# Daemon helpers
# ---------------------------------------------------------------------------

def check_stale_pid(pid_file):
    if not os.path.exists(pid_file):
        return False
    try:
        with open(pid_file, "r") as f:
            pid = int(f.read().strip())
        os.kill(pid, 0)
        return True
    except (ValueError, OSError):
        try:
            os.remove(pid_file)
        except OSError:
            pass
        return False


def create_pid(pid_file):
    with open(pid_file, "w") as f:
        f.write(str(os.getpid()))


def daemonize(log_file, pid_file):
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

    with open("/dev/null", "r") as dev_null:
        os.dup2(dev_null.fileno(), sys.stdin.fileno())

    with open(log_file, "a") as log:
        os.dup2(log.fileno(), sys.stdout.fileno())
        os.dup2(log.fileno(), sys.stderr.fileno())

    create_pid(pid_file)


# ---------------------------------------------------------------------------
# Server commands
# ---------------------------------------------------------------------------

def start_server(host, port, bg, log_file, pid_file, peers_file, web_port, dns_port, acls_file):
    store = PeersStore(peers_file, acls_file)

    if pid_file and check_stale_pid(pid_file):
        print(f"Server already running (check {pid_file})")
        sys.exit(1)

    if bg:
        daemonize(log_file, pid_file)
        logging.basicConfig(
            level=logging.INFO,
            format="%(asctime)s %(levelname)s %(message)s",
            handlers=[logging.FileHandler(log_file)],
        )
    else:
        logging.basicConfig(
            level=logging.INFO,
            format="%(asctime)s %(levelname)s %(message)s",
        )
        if pid_file:
            create_pid(pid_file)

    logger.info("Starting shomescale server on %s:%d", host, port)

    # DNS on port 53 requires setcap or root
    if dns_port > 0 and dns_port < 1024 and os.geteuid() != 0:
        logger.info("DNS port %d (privileged). Ensure cap_net_bind_service is set.", dns_port)

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((host, port))
    server.listen(5)
    logger.info("Coordination server listening on %s:%d", host, port)

    threading.Thread(target=run_timeout_checker, args=(store,), daemon=True).start()

    if dns_port > 0:
        dns = DNSServer(store, port=dns_port)
        threading.Thread(target=dns.run, daemon=True).start()

    if web_port > 0:
        threading.Thread(target=run_web_server, args=(store, web_port), daemon=True).start()

    try:
        while True:
            conn, addr = server.accept()
            threading.Thread(target=handle_client, args=(conn, addr, store), daemon=True).start()
    except KeyboardInterrupt:
        logger.info("Shutting down")
    finally:
        server.close()
        if pid_file and os.path.exists(pid_file):
            os.remove(pid_file)


def show_status(pid_file, peers_file):
    running = check_stale_pid(pid_file)
    print(f"Server running: {running}")
    if os.path.exists(peers_file):
        with open(peers_file) as f:
            peers_data = json.load(f)
        print("Registered peers:")
        for uid_or_name, info in peers_data.items():
            name = info.get("name", uid_or_name)
            uid = info.get("uuid", uid_or_name)
            online_str = "Online" if info.get("online") else "Offline"
            short_uuid = uid[:8] if len(uid) > 8 else uid
            print(f"  - {name} ({short_uuid}): {info['internal_ip']} [{online_str}]  Endpoint: {info.get('endpoint', 'N/A')}")
    else:
        print("No peers registered.")


def stop_server(pid_file):
    if not check_stale_pid(pid_file):
        print("Server not running.")
        return
    with open(pid_file) as f:
        pid = int(f.read().strip())
    try:
        os.kill(pid, 15)
        print(f"Sent SIGTERM to {pid}.")
    except OSError as e:
        print(f"Failed to stop: {e}")
    if os.path.exists(pid_file):
        os.remove(pid_file)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="shomescale server")
    subparsers = parser.add_subparsers(dest="command", required=True)

    sp = subparsers.add_parser("start", help="Start the server")
    sp.add_argument("--bg", action="store_true", help="Background mode (daemon)")
    sp.add_argument("--host", default="0.0.0.0")
    sp.add_argument("--port", type=int, default=shared.DEFAULT_PORT)
    sp.add_argument("--web-port", type=int, default=0, help="Web dashboard port (0=disabled)")
    sp.add_argument("--dns-port", type=int, default=0, help="DNS server port (0=disabled)")
    sp.add_argument("--acls", default=None, help="Path to acls.json")

    subparsers.add_parser("status", help="Check server status")
    subparsers.add_parser("stop", help="Stop the server")

    args = parser.parse_args()

    pid_file = os.path.abspath("server.pid")
    log_file = os.path.abspath("server.log")
    peers_file = os.path.abspath("peers.json")

    if args.command == "start":
        start_server(
            args.host, args.port, args.bg,
            log_file, pid_file, peers_file,
            getattr(args, "web_port", 0), getattr(args, "dns_port", 0), args.acls,
        )
    elif args.command == "status":
        show_status(pid_file, peers_file)
    elif args.command == "stop":
        stop_server(pid_file)


if __name__ == "__main__":
    main()
