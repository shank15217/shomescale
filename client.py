#!/usr/bin/env python3
"""shomescale client CLI entry point.

Thin dispatch to the actual modules:
  - client_daemon    (heartbeat loop, reconnection)
  - client_wireguard (WG install, keys, config, interface)
  - client_dns       (dnsmasq + resolv.conf)
"""

import argparse
import json
import logging
import os
import sys

import shared
from shomescale_protocol import send_json, recv_json

logger = logging.getLogger("shomescale-client")


def _resolve_paths():
    """Resolve file paths to absolute based on script directory."""
    d = os.path.dirname(os.path.realpath(__file__))
    return {
        "config":  os.path.join(d, "config.json"),
        "wg_conf": os.path.join(d, "wg0.conf"),
        "pid":     os.path.join(d, "client.pid"),
        "log":     os.path.join(d, "client.log"),
    }


def _load_config(path):
    if os.path.exists(path):
        with open(path) as f:
            return json.load(f)
    return None


def _save_config(path, config):
    with open(path, "w") as f:
        json.dump(config, f, indent=2)
    os.chmod(path, 0o600)


def _send_request(host, port, req, timeout=10):
    import socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    sock.connect((host, port))
    try:
        send_json(sock, req)
        return recv_json(sock)
    finally:
        sock.close()


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------

def cmd_register(server_host, server_port, name, listen_port, paths):
    from client_wireguard import ensure
    ensure()
    config = _load_config(paths["config"])
    if config:
        logger.warning("Already registered as %s (%s)", config["name"], config["internal_ip"])
        return

    # Server generates keypair and returns privkey+pubkey
    resp = _send_request(server_host, server_port, {
        "action": "register", "name": name, "pubkey": "", "port": listen_port,
    })
    if resp["status"] == "ok":
        config = {
            "name": name,
            "uuid": resp.get("uuid", ""),
            "privkey": resp.get("privkey", ""),
            "pubkey": resp.get("pubkey", ""),
            "key_generation": 1,
            "internal_ip": resp["internal_ip"],
            "listen_port": listen_port,
            "server_host": server_host, "server_port": server_port,
        }
        _save_config(paths["config"], config)
        logger.info("Registered as %s (ID: %s) with IP %s",
                     name, config["uuid"], config["internal_ip"])
        logger.info("DNS names: %s.shomescale, %s.shomescale",
                     name, config["uuid"][:8])
    else:
        logger.error("Registration failed: %s", resp.get("msg", "Unknown error"))


def cmd_start(server_host, server_port, bg=False, paths=None):
    from client_daemon import run, daemonize, daemonize_check_stale, load_config

    config = load_config(paths["config"])
    if not config:
        logger.error("Not registered. Run 'register' first.")
        return

    if bg:
        if daemonize_check_stale(paths["pid"]):
            print("Daemon already running.")
            sys.exit(1)
        daemonize(paths["log"], paths["pid"])
        logging.basicConfig(
            level=logging.INFO,
            format="%(asctime)s %(levelname)s %(message)s",
            handlers=[logging.FileHandler(paths["log"])],
        )
    else:
        logging.basicConfig(
            level=logging.INFO,
            format="%(asctime)s %(levelname)s %(message)s",
        )

    run(config, paths["config"], server_host, server_port)


def cmd_stop(paths):
    from client_daemon import stop as daemon_stop
    from client_wireguard import is_up, wg_down

    if is_up():
        wg_down(paths["wg_conf"])

    daemon_stop(paths["config"])

    if os.path.exists(paths["pid"]):
        try:
            with open(paths["pid"]) as f:
                pid = int(f.read().strip())
            os.kill(pid, 15)
            logger.info("Sent SIGTERM to daemon (PID %d).", pid)
        except OSError:
            pass
        os.remove(paths["pid"])


def cmd_status(server_host, server_port, paths):
    from client_wireguard import is_up
    from client_daemon import run as daemon_run  # noqa: unused, just import
    from client_daemon import daemonize_check_stale, load_config as load_conf

    config = load_conf(paths["config"])
    running = daemonize_check_stale(paths["pid"])
    print(f"Daemon running: {running}")
    print(f"WireGuard interface up: {is_up()}")
    if config:
        print(f"Name: {config['name']}")
        print(f"Internal IP: {config['internal_ip']}")
        print(f"Listen Port: {config['listen_port']}")
    else:
        print("Not registered.")
    if server_host:
        resp = _send_request(server_host, server_port, {"action": "get_peers"})
        if resp["status"] == "ok":
            print(f"Online peers ({len(resp['peers'])}):")
            for p in resp["peers"]:
                print(f"  - {p['name']}: {p['internal_ip']} @ {p['endpoint']}")
    else:
        print("Provide --server to fetch online peers.")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="shomescale client")
    subparsers = parser.add_subparsers(dest="command", required=True)

    p_reg = subparsers.add_parser("register")
    p_reg.add_argument("--server", required=True)
    p_reg.add_argument("--server-port", type=int, default=shared.DEFAULT_PORT)
    p_reg.add_argument("--name", required=True)
    p_reg.add_argument("--listen-port", type=int, default=51820)

    p_start = subparsers.add_parser("start")
    p_start.add_argument("--server", required=True)
    p_start.add_argument("--server-port", type=int, default=shared.DEFAULT_PORT)
    p_start.add_argument("--bg", action="store_true", help="Background daemon mode")

    subparsers.add_parser("stop")

    p_stat = subparsers.add_parser("status")
    p_stat.add_argument("--server")
    p_stat.add_argument("--server-port", type=int, default=shared.DEFAULT_PORT)

    args = parser.parse_args()
    paths = _resolve_paths()

    if args.command == "register":
        cmd_register(args.server, args.server_port, args.name,
                     args.listen_port, paths)
    elif args.command == "start":
        cmd_start(args.server, args.server_port, args.bg, paths)
    elif args.command == "stop":
        cmd_stop(paths)
    elif args.command == "status":
        cmd_status(args.server, args.server_port, paths)


if __name__ == "__main__":
    main()
