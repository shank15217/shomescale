"""shomescale client: WireGuard management module.

Handles WireGuard installation, key generation, config generation,
and interface management (up/down/restart/sync).
"""

import json
import logging
import os
import re
import subprocess

import shared

WG_INTERFACE = "wg0"
WG_CONF_MODE = 0o600

logger = logging.getLogger("shomescale-wg")


def ensure():
    """Install WireGuard if not already present."""
    if is_installed():
        return
    logger.info("WireGuard not found. Attempting to install...")
    distro = get_distro_info()
    distro_id = distro.get("ID", "").lower()
    id_like = distro.get("ID_LIKE", "").lower()
    version_id = distro.get("VERSION_ID", "")

    if distro_id in ("ubuntu", "debian") or "debian" in id_like:
        subprocess.check_call(["apt-get", "update"], stdout=subprocess.DEVNULL)
        subprocess.check_call(["apt-get", "install", "-y", "wireguard"])
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
        except subprocess.CalledProcessError as e:
            logger.error("Failed to install WireGuard: %s", e)
            import sys; sys.exit(1)
    else:
        logger.error("Unsupported distribution. Install WireGuard manually.")
        import sys; sys.exit(1)

    if not is_installed():
        logger.error("WireGuard installation failed.")
        import sys; sys.exit(1)


def is_installed():
    try:
        subprocess.check_call(
            ["wg", "--version"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        return True
    except (subprocess.CalledProcessError, FileNotFoundError):
        return False


def get_distro_info():
    info = {}
    if os.path.exists("/etc/os-release"):
        with open("/etc/os-release") as f:
            for line in f:
                if "=" in line:
                    key, val = line.strip().split("=", 1)
                    info[key] = val.strip('"')
    return info


def generate_keys():
    """Generate a WireGuard keypair. Returns (privkey, pubkey)."""
    privkey = subprocess.check_output(["wg", "genkey"]).decode().strip()
    pubkey = subprocess.check_output(
        ["wg", "pubkey"], input=privkey.encode()
    ).decode().strip()
    return privkey, pubkey


def generate_conf(config, peers, include_interface=True):
    """Generate WireGuard config text."""
    lines = []
    if include_interface:
        lines.append("[Interface]")
        lines.append(f"Address = {config['internal_ip']}/{shared.INTERNAL_NETMASK}")
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


def update(conf_full, conf_sync, wg_conf_file="wg0.conf"):
    """Apply WireGuard config. Uses wg syncconf if interface exists, otherwise wg-quick up."""
    tmp_sync = "wg_temp.conf"
    with open(tmp_sync, "w") as f:
        f.write(conf_sync)
    os.chmod(tmp_sync, WG_CONF_MODE)

    abs_conf = os.path.abspath(wg_conf_file)

    try:
        subprocess.check_call(
            ["wg", "show", WG_INTERFACE],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        subprocess.check_call(["wg", "syncconf", WG_INTERFACE, tmp_sync])
        logger.info("WireGuard config synced.")
    except subprocess.CalledProcessError:
        with open(wg_conf_file, "w") as f:
            f.write(conf_full)
        os.chmod(wg_conf_file, WG_CONF_MODE)
        subprocess.check_call(["wg-quick", "up", abs_conf])
        logger.info("WireGuard interface %s brought up.", WG_INTERFACE)

    os.remove(tmp_sync)

    with open(wg_conf_file, "w") as f:
        f.write(conf_full)
    os.chmod(wg_conf_file, WG_CONF_MODE)


def verify_listening_port(config, wg_interface=WG_INTERFACE):
    """Check if WireGuard is listening on the configured port."""
    try:
        output = subprocess.check_output(["wg", "show", wg_interface]).decode()
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


def restart(wg_conf_file="wg0.conf"):
    """Bring interface down and back up."""
    abs_conf = os.path.abspath(wg_conf_file)
    try:
        subprocess.check_call(["wg-quick", "down", abs_conf])
        subprocess.check_call(["wg-quick", "up", abs_conf])
        logger.info("WireGuard interface restarted.")
        return True
    except subprocess.CalledProcessError as e:
        logger.error("Failed to restart WireGuard: %s", e)
        return False


def wg_down(wg_conf_file="wg0.conf"):
    """Bring WireGuard interface down."""
    abs_conf = os.path.abspath(wg_conf_file)
    try:
        subprocess.check_call(["wg-quick", "down", abs_conf])
        logger.info("WireGuard %s brought down.", WG_INTERFACE)
        return True
    except subprocess.CalledProcessError as e:
        logger.error("Failed to bring down WireGuard: %s", e)
        return False


def is_up(wg_interface=WG_INTERFACE):
    """Check if the WireGuard interface is up."""
    try:
        subprocess.check_call(
            ["wg", "show", wg_interface],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        return True
    except subprocess.CalledProcessError:
        return False
