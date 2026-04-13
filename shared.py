"""shomescale shared constants.

Used by both server and client modules.
"""

# ---------------------------------------------------------------------------
# Network
# ---------------------------------------------------------------------------
INTERNAL_NETWORK = "100.64.0.0"
INTERNAL_NETMASK = 24

# ---------------------------------------------------------------------------
# Server ports
# ---------------------------------------------------------------------------
DEFAULT_PORT = 10000       # TCP coordination
DEFAULT_DNS_PORT = 53      # DNS (requires setcap or root)
DEFAULT_WEB_PORT = 8080    # Web dashboard

# ---------------------------------------------------------------------------
# Client
# ---------------------------------------------------------------------------
HEARTBEAT_INTERVAL = 30         # seconds between heartbeats
PEER_CHECK_INTERVAL = 60        # seconds between peer list checks
RECONNECT_BASE_DELAY = 5        # seconds, base for exponential backoff
RECONNECT_MAX_DELAY = 120       # seconds, max reconnect delay
HEARTBEAT_TIMEOUT = 60          # server: seconds before peer considered offline
CHECK_INTERVAL = 30             # server: seconds between timeout checks

# ---------------------------------------------------------------------------
# DNS
# ---------------------------------------------------------------------------
DNS_DOMAIN = "shomescale"       # .shomescale TLD

# ---------------------------------------------------------------------------
# WireGuard
# ---------------------------------------------------------------------------
WG_INTERFACE = "wg0"
WG_CONF_MODE = 0o600

# ---------------------------------------------------------------------------
# Files (overwritten in main() with absolute paths)
# ---------------------------------------------------------------------------
SCRIPT_DIR = "./"
