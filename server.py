
#!/usr/bin/env python3
"""shomescale server - Central directory/coordination server for a WireGuard mesh VPN.

Handles peer registration, IP assignment, heartbeat tracking, peer discovery,
and ACL enforcement. Data plane is P2P over WireGuard - this server is only
used for coordination.

NEW FEATURES:
- UUID node IDs: every peer gets a uuid4, human names are just display names
- DNS server: resolves name.shomescale and uuid.shomescale -> internal IP
- Web dashboard: live-updating mesh topology view with peer stats
"""

import socket
import json
import logging
import threading
import os
import time
import sys
import argparse
import uuid
import struct
import struct
from http.server import HTTPServer, BaseHTTPRequestHandler
from io import BytesIO

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
INTERNAL_NETWORK = "100.64.0.0"
INTERNAL_NETMASK = 24
HEARTBEAT_TIMEOUT = 60       # seconds before peer considered offline
CHECK_INTERVAL = 30           # seconds between timeout checks
DEFAULT_PORT = 10000
DEFAULT_DNS_PORT = 53         # Standard DNS port (requires setcap NET_BIND_SERVICE or root)
DEFAULT_WEB_PORT = 8080       # Web dashboard port
DNS_DOMAIN = "shomescale"     # .shomescale TLD for DNS queries

logger = logging.getLogger("shomescale-server")

# ---------------------------------------------------------------------------
# Length-prefixed framing for JSON over TCP (coordination channel)
# ---------------------------------------------------------------------------

def recv_json(sock):
    """Read a complete JSON message from the socket using length-prefixed framing.

    Protocol: 4-byte big-endian length prefix + UTF-8 JSON body.
    Blocks until the full message is received or connection closes.
    Returns parsed JSON or raises on error/closed connection.
    """
    header = b""
    while len(header) < 4:
        chunk = sock.recv(4 - len(header))
        if not chunk:
            raise ConnectionError("Connection closed while reading length prefix")
        header += chunk

    body_length = int.from_bytes(header, byteorder="big", signed=False)
    if body_length > 10 * 1024 * 1024:  # 10 MB limit
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
    payload = json.dumps(obj).encode()
    header = len(payload).to_bytes(4, byteorder="big", signed=False)
    sock.sendall(header + payload)


# ---------------------------------------------------------------------------
# UUID-based Peers store (thread-safe)
# ---------------------------------------------------------------------------

class PeersStore:
    """Thread-safe peers registry backed by a JSON file.

    Keys are uuid4 strings (UUID is the primary identifier).
    Human names are display names only - enforced unique.
    """

    def __init__(self, peers_file):
        self.peers_file = peers_file
        self.lock = threading.Lock()
        self.peers = {}           # {uuid_str: info_dict}
        self.name_index = {}     # {display_name: uuid_str}  for fast lookups
        self.ip_counter = 1
        self.start_time = time.time()  # for uptime tracking
        self._load()

    # -- lock helpers ---------------------------------------------------------

    def _load(self):
        """Load peers from disk. Caller must hold self.lock (or be in __init__)."""
        if os.path.exists(self.peers_file):
            with open(self.peers_file, "r") as f:
                data = json.load(f)
        else:
            self._save_unlocked()
            return

        # data can be either {uuid: info} (new format) or {name: info} (old format)
        if data:
            first_key = next(iter(data))
            first_val = next(iter(data.values()))
            old_format = isinstance(first_val, dict) and 'name' not in first_val and first_key.count('-') != 4

            if old_format:
                # Migrate: old format was {name: info} without uuid
                self.peers = {}
                for old_name, info in data.items():
                    uid = str(uuid.uuid4())
                    info["name"] = old_name
                    info["uuid"] = uid
                    # Ensure required fields
                    info.setdefault("online", False)
                    info.setdefault("last_hello", 0)
                    self.peers[uid] = info
                    self.name_index[old_name] = uid
            else:
                # New format: {uuid: info}
                self.peers = data
                for uid, info in self.peers.items():
                    name = info.get("name", "")
                    if name:
                        self.name_index[name] = uid

            if self.peers:
                self.ip_counter = (
                    max(int(info["internal_ip"].split(".")[-1]) for info in self.peers.values())
                    + 1
                )

        now = time.time()
        for info in self.peers.values():
            if info.get("online", False):
                info["last_hello"] = now
            else:
                info["online"] = False
                info["last_hello"] = 0

    def _save_unlocked(self):
        """Write peers to disk atomically. Caller MUST hold self.lock."""
        tmp = self.peers_file + ".tmp"
        with open(tmp, "w") as f:
            json.dump(self.peers, f, indent=2)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, self.peers_file)

    def _name_taken(self, name):
        """Check if display name is already claimed by a DIFFERENT uuid."""
        existing_uuid = self.name_index.get(name)
        return existing_uuid is not None

    # -- public, lock-protected methods ---------------------------------------

    def register(self, name, pubkey, endpoint):
        """Register a new peer or return error if name exists."""
        with self.lock:
            if self._name_taken(name):
                return False, {"status": "error", "msg": "Name already taken"}

            node_uuid = str(uuid.uuid4())
            internal_ip = f"{INTERNAL_NETWORK.rsplit('.', 1)[0]}.{self.ip_counter}"
            now = time.time()
            self.peers[node_uuid] = {
                "name": name,
                "uuid": node_uuid,
                "pubkey": pubkey,
                "endpoint": endpoint,
                "internal_ip": internal_ip,
                "online": True,
                "last_hello": now,
                "registered_at": now,
                "bytes_rx": 0,
                "bytes_tx": 0,
            }
            self.name_index[name] = node_uuid
            self.ip_counter += 1
            self._save_unlocked()

        return True, {
            "status": "ok",
            "internal_ip": internal_ip,
            "uuid": node_uuid,
            "name": name,
        }

    def hello(self, name_or_uuid, endpoint):
        """Update heartbeat for a peer (accepts name or uuid)."""
        with self.lock:
            # Try uuid first, then name
            uid = self.peers.get(name_or_uuid, {}).get("uuid")
            if uid is None:
                uid = self.name_index.get(name_or_uuid)
            if uid is None:
                return False, {"status": "error", "msg": "Unknown name or uuid"}

            self.peers[uid]["endpoint"] = endpoint
            self.peers[uid]["last_hello"] = time.time()
            self.peers[uid]["online"] = True
            self._save_unlocked()

        return True, {"status": "ok"}

    def get_peers(self, exclude_name=None, exclude_uuid=None):
        """Return list of online peers, optionally excluding self."""
        with self.lock:
            result = []
            for uid, info in self.peers.items():
                if not info["online"]:
                    continue
                if exclude_name and info.get("name") == exclude_name:
                    continue
                if exclude_uuid and uid == exclude_uuid:
                    continue
                result.append({
                    "name": info["name"],
                    "uuid": uid,
                    "pubkey": info["pubkey"],
                    "endpoint": info["endpoint"],
                    "internal_ip": info["internal_ip"],
                    "allowed_ips": info["internal_ip"] + "/32",
                })
        return result

    def get_status(self):
        """Get full status for the web dashboard."""
        with self.lock:
            uptime = time.time() - self.start_time
            peers = []
            for uid, info in self.peers.items():
                time_since_hello = time.time() - info.get("last_hello", 0)
                peers.append({
                    "name": info["name"],
                    "uuid": uid,
                    "internal_ip": info["internal_ip"],
                    "pubkey": info["pubkey"],
                    "endpoint": info["endpoint"],
                    "online": info["online"],
                    "last_hello": info.get("last_hello", 0),
                    "time_since_hello": round(time_since_hello, 1),
                    "registered_at": info.get("registered_at", 0),
                    "bytes_rx": info.get("bytes_rx", 0),
                    "bytes_tx": info.get("bytes_tx", 0),
                })
            # Sort: online first, then by name
            peers.sort(key=lambda p: (not p["online"], p["name"]))
            online_count = sum(1 for p in peers if p["online"])
            offline_count = len(peers) - online_count

        return {
            "uptime": round(uptime, 1),
            "total_peers": len(peers),
            "online": online_count,
            "offline": offline_count,
            "peers": peers,
        }

    def get_dns_records(self):
        """Return list of (name, ip) tuples for DNS resolution.
        Includes both display_names and short uuids.
        """
        with self.lock:
            records = {}  # name_lower -> ip
            for uid, info in self.peers.items():
                if info["online"]:
                    records[info["name"].lower()] = info["internal_ip"]
                    # Also register short uuid (first 8 chars)
                    short_uuid = uid[:8]
                    records[short_uuid] = info["internal_ip"]
        return records

    def timeout_check(self):
        """Mark peers stale (no hello within HEARTBEAT_TIMEOUT) as offline."""
        now = time.time()
        with self.lock:
            changed = False
            for info in self.peers.values():
                if info["last_hello"] < now - HEARTBEAT_TIMEOUT and info.get("online"):
                    info["online"] = False
                    changed = True
            if changed:
                self._save_unlocked()


# ---------------------------------------------------------------------------
# Client handler (TCP coordination channel)
# ---------------------------------------------------------------------------

def handle_client(conn, addr, store):
    try:
        req = recv_json(conn)
    except (ConnectionError, json.JSONDecodeError, ValueError) as e:
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
                req["name"],  # Can be name OR uuid now
                f"{addr[0]}:{req['port']}",
            )
        elif action == "get_peers":
            response = {"status": "ok", "peers": store.get_peers()}
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
# DNS Server (UDP, minimal A record responder for .shomescale)
# ---------------------------------------------------------------------------

class DNSServer:
    """Minimal DNS server that resolves A records for *.shomescale."""

    def __init__(self, store, port=DEFAULT_DNS_PORT):
        self.store = store
        self.port = port
        self.running = False

    def _parse_dns_query(self, data):
        """Extract the queried domain name and type from a DNS packet."""
        if len(data) < 12:
            return None, None
        flags = struct.unpack("!H", data[2:4])[0]
        qr = (flags >> 15) & 1  # 0 = query, 1 = response
        if qr != 0:
            return None, None
        qdcount = struct.unpack("!H", data[4:6])[0]
        if qdcount != 1:
            return None, None

        # Parse the question name
        offset = 12
        labels = []
        while offset < len(data):
            length = data[offset]
            if length == 0:
                offset += 1
                break
            labels.append(data[offset + 1:offset + 1 + length].decode("ascii"))
            offset += 1 + length

        # Parse question type
        if offset + 4 > len(data):
            return None, None
        qtype = struct.unpack("!H", data[offset:offset + 2])[0]

        domain = ".".join(labels).lower()
        return domain, qtype

    def _build_dns_response(self, txid, domain, ip_address, authoritative=False):
        """Build a DNS response packet."""
        flags = 0x8180  # Response, recursion desired, recursion available
        if authoritative:
            flags |= 0x0400  # Authoritative answer
        ancount = 1 if ip_address else 0
        header = struct.pack("!HHHHHH", txid, flags, 1, ancount, 0, 0)

        # Question (echo back)
        question = b""
        for label in domain.split("."):
            question += struct.pack("!B", len(label)) + label.encode("ascii")
        question += b"\x00"  # null terminator
        question += struct.pack("!HH", 1, 1)  # Type A, Class IN

        if not ip_address:
            return header + question

        # Answer: pointer to name in question (C0 0C = offset 12)
        answer = b"\xc0\x0c"
        answer += struct.pack("!HHIH", 1, 1, 300, 4)  # Type A, Class IN, TTL=300s, Length=4
        answer += socket.inet_aton(ip_address)

        return header + question + answer

    def run(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("0.0.0.0", self.port))
        sock.settimeout(1.0)
        self.running = True
        logger.info("DNS server listening on port %d", self.port)

        while self.running:
            try:
                data, addr = sock.recvfrom(512)
            except socket.timeout:
                continue

            try:
                txid = struct.unpack("!H", data[0:2])[0]
                domain, qtype = self._parse_dns_query(data)
                if domain is None:
                    continue

                logger.debug("DNS query: %s -> %s", domain, addr)

                # Check if it's for our domain
                suffix = "." + DNS_DOMAIN
                base_name = None
                if domain == DNS_DOMAIN:
                    base_name = DNS_DOMAIN  # query for "shomescale" itself
                elif domain.endswith(suffix):
                    base_name = domain[:-len(suffix)]

                ip = None
                if base_name and qtype == 1:  # A record
                    records = self.store.get_dns_records()
                    ip = records.get(base_name.lower())
                    if ip:
                        logger.info("DNS resolved: %s -> %s", domain, ip)

                if ip:
                    response = self._build_dns_response(txid, domain, ip, authoritative=True)
                else:
                    # NXDOMAIN: set rcode to 3
                    hdr = struct.pack("!HHHHHH", txid, 0x8583, 1, 0, 0, 0)
                    question = b""
                    for label in domain.split("."):
                        question += struct.pack("!B", len(label)) + label.encode("ascii")
                    question += b"\x00"
                    question += struct.pack("!HH", qtype or 1, 1)
                    response = hdr + question

                sock.sendto(response, addr)
            except Exception:
                logger.exception("DNS handler error for %s", addr)

        sock.close()

    def stop(self):
        self.running = False


# ---------------------------------------------------------------------------
# Web Dashboard (HTTP server)
# ---------------------------------------------------------------------------

DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>shomescale Dashboard</title>
<style>
  :root {
    --bg: #0d1117; --card: #161b22; --border: #30363d;
    --text: #c9d1d9; --text-muted: #8b949e; --green: #238636;
    --red: #da3633; --accent: #58a6ff;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, sans-serif;
    background: var(--bg); color: var(--text); padding: 20px;
  }
  .header {
    text-align: center; padding: 30px 0 10px;
  }
  .header h1 {
    font-size: 2.4em; color: var(--accent); margin-bottom: 4px;
  }
  .header p { color: var(--text-muted); }
  .stats {
    display: flex; gap: 16px; justify-content: center;
    flex-wrap: wrap; margin: 20px 0;
  }
  .stat-card {
    background: var(--card); border: 1px solid var(--border);
    border-radius: 12px; padding: 16px 28px; text-align: center;
    min-width: 140px;
  }
  .stat-card .value {
    font-size: 2em; font-weight: bold; margin: 4px 0;
  }
  .stat-card .label { color: var(--text-muted); font-size: 0.85em; }
  .stat-card.online .value { color: var(--green); }
  .stat-card.offline .value { color: var(--red); }
  .stat-card.total .value { color: var(--accent); }
  .stat-card.uptime .value { color: var(--text-muted); font-size: 1.4em; }
  table {
    width: 100%; border-collapse: collapse; margin-top: 10px;
    background: var(--card); border-radius: 12px; overflow: hidden;
  }
  th, td {
    padding: 10px 14px; text-align: left;
    border-bottom: 1px solid var(--border);
  }
  th {
    background: #1c2128; color: var(--text-muted);
    font-weight: 600; font-size: 0.85em; text-transform: uppercase;
  }
  tr:hover { background: #1c2128; }
  .status-dot {
    display: inline-block; width: 10px; height: 10px;
    border-radius: 50%; margin-right: 6px; vertical-align: middle;
  }
  .status-dot.online  { background: var(--green); }
  .status-dot.offline { background: var(--red); }
  .mono { font-family: 'SF Mono', Consolas, monospace; font-size: 0.9em; }
  .ago { color: var(--text-muted); font-size: 0.85em; }
  .footer {
    text-align: center; margin-top: 20px; color: var(--text-muted);
    font-size: 0.8em;
  }
  @keyframes pulse { 0%,100% { opacity: 1; } 50% { opacity: 0.5; } }
  .loading { animation: pulse 1.5s infinite; }
</style>
</head>
<body>
<div class="header">
  <h1>shomescale</h1>
  <p>Mesh VPN Dashboard &mdash; auto-refreshes every 3s</p>
</div>

<div id="loading" class="loading" style="text-align:center;padding:40px;color:#8b949e;">
  Loading...
</div>

<div id="content" style="display:none;">
  <div class="stats">
    <div class="stat-card total">
      <div class="label">Total Peers</div>
      <div class="value" id="totalPeers">&mdash;</div>
    </div>
    <div class="stat-card online">
      <div class="label">Online</div>
      <div class="value" id="onlinePeers">&mdash;</div>
    </div>
    <div class="stat-card offline">
      <div class="label">Offline</div>
      <div class="value" id="offlinePeers">&mdash;</div>
    </div>
    <div class="stat-card uptime">
      <div class="label">Uptime</div>
      <div class="value" id="uptime">&mdash;</div>
    </div>
  </div>

  <table>
    <thead>
      <tr>
        <th>Status</th>
        <th>Name</th>
        <th>UUID</th>
        <th>IP</th>
        <th>Endpoint</th>
        <th>Last Hello</th>
      </tr>
    </thead>
    <tbody id="peerTable"></tbody>
  </table>
</div>

<div class="footer">shomescale &middot; WireGuard Mesh VPN Dashboard</div>

<script>
function formatUptime(seconds) {
  if (!seconds || seconds < 0) return '--';
  const d = Math.floor(seconds / 86400);
  const h = Math.floor((seconds % 86400) / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  if (d > 0) return d + 'd ' + h + 'h ' + m + 'm';
  if (h > 0) return h + 'h ' + m + 'm';
  return m + 'm';
}

function timeAgo(stamp) {
  if (!stamp) return '--';
  const diff = Math.round(Date.now() / 1000 - stamp);
  if (diff < 5) return 'just now';
  if (diff < 60) return diff + 's ago';
  if (diff < 3600) return Math.floor(diff/60) + 'm ago';
  return Math.floor(diff/3600) + 'h ago';
}

async function refresh() {
  try {
    const r = await fetch('/api/status');
    const data = await r.json();
    const loading = document.getElementById('loading');
    const content = document.getElementById('content');
    loading.style.display = 'none';
    content.style.display = 'block';

    document.getElementById('totalPeers').textContent = data.total_peers;
    document.getElementById('onlinePeers').textContent = data.online;
    document.getElementById('offlinePeers').textContent = data.offline;
    document.getElementById('uptime').textContent = formatUptime(data.uptime);

    const tbody = document.getElementById('peerTable');
    tbody.innerHTML = '';
    for (const p of data.peers) {
      const dot = p.online ? 'online' : 'offline';
      const ago = p.online ? timeAgo(p.last_hello) : (timeAgo(p.last_hello) + ' (offline)');
      const tr = document.createElement('tr');
      tr.innerHTML = `
        <td><span class="status-dot ${dot}"></span>${p.online ? 'Online' : 'Offline'}</td>
        <td><strong>${p.name}</strong></td>
        <td class="mono" style="font-size:0.75em;color:#8b949e;">${p.uuid.substring(0,8)}</td>
        <td class="mono">${p.internal_ip}</td>
        <td class="mono" style="font-size:0.85em;">${p.endpoint || 'N/A'}</td>
        <td class="ago">${ago}</td>
      `;
      tbody.appendChild(tr);
    }
  } catch (e) {
    console.error('Dashboard refresh failed:', e);
    document.getElementById('loading').textContent = 'Connection lost. Retrying...';
  }
}

refresh();
setInterval(refresh, 3000);
</script>
</body>
</html>"""


class DashboardHandler(BaseHTTPRequestHandler):
    """HTTP request handler for the web dashboard."""

    store = None  # Set by web server starter

    def do_GET(self):
        if self.path == "/api/status":
            self._send_json(200, self.store.get_status())
        elif self.path == "/":
            self._send_html(200, DASHBOARD_HTML)
        else:
            self._send_json(404, {"error": "Not found"})

    def _send_json(self, code, data):
        body = json.dumps(data, indent=2).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_html(self, code, html):
        body = html.encode()
        self.send_response(code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        # Suppress per-request logs, use dashboard-level logging instead
        pass


def run_web_server(store, port=DEFAULT_WEB_PORT):
    """Start the HTTP dashboard server in its own thread."""
    handler = DashboardHandler
    handler.store = store
    server = HTTPServer(("0.0.0.0", port), handler)
    server_request = getattr(server, "shutdown_request", None)
    logger.info("Web dashboard listening on http://0.0.0.0:%d", port)
    server.serve_forever()

    # Allow graceful shutdown
    # Note: serve_forever() blocks, so stop is called via server.shutdown()
    # which causes serve_forever() to return


# ---------------------------------------------------------------------------
# Timeout checker (runs in its own thread)
# ---------------------------------------------------------------------------

def run_timeout_checker(store):
    while True:
        store.timeout_check()
        time.sleep(CHECK_INTERVAL)


# ---------------------------------------------------------------------------
# Daemon helpers
# ---------------------------------------------------------------------------

def check_stale_pid(pid_file):
    """Return True if a live process still owns the PID file.
    If stale, remove it and return False.
    """
    if not os.path.exists(pid_file):
        return False
    try:
        with open(pid_file, "r") as f:
            pid = int(f.read().strip())
        os.kill(pid, 0)          # Signal 0 = check existence
        return True               # Process is alive
    except (ValueError, OSError):
        try:
            logger.warning("Removing stale PID file")
        except Exception:
            pass  # logging may not be configured yet
        try:
            os.remove(pid_file)
        except OSError:
            pass
        return False


def create_pid(pid_file):
    with open(pid_file, "w") as f:
        f.write(str(os.getpid()))


def daemonize(log_file, pid_file):
    """Double-fork daemonization. Redirects stdout/stderr to log_file."""
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

def start_server(host="0.0.0.0", port=DEFAULT_PORT, bg=False, log_file="", pid_file="",
                 peers_file="", web_port=0, dns_port=0):
    store = PeersStore(peers_file)

    # Stale PID check BEFORE daemonizing (daemonize creates the PID file)
    if pid_file and check_stale_pid(pid_file):
        print(f"Server already running (check {pid_file})")
        sys.exit(1)

    if bg:
        daemonize(log_file, pid_file)
        # After daemonize: stdout/stderr already redirected to log_file.
        # Only use FileHandler to avoid duplicate lines.
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

    # Check if running as root for DNS port binding (only warn, dont fail,
    # since cap_net_bind_service might be set on the python binary)
    if dns_port > 0 and dns_port < 1024 and os.geteuid() != 0:
        logger.info("DNS port %d (privileged). Ensure cap_net_bind_service is set on python.", dns_port)

    # Start TCP coordination server
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((host, port))
    server.listen(5)
    logger.info("Coordination server listening on %s:%d", host, port)

    # Start timeout checker
    threading.Thread(target=run_timeout_checker, args=(store,), daemon=True).start()

    # Start DNS server (if enabled)
    dns_thread = None
    if dns_port > 0:
        dns = DNSServer(store, port=dns_port)
        dns_thread = threading.Thread(target=dns.run, daemon=True)
        dns_thread.start()

    # Start web dashboard (if enabled)
    if web_port > 0:
        threading.Thread(target=run_web_server, args=(store, web_port), daemon=True).start()

    # Main accept loop
    try:
        while True:
            conn, addr = server.accept()
            t = threading.Thread(target=handle_client, args=(conn, addr, store), daemon=True)
            t.start()
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
            print(f"  - {name} ({uid[:8]}): {info['internal_ip']} [{online_str}]  Endpoint: {info.get('endpoint', 'N/A')}")
    else:
        print("No peers registered.")


def stop_server(pid_file):
    if not check_stale_pid(pid_file):
        print("Server not running.")
        return
    with open(pid_file) as f:
        pid = int(f.read().strip())
    try:
        os.kill(pid, 15)  # SIGTERM
        print(f"Sent SIGTERM to {pid}.")
    except OSError as e:
        print(f"Failed to stop: {e}")
    if os.path.exists(pid_file):
        os.remove(pid_file)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="shomescale server - Central directory for a WireGuard mesh VPN",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # Start
    sp = subparsers.add_parser("start", help="Start the server")
    sp.add_argument("--bg", action="store_true", help="Run in background (daemon)")
    sp.add_argument("--host", default="0.0.0.0", help="Listen address (default 0.0.0.0)")
    sp.add_argument("--port", type=int, default=DEFAULT_PORT,
                    help=f"TCP coordination port (default {DEFAULT_PORT})")
    sp.add_argument("--web-port", type=int, default=0,
                    help="Web dashboard port (0=disabled, default 8080)")
    sp.add_argument("--dns-port", type=int, default=0,
                    help="DNS server port (0=disabled, default 5353)")

    # Status
    subparsers.add_parser("status", help="Check server status")

    # Stop
    subparsers.add_parser("stop", help="Stop the server")

    args = parser.parse_args()

    # Common paths (absolute, relative to cwd)
    pid_file = os.path.abspath("server.pid")
    log_file = os.path.abspath("server.log")
    peers_file = os.path.abspath("peers.json")

    # Feature ports are only on the 'start' subparser (default to 0 = disabled)
    if args.command == "start":
        start_server(args.host, args.port, args.bg, log_file, pid_file, peers_file,
                     web_port=getattr(args, "web_port", 0), dns_port=getattr(args, "dns_port", 0))
    elif args.command == "status":
        show_status(pid_file, peers_file)
    elif args.command == "stop":
        stop_server(pid_file)


if __name__ == "__main__":
    main()
