# shomescale

A from-scratch WireGuard mesh VPN implementation built to understand how private mesh networks work. Features central coordination, DNS resolution, ACL-based group isolation, server-managed key rotation, and a web dashboard.

## Architecture

```
  Pi Cluster (x10)                    Directory Server (Rocky 9)
  ┌──────────────┐                    ┌─────────────────────────────┐
  │ client.py    │─── TCP :10000 ───>│ TCP Coordinator             │
  │ client_daemon│    (JSON)         │  ├─ PeersStore (peer reg)   │
  │ WireGuard    │<── rotate_keys ───│  ├─ ACL Engine (isolation)  │
  │ dnsmasq      │                   │  └─ Key Engine (rotation)   │
  │              │─── UDP :53 ──────>│ DNS Server (*.shomescale)   │
  │  wg0 mesh    │                   │                             │
  │ 100.64.0.x   │<── P2P ─────────>│ Web Dashboard :8080         │
  └──────────────┘                   └─────────────────────────────┘
```

See [shomescale-architecture.html](shomescale-architecture.html) for the full interactive diagram.

## Features

- **WireGuard full-mesh VPN** — P2P tunnels between every node via `wg syncconf`
- **Local mesh** — same-subnet nodes connect directly via LAN, avoiding relay/hairpin NAT
- **Central directory server** — TCP coordination with length-prefixed JSON protocol
- **UUID-based identity** — collision-proof peer identification (display names enforced unique)
- **DNS resolution** — `*.shomescale` domain via dnsmasq forwarding to server DNS
- **Web dashboard** — real-time peer list, topology graph, ACL rules (`:8080`)
- **ACL group isolation** — symmetric bidirectional isolation between groups
- **Server-managed key rotation** — central key authority with generation counter and live update
- **Key revocation** — exclude compromised peers from key rotation
- **Comprehensive test suite** — 81 pytest tests (protocol, ACL, rotation, DNS, dashboard, integration, local mesh)

## Modules

| Module | Purpose |
|--------|---------|
| `server.py` | Server entry point (TCP + HTTP + DNS) |
| `client.py` | Client CLI (register, start, stop, status) |
| `client_daemon.py` | Background daemon (heartbeat, peer sync, key rotation detection) |
| `client_wireguard.py` | WireGuard interface management |
| `client_dns.py` | DNS forwarding setup (dnsmasq) |
| `shomescale_protocol.py` | Length-prefixed JSON framing |
| `shomescale_store.py` | Peer registry + get_peers with ACL filtering |
| `shomescale_store_acls.py` | ACL engine (group isolation, revocation) |
| `shomescale_rotation.py` | KeyEngine (keypair generation, rotation, revocation) |
| `shomescale_dns.py` | DNS query parser + response builder |
| `shomescale_web.py` | Dashboard HTML + API endpoints |
| `shared.py` | Constants, intervals, ports |

## Protocol

All coordination uses a simple binary protocol over TCP:

```
[4-byte big-endian length][UTF-8 JSON payload]
```

**Client actions:**
- `register` — get UUID, IP, and server-generated keypair
- `hello` — heartbeat with current endpoint
- `get_peers` — fetch peer list (filtered by ACL)
- `get_keys` — fetch current keypair after rotation

**Server actions:**
- `rotate_keys` — rotate all online peers, bump generation counter
- `reload_acls` — reload ACL configuration from disk
- `get_status` — server uptime and peer statistics

## Quick Start

### Server (directory + DNS + dashboard)

```bash
python3 server.py start --bg --dns-port 53 --web-port 8080 --acls acls.json
python3 server.py status
python3 server.py stop
```

### Client (register + start)

```bash
python3 client.py register --server <SERVER_IP> --name my-node --listen-port 51820
python3 client.py start --server <SERVER_IP> --bg
python3 client.py status
python3 client.py stop
```

### ACL Configuration

```json
{
  "groups": {
    "team-a": ["node-1", "node-2"],
    "team-b": ["node-3", "node-4"]
  },
  "isolate": [
    { "group_a": "team-a", "group_b": "team-b" }
  ]
}
```

Isolated groups cannot see each other in peer lists or establish WireGuard tunnels.

## Testing

```bash
# Run full suite
uv run pytest tests/ -v

# Run specific test file
uv run pytest tests/test_integration.py -v

# Run with verbose output
uv run pytest tests/ --tb=short
```

**Test coverage (81 tests):**

| File | Tests | What's covered |
|------|-------|----------------|
| `test_protocol.py` | 10 | Length-prefixed JSON framing, edge cases |
| `test_acls.py` | 9 | ACL isolation, group membership, filtering |
| `test_rotation.py` | 12 | Key generation, rotation, persistence, revocation |
| `test_store.py` | 5 | Peer registration, hello, peer listing |
| `test_dns.py` | 13 | Query parsing, response building, live server |
| `test_web_dashboard.py` | 10 | HTML rendering, API endpoints, 404s |
| `test_integration.py` | 5 | Full server + client + ACL round-trip |
| `test_local_mesh.py` | 17 | Subnet detection, local IP, LAN-direct config, store |

## Deployment

**Server:** Rocky Linux 9 VM on Proxmox (`192.168.35.141`)
**Clients:** 10x Raspberry Pi (Debian 13) at `192.168.35.210-219`
**Internal mesh:** `100.64.0.0/10` CGNAT range
**WireGuard port:** UDP `51820`

## Roadmap

See [ROADMAP.md](ROADMAP.md) for the full feature roadmap and technical debt tracking.

**Upcoming features:**
- Subnet routing (expose home LAN via mesh)
- Exit node (route all traffic through trusted node)
- NAT traversal (STUN + UDP hole-punching)
- DERP relay (fallback for unreachable nodes)
- Prometheus metrics endpoint
- Packaging (deb/rpm)

## Requirements

- Python 3.9+
- WireGuard (`wg`, `wg-quick`)
- `dnsmasq` (client DNS forwarding)
- `dnspython` (test suite only)

## License

MIT
