# shomescale

Simple Tailscale-like WireGuard mesh VPN in Python (~500 lines client, ~900 lines server).

Central directory server coordinates peers, assigns internal IPs, serves DNS, and hosts a live web dashboard.
All data traffic goes peer-to-peer over WireGuard — the server is only used for coordination.

## Architecture

```
Server (directory + DNS + dashboard)
├─ TCP coordination (:10000)  – peer registration, heartbeats, peer discovery
├─ DNS (:53)                  – resolves *.shomescale → internal IP
└─ Web dashboard (:8080)       – live-updating mesh topology view

Each peer (client)
├─ WireGuard (wg0)            – full-mesh encrypted tunnels to all peers
├─ dnsmasq (127.0.0.1:53)     – forwards *.shomescale → server DNS; everything else → gateway
└─ Daemon loop               – heartbeat, peer sync, DNS management
```

## DNS Design

No `/etc/hosts` hacking. Each client runs a local `dnsmasq` instance that:
- Forwards `*.shomescale` queries to the directory server's DNS (port 53)
- Forwards everything else to the upstream gateway (transparent internet access)
- `/etc/resolv.conf` points to `127.0.0.1` with gateway as fallback

Naming: `pi-cluster01-wg.shomescale` → `100.64.0.1`
- Display names enforced unique at registration (no collisions)
- Every peer also gets a `uuid4`; short prefix resolves too: `4aedd3cd.shomescale`
- Uses `.shomescale` as a custom TLD — no conflict with real domains

## Quick Start

### Server (once per deployment)

```bash
# Allow Python to bind port 53 (requires root once)
sudo setcap cap_net_bind_service=+ep /usr/bin/python3

# Start with DNS + dashboard
python3 server.py start --bg --dns-port 53 --web-port 8080

python3 server.py status   # see registered peers
python3 server.py stop     # clean shutdown
```

Dashboard → `http://<server-ip>:8080` (auto-refreshes every 3s)

### Client (each mesh node)

```bash
python3 client.py register --server 192.168.35.141 --name my-node --listen-port 51820
python3 client.py start --server 192.168.35.141 --bg   # WireGuard + dnsmasq + DNS

python3 client.py status --server 192.168.35.141        # check status
python3 client.py stop                                   # WireGuard down + DNS cleanup
```

## What Makes It Different

| Feature | This implementation | Tailscale |
|---------|--------------------|-----------|
| DNS | Custom UDP server (*.shomescale) + per-client dnsmasq forwarding | MagicDNS via coordination server |
| Name resolution | `name.shomescale` (custom TLD) | `name.account.ts.net` (real TLD) |
| Coordination | Simple TCP server (JSON) | DERP relay + Noise protocol |
| Peer discovery | Full mesh via directory | Mesh + DERP fallback |
| ACLs | Not yet | Per-user/group network policy |
| NAT traversal | Direct only | STUN + UDP hole punching |
| Auth keys | None (trusted LAN) | OAuth / machine auth keys |

## Server Ports

| Port | Service | Requires |
|------|---------|----------|
| 10000 | TCP coordination | none |
| 53 | DNS | `setcap` on python or root |
| 8080 | Web dashboard | none |

## Files Generated at Runtime (gitignored)

- `config.json` — client credentials (UUID, keys, IP)
- `peers.json` — all registered peer state on server
- `wg0.conf` — WireGuard config per client
- `*.pid` / `*.log` — daemon process management
