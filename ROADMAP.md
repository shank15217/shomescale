# shomescale: Feature Roadmap

Status legend: ✅ Done | ⚠️ Partial | ❌ Not Started | 🔜 Next

## 📊 Core Infrastructure

| Feature | Status | Notes |
|---------|--------|-------|
| WireGuard full-mesh VPN | ✅ | P2P tunnels via `wg syncconf` |
| Central directory server | ✅ | TCP coordination (port 10000) |
| UUID-based peer identity | ✅ | Display names enforced unique, UUIDs are real IDs |
| DNS resolution (`*.shomescale`) | ✅ | `dnsmasq` forwarding to server port 53 |
| Web dashboard (`:8080`) | ✅ | Peer list, topology graph, ACL rules |
| Key rotation & revocation | ✅ | Server-managed keypairs, gen counter, live update |
| Test framework (pytest) | ✅ | 64 tests, unit + protocol + ACL + rotation + DNS + dashboard + integration |

## 🚧 Current Roadmap

| Feature | Status | Why It Matters |
|---------|--------|----------------|
| **1. Subnet Routing** | 🔜 Next | Access home LAN/remote networks through mesh |
| **2. Exit Node** | ❌ | Route all traffic through trusted node (public WiFi) |
| **3. NAT Traversal** | ❌ | STUN + UDP hole-punching for nodes behind NAT |
| **4. DERP-like Relay** | ❌ | Fallback relay for symmetric NAT / unreachable nodes |
| **5. ACL Matrix in Dashboard** | ❌ | Per-peer, per-destination permission grid |
| **6. Auto-renew/heartbeat expiry** | ❌ | 60s timeout, but no alerting or auto-removal |
| **7. Metrics / Grafana export** | ❌ | Prometheus endpoint for latency, uptime, tx/rx stats |
| **8. Packaging (deb/rpm/bin)** | ❌ | `pip install shomescale` or .deb for Pi deployment |

## 🔧 Technical Debt

| Issue | Severity | Notes |
|-------|----------|-------|
| `/etc/hosts` still written by client | Medium | DNS replaces most, but legacy code remains |
| No TLS on coordination channel | Medium | Keys sent over TCP in plaintext on LAN |
| Server is single point of failure | High | No HA/redundancy |
| No client auto-reconnect (TCP) | Medium | Backoff works, but no exponential jitter |

## 📋 Test Coverage Status

| Test Area | Tests | Status |
|-----------|-------|--------|
| Protocol framing | 10 | ✅ Complete |
| ACL engine | 9 | ✅ Complete |
| Key rotation | 12 | ✅ Complete |
| PeersStore | 5 | ✅ Complete |
| DNS server | 13 | ✅ Complete |
| Web dashboard | 10 | ✅ Complete |
| Integration | 5 | ✅ Complete |
| **Total** | **64** | ✅ **All passing** |
