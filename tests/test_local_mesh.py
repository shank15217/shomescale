"""shomescale test suite - local mesh (LAN-direct) endpoint selection.

Tests the local mesh feature: when two WireGuard nodes share a LAN subnet,
they should connect directly via local endpoints instead of going through
the directory server's observed (potentially NAT'd) endpoint.

This mirrors Tailscale's policy: Direct > Peer Relay > DERP.
In shomescale: same-subnet local_endpoint > public endpoint.
"""

import ipaddress
import sys
import os
import unittest.mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))


# ---------------------------------------------------------------------------
# Helper: subnet detection
# ---------------------------------------------------------------------------

class TestSubnetDetection:
    """Test same_subnet() logic for determining if two IPs share a LAN."""

    def test_same_class_c(self):
        from client_wireguard import same_subnet
        assert same_subnet("192.168.1.10", "192.168.1.20", "192.168.1.0/24") is True

    def test_different_class_c(self):
        from client_wireguard import same_subnet
        assert same_subnet("192.168.1.10", "192.168.2.20", "192.168.1.0/24") is False

    def test_same_16(self):
        from client_wireguard import same_subnet
        assert same_subnet("10.0.5.10", "10.0.99.20", "10.0.0.0/16") is True

    def test_different_major_octet(self):
        from client_wireguard import same_subnet
        assert same_subnet("10.0.0.1", "192.168.0.1", "10.0.0.0/8") is False

    def test_same_class_c_different_mask(self):
        from client_wireguard import same_subnet
        # /25 means 192.168.1.0-127 is one subnet, .128-.255 is another
        assert same_subnet("192.168.1.10", "192.168.1.200", "192.168.1.0/25") is False


# ---------------------------------------------------------------------------
# Helper: get_local_ip
# ---------------------------------------------------------------------------

class TestGetLocalIP:
    def test_returns_ip_string(self):
        from client_wireguard import get_local_ip
        # Mock socket to return a known IP
        with unittest.mock.patch("client_wireguard.socket") as mock_sock_mod:
            mock_s = unittest.mock.MagicMock()
            mock_s.getsockname.return_value = ("192.168.35.5", 12345)
            mock_sock_mod.socket.return_value = mock_s
            result = get_local_ip()
            assert result == "192.168.35.5"
            mock_s.connect.assert_called_once()

    def test_returns_none_on_failure(self):
        from client_wireguard import get_local_ip
        with unittest.mock.patch("client_wireguard.socket") as mock_sock_mod:
            mock_sock_mod.socket.side_effect = Exception("no network")
            result = get_local_ip()
            assert result is None


# ---------------------------------------------------------------------------
# WG config generation with local mesh
# ---------------------------------------------------------------------------

class TestGenerateConfLocalMesh:
    """Test that generate_conf picks local_endpoint for same-subnet peers."""

    def _make_config(self, local_ip="192.168.35.5", wg_ip="100.64.0.1"):
        return {
            "name": "node-a",
            "internal_ip": wg_ip,
            "privkey": "A" * 43 + "=",
            "listen_port": 51820,
            "local_ip": local_ip,
        }

    def test_same_subnet_uses_local_endpoint(self):
        from client_wireguard import generate_conf
        config = self._make_config(local_ip="192.168.35.5")
        peers = [
            {
                "name": "node-b",
                "pubkey": "B" * 43 + "=",
                "endpoint": "203.0.113.5:51820",       # public/NAT endpoint
                "local_endpoint": "192.168.35.10:51820",  # LAN endpoint
                "internal_ip": "100.64.0.2",
                "allowed_ips": "100.64.0.2/32",
            }
        ]
        conf = generate_conf(config, peers, subnet="192.168.35.0/24")
        # Should use local_endpoint, not the public one
        assert "Endpoint = 192.168.35.10:51820" in conf
        assert "Endpoint = 203.0.113.5:51820" not in conf

    def test_different_subnet_uses_public_endpoint(self):
        from client_wireguard import generate_conf
        config = self._make_config(local_ip="192.168.35.5")
        peers = [
            {
                "name": "node-b",
                "pubkey": "B" * 43 + "=",
                "endpoint": "203.0.113.5:51820",
                "local_endpoint": "10.0.0.10:51820",     # different subnet
                "internal_ip": "100.64.0.2",
                "allowed_ips": "100.64.0.2/32",
            }
        ]
        conf = generate_conf(config, peers, subnet="192.168.35.0/24")
        # Should use public endpoint
        assert "Endpoint = 203.0.113.5:51820" in conf
        assert "Endpoint = 10.0.0.10:51820" not in conf

    def test_no_local_endpoint_falls_back_to_public(self):
        from client_wireguard import generate_conf
        config = self._make_config(local_ip="192.168.35.5")
        peers = [
            {
                "name": "node-b",
                "pubkey": "B" * 43 + "=",
                "endpoint": "203.0.113.5:51820",
                # No local_endpoint key at all
                "internal_ip": "100.64.0.2",
                "allowed_ips": "100.64.0.2/32",
            }
        ]
        conf = generate_conf(config, peers, subnet="192.168.35.0/24")
        assert "Endpoint = 203.0.113.5:51820" in conf

    def test_no_subnet_param_behaves_like_before(self):
        """Backward compat: no subnet arg = old behavior (use endpoint as-is)."""
        from client_wireguard import generate_conf
        config = self._make_config(local_ip="192.168.35.5")
        peers = [
            {
                "name": "node-b",
                "pubkey": "B" * 43 + "=",
                "endpoint": "203.0.113.5:51820",
                "local_endpoint": "192.168.35.10:51820",
                "internal_ip": "100.64.0.2",
                "allowed_ips": "100.64.0.2/32",
            }
        ]
        conf = generate_conf(config, peers)
        # Without subnet, should use endpoint (old behavior)
        assert "Endpoint = 203.0.113.5:51820" in conf

    def test_mixed_subnets_selects_correctly(self):
        """Mix of same-subnet and different-subnet peers."""
        from client_wireguard import generate_conf
        config = self._make_config(local_ip="192.168.35.5")
        peers = [
            {
                "name": "node-b",
                "pubkey": "B" * 43 + "=",
                "endpoint": "203.0.113.5:51820",
                "local_endpoint": "192.168.35.10:51820",
                "internal_ip": "100.64.0.2",
                "allowed_ips": "100.64.0.2/32",
            },
            {
                "name": "node-c",
                "pubkey": "C" * 43 + "=",
                "endpoint": "198.51.100.5:51820",
                "local_endpoint": "10.0.0.5:51820",
                "internal_ip": "100.64.0.3",
                "allowed_ips": "100.64.0.3/32",
            },
        ]
        conf = generate_conf(config, peers, subnet="192.168.35.0/24")
        assert "Endpoint = 192.168.35.10:51820" in conf   # local for node-b
        assert "Endpoint = 198.51.100.5:51820" in conf     # public for node-c

    def test_self_peer_excluded(self):
        """Self should still be excluded from peer config."""
        from client_wireguard import generate_conf
        config = self._make_config()
        peers = [
            {
                "name": "node-a",  # same as config name
                "pubkey": "A" * 43 + "=",
                "endpoint": "192.168.35.5:51820",
                "local_endpoint": "192.168.35.5:51820",
                "internal_ip": "100.64.0.1",
                "allowed_ips": "100.64.0.1/32",
            }
        ]
        conf = generate_conf(config, peers, subnet="192.168.35.0/24")
        assert "[Peer]" not in conf


# ---------------------------------------------------------------------------
# Server: local_endpoint storage and distribution
# ---------------------------------------------------------------------------

class TestStoreLocalEndpoint:
    """Test that PeersStore stores and returns local_endpoint."""

    def test_register_stores_local_endpoint(self, tmp_path):
        with unittest.mock.patch("shomescale_rotation.generate_keypair",
                                  return_value=("A" * 43 + "=", "B" * 43 + "=")):
            from shomescale_store import PeersStore
            store = PeersStore(str(tmp_path / "peers.json"), str(tmp_path / "acls.json"))
            # Register with local_endpoint
            ok, resp = store.register(
                "node-a", "pubkey",
                endpoint="203.0.113.5:51820",
                local_endpoint="192.168.35.10:51820",
            )
            assert ok
            # Check it was stored
            uid = resp["uuid"]
            assert store.peers[uid]["endpoint"] == "203.0.113.5:51820"
            assert store.peers[uid]["local_endpoint"] == "192.168.35.10:51820"

    def test_register_without_local_endpoint_still_works(self, tmp_path):
        """Backward compat: no local_endpoint = old behavior."""
        with unittest.mock.patch("shomescale_rotation.generate_keypair",
                                  return_value=("A" * 43 + "=", "B" * 43 + "=")):
            from shomescale_store import PeersStore
            store = PeersStore(str(tmp_path / "peers.json"), str(tmp_path / "acls.json"))
            ok, resp = store.register("node-a", "pubkey", "203.0.113.5:51820")
            assert ok
            uid = resp["uuid"]
            assert store.peers[uid].get("local_endpoint") is None

    def test_hello_updates_local_endpoint(self, tmp_path):
        with unittest.mock.patch("shomescale_rotation.generate_keypair",
                                  return_value=("A" * 43 + "=", "B" * 43 + "=")):
            from shomescale_store import PeersStore
            store = PeersStore(str(tmp_path / "peers.json"), str(tmp_path / "acls.json"))
            ok, resp = store.register("node-a", "pubkey", "203.0.113.5:51820")
            assert ok

            # Hello with local_endpoint update
            ok, resp = store.hello("node-a", "203.0.113.5:51820",
                                    local_endpoint="192.168.35.10:51820")
            assert ok

            # Verify it was updated
            uid = store.name_index["node-a"]
            assert store.peers[uid]["local_endpoint"] == "192.168.35.10:51820"

    def test_get_peers_includes_local_endpoint(self, tmp_path):
        mock_keypair = [("A" * 43 + "=", "B" * 43 + "="),
                        ("C" * 43 + "=", "D" * 43 + "=")]
        idx = [0]
        def next_key():
            k = mock_keypair[min(idx[0], len(mock_keypair) - 1)]
            idx[0] += 1
            return k

        with unittest.mock.patch("shomescale_rotation.generate_keypair", next_key):
            from shomescale_store import PeersStore
            store = PeersStore(str(tmp_path / "peers.json"), str(tmp_path / "acls.json"))
            store.register("node-a", "pubkey", "203.0.113.5:51820",
                           local_endpoint="192.168.35.10:51820")
            store.register("node-b", "pubkey2", "198.51.100.5:51820",
                           local_endpoint="192.168.35.20:51820")

            peers = store.get_peers(source_name="node-a")
            for p in peers:
                assert "local_endpoint" in p
                assert p["local_endpoint"] is not None
