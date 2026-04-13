"""shomescale test suite - integration tests.

Tests that exercise multiple modules together:
store + ACL + rotation + protocol in a realistic flow.
"""

import json
import socket
import struct
import threading
import time
import unittest.mock

import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from shomescale_store import PeersStore
from shomescale_protocol import send_json, recv_json


def start_server(store, host="127.0.0.1"):
    """Start a TCP server for the given PeersStore."""
    import shomescale_store_acls as acls_mod

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((host, 0))
    srv.listen(5)
    srv.settimeout(2.0)
    port = srv.getsockname()[1]

    def handler():
        while True:
            try:
                conn, addr = srv.accept()
            except (socket.timeout, OSError):
                break
            try:
                req = recv_json(conn)
                action = req.get("action", "")
                response = {}

                if action == "register":
                    ok, response = store.register(
                        req["name"], req["pubkey"], f"{addr[0]}:{req['port']}")
                elif action == "hello":
                    ok, response = store.hello(
                        req["name"], f"{addr[0]}:{req['port']}")
                elif action == "get_peers":
                    response = {"status": "ok", "peers": store.get_peers(
                        source_name=req.get("name"))}
                elif action == "get_keys":
                    uid = req.get("uuid", "")
                    k = store.get_peer_keys(uid)
                    if k:
                        response = {"status": "ok", "keys": k}
                    else:
                        response = {"status": "error", "msg": "Unknown UUID"}
                elif action == "rotate_keys":
                    onlines = [uid for uid, info in store.peers.items()
                               if info.get("online")]
                    count = store.keys.rotate_all_online(onlines)
                    for uid, _, pub, gen in [(uid, *store.keys.get_keypair(uid), store.keys.get_keypair(uid)[2])
                                             for uid in onlines]:
                        store.peers[uid]["pubkey"] = pub
                    response = {"status": "ok", "rotated_count": count}
                elif action == "reload_acls":
                    store.acls.reload()
                    response = {"status": "ok"}
                elif action == "get_status":
                    response = {"status": "ok", "data": store.get_status()}
                else:
                    response = {"status": "error", "msg": f"Unknown action: {action}"}

                send_json(conn, response)
            except Exception:
                pass
            finally:
                conn.close()

    t = threading.Thread(target=handler, daemon=True)
    t.start()
    time.sleep(0.1)
    return srv, port, t


class TestIntegrationRegistration:
    """Full registration flow: client-like request → server response."""

    def setup_method(self):
        # Create ACL config
        self.acls_file = "/tmp/test_int_acls.json"
        self.peers_file = "/tmp/test_int_peers.json"

        # Create empty peers file
        with open(self.peers_file, "w") as f:
            json.dump({}, f)

        with unittest.mock.patch("shomescale_rotation.generate_keypair",
                                  return_value=("A" * 43 + "=", "B" * 43 + "=")):
            self.store = PeersStore(self.peers_file, self.acls_file)
            self.srv, self.port, self.thread = start_server(self.store)

    def teardown_method(self):
        self.srv.close()
        self.thread.join(timeout=2)
        for f in [self.acls_file, self.peers_file]:
            try:
                os.remove(f)
            except OSError:
                pass

    def _send(self, req):
        """Send request to the server and get response."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect(("127.0.0.1", self.port))
        send_json(sock, req)
        resp = recv_json(sock)
        sock.close()
        return resp

    def test_full_register_flow(self):
        """Register, get keys, and verify peer appears in list."""
        with unittest.mock.patch("shomescale_rotation.generate_keypair",
                                  return_value=("A" * 43 + "=", "B" * 43 + "=")):
            resp = self._send({
                "action": "register",
                "name": "test-node",
                "pubkey": "dummy",
                "port": 51820,
            })
        assert resp["status"] == "ok"
        assert "uuid" in resp
        assert "internal_ip" in resp

        # Verify peer appears in get_peers
        peers = self._send({"action": "get_peers"})
        assert peers["status"] == "ok"
        assert any(p["name"] == "test-node" for p in peers["peers"])

    def test_register_then_hello(self):
        """Register a peer, then heartbeat, verify it stays online."""
        with unittest.mock.patch("shomescale_rotation.generate_keypair",
                                  return_value=("A" * 43 + "=", "B" * 43 + "=")):
            resp = self._send({
                "action": "register",
                "name": "heartbeat-node",
                "pubkey": "dummy",
                "port": 51820,
            })
        uid = resp["uuid"]

        # Send heartbeat
        hello = self._send({
            "action": "hello",
            "name": "heartbeat-node",
            "port": 51820,
        })
        assert hello["status"] == "ok"

        # Verify the peer is online
        with self.store.lock:
            peer = self.store.peers.get(uid)
            assert peer is not None
            assert peer["online"] is True

    def test_register_duplicate_rejected(self):
        """Register same name twice - second should fail."""
        with unittest.mock.patch("shomescale_rotation.generate_keypair",
                                  return_value=("A" * 43 + "=", "B" * 43 + "=")):
            r1 = self._send({
                "action": "register",
                "name": "duplicate-node",
                "pubkey": "dummy",
                "port": 51820,
            })
            r2 = self._send({
                "action": "register",
                "name": "duplicate-node",
                "pubkey": "dummy2",
                "port": 51821,
            })

        assert r1["status"] == "ok"
        assert r2["status"] == "error"
        assert "taken" in r2["msg"].lower()

    def test_get_keys_returns_privkey(self):
        """After registration, get_keys returns the stored keypair."""
        with unittest.mock.patch("shomescale_rotation.generate_keypair",
                                  return_value=("A" * 43 + "=", "B" * 43 + "=")):
            reg = self._send({
                "action": "register",
                "name": "keytest-node",
                "pubkey": "dummy",
                "port": 51820,
            })
        uid = reg["uuid"]

        keys_resp = self._send({"action": "get_keys", "uuid": uid})
        assert keys_resp["status"] == "ok"
        assert "keys" in keys_resp
        assert keys_resp["keys"]["privkey"] == "A" * 43 + "="
        assert keys_resp["keys"]["pubkey"] == "B" * 43 + "="


class TestIntegrationWithACLs:
    """Integration tests with ACL enforcement."""

    def setup_method(self):
        self.acls_file = "/tmp/test_int_acl2.json"
        self.peers_file = "/tmp/test_int_peers2.json"

        # Write an ACL config that isolates two groups
        acl_config = {
            "groups": {
                "isolated1": ["node-a"],
                "isolated2": ["node-b"],
            },
            "isolate": [
                {"group_a": "isolated1", "group_b": "isolated2"}
            ]
        }
        with open(self.acls_file, "w") as f:
            json.dump(acl_config, f)

        with open(self.peers_file, "w") as f:
            json.dump({}, f)

        with unittest.mock.patch("shomescale_rotation.generate_keypair",
                                  return_value=("A" * 43 + "=", "B" * 43 + "=")):
            self.store = PeersStore(self.peers_file, self.acls_file)
            self.srv, self.port, self.thread = start_server(self.store)

    def teardown_method(self):
        self.srv.close()
        self.thread.join(timeout=2)
        for f in [self.acls_file, self.peers_file]:
            try:
                os.remove(f)
            except OSError:
                pass

    def _send(self, req):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect(("127.0.0.1", self.port))
        send_json(sock, req)
        resp = recv_json(sock)
        sock.close()
        return resp

    def test_acl_filtering_during_get_peers(self):
        """Register two isolated nodes; each should not see the other."""
        mock_key = iter([("K1" + "A" * 41 + "=", "K1" + "B" * 41 + "="),
                          ("K2" + "A" * 41 + "=", "K2" + "B" * 41 + "=")])
        with unittest.mock.patch("shomescale_rotation.generate_keypair",
                                  side_effect=mock_key):
            self._send({"action": "register", "name": "node-a",
                         "pubkey": "dummy", "port": 51820})
            self._send({"action": "register", "name": "node-b",
                         "pubkey": "dummy", "port": 51821})

        # node-a's get_peers should NOT include node-b
        peers = self._send({"action": "get_peers", "name": "node-a"})
        names = [p["name"] for p in peers.get("peers", [])]
        assert "node-b" not in names  # isolated

        # node-b's get_peers should NOT include node-a
        peers = self._send({"action": "get_peers", "name": "node-b"})
        names = [p["name"] for p in peers.get("peers", [])]
        assert "node-a" not in names  # isolated
