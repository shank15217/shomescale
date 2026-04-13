"""shomescale test suite - PeersStore tests."""

import json
import sys
import os
import threading
import time
import unittest.mock
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from shomescale_store import PeersStore


class TestPeersStore:
    def test_register_new_peer(self, tmp_path):
        with unittest.mock.patch("shomescale_rotation.generate_keypair",
                                  return_value=("A"*43+"=", "B"*43+"=")):
            store = PeersStore(str(tmp_path / "peers.json"), str(tmp_path / "acls.json"))
            ok, resp = store.register("node-a", "pubkey", "1.2.3.4:51820")
            assert ok
            assert resp["status"] == "ok"
            assert "uuid" in resp
            assert resp["name"] == "node-a"

    def test_register_duplicate_name(self, tmp_path):
        with unittest.mock.patch("shomescale_rotation.generate_keypair",
                                  return_value=("A"*43+"=", "B"*43+"=")):
            store = PeersStore(str(tmp_path / "peers.json"), str(tmp_path / "acls.json"))
            store.register("node-a", "pubkey", "1.2.3.4:51820")
            ok, resp = store.register("node-a", "pubkey2", "1.2.3.4:51821")
            assert not ok
            assert resp["status"] == "error"
            assert "taken" in resp["msg"].lower()

    def test_hello(self, tmp_path):
        with unittest.mock.patch("shomescale_rotation.generate_keypair",
                                  return_value=("A"*43+"=", "B"*43+"=")):
            store = PeersStore(str(tmp_path / "peers.json"), str(tmp_path / "acls.json"))
            ok, resp = store.register("node-a", "pubkey", "1.2.3.4:51820")
            uid = resp["uuid"]

            # Update heartbeat by name
            ok, resp = store.hello("node-a", "1.2.3.4:51821")
            assert ok
            assert resp["status"] == "ok"

    def test_hello_unknown_name(self, tmp_path):
        store = PeersStore(str(tmp_path / "peers.json"), str(tmp_path / "acls.json"))
        ok, resp = store.hello("nonexistent", "1.2.3.4:51820")
        assert not ok
        assert resp["status"] == "error"

    def test_get_peers(self, tmp_path):
        mock_keypair = [("A"*43+"=", "B"*43+"="), ("C"*43+"=", "D"*43+"=")]
        idx = [0]
        def next_key():
            k = mock_keypair[min(idx[0], len(mock_keypair)-1)]
            idx[0] += 1
            return k
        with unittest.mock.patch("shomescale_rotation.generate_keypair", next_key):
            store = PeersStore(str(tmp_path / "peers.json"), str(tmp_path / "acls.json"))
            store.register("node-a", "pubkey", "1.2.3.4:51820")
            store.register("node-b", "pubkey2", "1.2.3.4:51821")

            # Get peers without source (should return all, including self since
            # store.get_peers doesn't filter when no source_name given)
            peers = store.get_peers()
            assert len(peers) >= 2