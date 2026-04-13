"""shomescale test suite - key rotation engine tests."""

import json
import sys
import os
import unittest.mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from shomescale_rotation import KeyEngine

# Mock key generation (avoids needing 'wg' binary)
MOCK_KEYPAIRS = {
    "peer-1": ("AAAA" * 11 + "=", "BBBB" * 11 + "="),
    "peer-2": ("CCCC" * 11 + "=", "DDDD" * 11 + "="),
    "peer-3": ("EEEE" * 11 + "=", "FFFF" * 11 + "="),
}

def mock_generate_keypair():
    return MOCK_KEYPAIRS.get("mock", ("XXXX" * 11 + "=", "YYYY" * 11 + "="))


class TestKeyEngineBasic:
    def test_create_keypair(self, tmp_path):
        with unittest.mock.patch("shomescale_rotation.generate_keypair", mock_generate_keypair):
            engine = KeyEngine(str(tmp_path))
            privkey, pubkey = engine.create_keypair("peer-1")
            assert privkey and pubkey
            assert len(privkey) >= 43  # base64 encoded 32 bytes
            assert len(pubkey) >= 43

    def test_create_keypair_unique(self, tmp_path):
        mock_calls = [
            ("AAAA"*11+"=", "BBBB"*11+"="),
            ("CCCC"*11+"=", "DDDD"*11+"=")
        ]
        idx = [0]
        def next_key():
            k = mock_calls[idx[0]]
            idx[0] += 1
            return k
        with unittest.mock.patch("shomescale_rotation.generate_keypair", next_key), \
             unittest.mock.patch("shomescale_rotation.KeyEngine._save"):
            engine = KeyEngine(str(tmp_path))
            priv1, pub1 = engine.create_keypair("peer-1")
            priv2, pub2 = engine.create_keypair("peer-2")
            assert priv1 != priv2
            assert pub1 != pub2

    def test_get_keypair(self, tmp_path):
        with unittest.mock.patch("shomescale_rotation.generate_keypair", mock_generate_keypair), \
             unittest.mock.patch("shomescale_rotation.KeyEngine._save"):
            engine = KeyEngine(str(tmp_path))
            engine.create_keypair("peer-1")
            privkey, pubkey, gen = engine.get_keypair("peer-1")
            assert privkey is not None
            assert pubkey is not None
            assert gen == 1

    def test_get_keypair_unknown(self, tmp_path):
        with unittest.mock.patch("shomescale_rotation.KeyEngine._save"):
            engine = KeyEngine(str(tmp_path))
            privkey, pubkey, gen = engine.get_keypair("unknown")
            assert privkey is None
            assert pubkey is None
            assert gen == 0

    def test_get_pubkey(self, tmp_path):
        with unittest.mock.patch("shomescale_rotation.generate_keypair", mock_generate_keypair), \
             unittest.mock.patch("shomescale_rotation.KeyEngine._save"):
            engine = KeyEngine(str(tmp_path))
            engine.create_keypair("peer-1")
            pubkey, gen = engine.get_pubkey("peer-1")
            assert pubkey is not None
            assert gen == 1


class TestKeyRotation:
    def test_rotate_single(self, tmp_path):
        calls = [("AAAA"*11+"=", "BBBB"*11+"="), ("CCCC"*11+"=", "DDDD"*11+"=")]
        idx = [0]
        def next_key():
            k = calls[min(idx[0], len(calls)-1)]
            idx[0] += 1
            return k
        with unittest.mock.patch("shomescale_rotation.generate_keypair", next_key), \
             unittest.mock.patch("shomescale_rotation.KeyEngine._save"):
            engine = KeyEngine(str(tmp_path))
            engine.create_keypair("peer-1")
            old_pubkey = engine.get_pubkey("peer-1")[0]

            _, new_pubkey, gen = engine.rotate("peer-1")
            assert gen == 2
            assert new_pubkey != old_pubkey

    def test_rotate_multiple(self, tmp_path):
        with unittest.mock.patch("shomescale_rotation.generate_keypair", mock_generate_keypair), \
             unittest.mock.patch("shomescale_rotation.KeyEngine._save"):
            engine = KeyEngine(str(tmp_path))
            engine.create_keypair("peer-1")
            engine.create_keypair("peer-2")
            engine.create_keypair("peer-3")

            count = engine.rotate_all_online(["peer-1", "peer-2"])
            assert count == 2

            assert engine.get_keypair("peer-1")[2] == 2
            assert engine.get_keypair("peer-2")[2] == 2
            assert engine.get_keypair("peer-3")[2] == 1

    def test_rotate_unknown(self, tmp_path):
        with unittest.mock.patch("shomescale_rotation.KeyEngine._save"):
            engine = KeyEngine(str(tmp_path))
            privkey, pubkey, gen = engine.rotate("nonexistent")
            assert privkey is None
            assert pubkey is None
            assert gen == 0


class TestKeyPersistence:
    def test_keystore_persists(self, tmp_path):
        mock_key = ("A" * 43 + "=", "B" * 43 + "=")
        with unittest.mock.patch("shomescale_rotation.generate_keypair", return_value=mock_key):
            engine1 = KeyEngine(str(tmp_path))
            engine1.create_keypair("peer-1")
            old_privkey, old_pubkey, old_gen = engine1.get_keypair("peer-1")

            engine2 = KeyEngine(str(tmp_path))
            privkey, pubkey, gen = engine2.get_keypair("peer-1")

            assert privkey == old_privkey
            assert pubkey == old_pubkey
            assert gen == old_gen

    def test_keystore_file_valid_json(self, tmp_path):
        with unittest.mock.patch("shomescale_rotation.generate_keypair", mock_generate_keypair):
            engine = KeyEngine(str(tmp_path))
            engine.create_keypair("peer-1")

            with open(tmp_path / "keystore.json") as f:
                data = json.load(f)

            assert "peer-1" in data
            assert data["peer-1"]["key_generation"] == 1
            assert data["peer-1"].get("revoked") is False


class TestRevocation:
    def test_revoke(self, tmp_path):
        mock_key = ("A" * 43 + "=", "B" * 43 + "=")
        with unittest.mock.patch("shomescale_rotation.generate_keypair", return_value=mock_key):
            engine = KeyEngine(str(tmp_path))
            engine.create_keypair("peer-1")
            assert engine.is_revoked("peer-1") is False

            engine.revoke("peer-1")
            assert engine.is_revoked("peer-1") is True

            engine.clear_revocation("peer-1")
            assert engine.is_revoked("peer-1") is False

    def test_revoke_unknown(self, tmp_path):
        engine = KeyEngine(str(tmp_path))
        # No need to create a keypair - just test unknown peer
        assert engine.is_revoked("unknown") is True
