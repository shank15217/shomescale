"""shomescale key rotation engine.

Server-managed WireGuard key generation and rotation.
Keys are stored server-side and distributed to clients over the
coordination channel. This allows automatic revocation via rotation
- compromised peers get excluded from the key update cycle.

Flow:
1. Server generates keypair for each peer during registration
2. Server persists keystore to keystore.json (survives restarts)
3. Rotation bumps key_generation and generates fresh keypairs
4. Clients detect generation change via peer list and fetch new keys
"""

import json
import logging
import os
import subprocess
import threading
import time

logger = logging.getLogger("shomescale-rotation")

KEYSTORE_FILE = "keystore.json"  # persisted alongside peers.json


def generate_keypair():
    """Generate a WireGuard keypair using the wg CLI."""
    privkey = subprocess.check_output(["wg", "genkey"]).decode().strip()
    pubkey = subprocess.check_output(
        ["wg", "pubkey"], input=privkey.encode()
    ).decode().strip()
    return privkey, pubkey


class KeyEngine:
    """Manages WireGuard keypairs for all peers.

    Server is the authority: generates, stores, and distributes keys.
    Persisted to keystore.json for crash recovery.
    """

    def __init__(self, base_dir="."):
        self.lock = threading.Lock()
        self.keystore = {}
        self.store_file = os.path.join(base_dir, KEYSTORE_FILE)
        self._load()

    def _load(self):
        if os.path.exists(self.store_file):
            try:
                with open(self.store_file) as f:
                    self.keystore = json.load(f)
                logger.info("Loaded keystore: %d entries", len(self.keystore))
            except Exception:
                logger.warning("Failed to load keystore, starting fresh")
                self.keystore = {}

    def _save(self):
        tmp = self.store_file + ".tmp"
        with open(tmp, "w") as f:
            json.dump(self.keystore, f, indent=2)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, self.store_file)

    # -- public API --

    def create_keypair(self, peer_uuid):
        """Generate initial keypair for a newly registered peer."""
        with self.lock:
            privkey, pubkey = generate_keypair()
            self.keystore[peer_uuid] = {
                "privkey": privkey,
                "pubkey": pubkey,
                "key_generation": 1,
                "last_rotated_at": time.time(),
                "revoked": False,
            }
            self._save()
            return privkey, pubkey

    def rotate(self, peer_uuid):
        """Rotate keypair for a single peer. Returns (privkey, pubkey, generation)."""
        with self.lock:
            if peer_uuid not in self.keystore:
                return None, None, 0
            entry = self.keystore[peer_uuid]
            privkey, pubkey = generate_keypair()
            entry["privkey"] = privkey
            entry["pubkey"] = pubkey
            entry["key_generation"] = entry.get("key_generation", 1) + 1
            entry["last_rotated_at"] = time.time()
            entry["revoked"] = False
            self._save()
            return privkey, pubkey, entry["key_generation"]

    def rotate_all_online(self, online_uuids):
        """Rotate keys for a set of peers. Returns rotated count."""
        with self.lock:
            count = 0
            for uid in online_uuids:
                if uid in self.keystore:
                    entry = self.keystore[uid]
                    privkey, pubkey = generate_keypair()
                    entry["privkey"] = privkey
                    entry["pubkey"] = pubkey
                    entry["key_generation"] = entry.get("key_generation", 1) + 1
                    entry["last_rotated_at"] = time.time()
                    entry["revoked"] = False
                    count += 1
            if count:
                self._save()
            return count

    def get_keypair(self, peer_uuid):
        """Return (privkey, pubkey, generation) or (None, None, 0)."""
        with self.lock:
            if peer_uuid not in self.keystore:
                return None, None, 0
            entry = self.keystore[peer_uuid]
            return entry["privkey"], entry["pubkey"], entry["key_generation"]

    def get_pubkey(self, peer_uuid):
        """Return (pubkey, generation) or (None, 0)."""
        with self.lock:
            if peer_uuid not in self.keystore:
                return None, 0
            entry = self.keystore[peer_uuid]
            return entry["pubkey"], entry["key_generation"]

    def revoke(self, peer_uuid):
        with self.lock:
            if peer_uuid in self.keystore:
                self.keystore[peer_uuid]["revoked"] = True
                self._save()

    def clear_revocation(self, peer_uuid):
        with self.lock:
            if peer_uuid in self.keystore:
                self.keystore[peer_uuid]["revoked"] = False
                self._save()

    def is_revoked(self, peer_uuid):
        with self.lock:
            if peer_uuid not in self.keystore:
                return True
            return self.keystore[peer_uuid].get("revoked", False)
