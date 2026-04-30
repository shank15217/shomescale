"""shomescale server: thread-safe peers store with ACL support."""

import json
import logging
import os
import threading
import time
import uuid

import shared
from shomescale_store_acls import AclEngine
from shomescale_rotation import KeyEngine

logger = logging.getLogger("shomescale-store")

class PeersStore:
    """Thread-safe peers registry backed by a JSON file.

    Keys are uuid4 strings. Human names are display names only.
    """

    def __init__(self, peers_file, acls_file=None):
        self.peers_file = peers_file
        base_dir = os.path.dirname(os.path.abspath(peers_file))
        self.lock = threading.Lock()
        self.peers = {}
        self.name_index = {}
        self.ip_counter = 1
        self.start_time = time.time()
        self.acls = AclEngine(acls_file)
        self.keys = KeyEngine(base_dir)
        self._load()

    def _load(self):
        if os.path.exists(self.peers_file):
            with open(self.peers_file, "r") as f:
                data = json.load(f)
        else:
            self._save_unlocked()
            return

        if data:
            first_key = next(iter(data))
            first_val = next(iter(data.values()))
            old_format = (
                isinstance(first_val, dict)
                and "name" not in first_val
                and first_key.count("-") != 4
            )

            if old_format:
                self.peers = {}
                for old_name, info in data.items():
                    uid = str(uuid.uuid4())
                    info["name"] = old_name
                    info["uuid"] = uid
                    info.setdefault("online", False)
                    info.setdefault("last_hello", 0)
                    self.peers[uid] = info
                    self.name_index[old_name] = uid
            else:
                self.peers = data
                for uid, info in self.peers.items():
                    name = info.get("name", "")
                    if name:
                        self.name_index[name] = uid

            if self.peers:
                self.ip_counter = (
                    max(
                        int(info["internal_ip"].split(".")[-1])
                        for info in self.peers.values()
                    )
                    + 1
                )

        now = time.time()
        for uid, info in self.peers.items():
            if info.get("online", False):
                info["last_hello"] = now
            else:
                info["online"] = False
                info["last_hello"] = 0

        # Backfill keystore for peers migrated from older versions
        for uid, info in self.peers.items():
            privkey, pubkey, gen = self.keys.get_keypair(uid)
            if gen == 0 and info.get("pubkey"):
                # No keystore entry - create one (key_generation stays at 1)
                self.keys.keystore[uid] = {
                    "privkey": info["pubkey"],  # we don't have the actual privkey
                    "pubkey": info["pubkey"],
                    "key_generation": 1,
                    "last_rotated_at": info.get("registered_at", now),
                    "revoked": False,
                }
        self.keys._save()

    def _save_unlocked(self):
        # Save peers + key generation info together
        data = {}
        for uid, info in self.peers.items():
            data[uid] = dict(info)
            _, _, gen = self.keys.get_keypair(uid)
            if gen > 0:
                data[uid]["key_generation"] = gen
        tmp = self.peers_file + ".tmp"
        with open(tmp, "w") as f:
            json.dump(data, f, indent=2)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, self.peers_file)

    def _name_taken(self, name):
        return name in self.name_index

    # -- public, lock-protected methods --

    def register(self, name, pubkey, endpoint, local_endpoint=None):
        """Register a new peer - server generates the keypair.

        Args:
            endpoint: the public/NAT'd endpoint seen by the server.
            local_endpoint: the LAN endpoint reported by the client (optional).
        """
        with self.lock:
            if self._name_taken(name):
                return False, {"status": "error", "msg": "Name already taken"}

            node_uuid = str(uuid.uuid4())
            privkey, pubkey = self.keys.create_keypair(node_uuid)
            prefix = shared.INTERNAL_NETWORK.rsplit(".", 1)[0]
            internal_ip = f"{prefix}.{self.ip_counter}"
            now = time.time()
            self.peers[node_uuid] = {
                "name": name,
                "uuid": node_uuid,
                "pubkey": pubkey,
                "endpoint": endpoint,
                "local_endpoint": local_endpoint,
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

    def rotate_keys(self):
        """Rotate keypair for every online peer. Returns list of (uuid, new_pubkey, gen)."""
        with self.lock:
            rotated = []
            for uid, info in self.peers.items():
                if info.get("online", False):
                    privkey, pubkey, gen = self.keys.rotate(uid)
                    if privkey:
                        info["pubkey"] = pubkey
                        rotated.append({
                            "uuid": uid,
                            "name": info["name"],
                            "pubkey": pubkey,
                            "key_generation": gen,
                            "privkey": privkey,
                        })
            self._save_unlocked()
            logger.info("Rotated keys for %d peers", len(rotated))
        return rotated

    def hello(self, name_or_uuid, endpoint, local_endpoint=None):
        """Update heartbeat. Accepts name or uuid.

        Args:
            endpoint: the public/NAT'd endpoint.
            local_endpoint: the LAN endpoint reported by the client (optional).
        """
        with self.lock:
            uid = self.peers.get(name_or_uuid, {}).get("uuid")
            if uid is None:
                uid = self.name_index.get(name_or_uuid)
            if uid is None:
                return False, {"status": "error", "msg": "Unknown name or uuid"}

            self.peers[uid]["endpoint"] = endpoint
            if local_endpoint is not None:
                self.peers[uid]["local_endpoint"] = local_endpoint
            self.peers[uid]["last_hello"] = time.time()
            self.peers[uid]["online"] = True
            self._save_unlocked()

        return True, {"status": "ok"}

    def get_peers(self, source_name=None, source_uuid=None, include_self=False):
        """Return list of online peers filtered by ACL rules.

        Only returns peers that the requesting peer is allowed to see.
        If include_self is True, the requesting peer is included in the results.
        """
        with self.lock:
            candidates = []
            for uid, info in self.peers.items():
                if not info["online"]:
                    continue
                if not include_self and source_name and info.get("name") == source_name:
                    continue
                if not include_self and source_uuid and uid == source_uuid:
                    continue
                candidates.append({
                    "name": info["name"],
                    "uuid": uid,
                    "pubkey": info["pubkey"],
                    "endpoint": info["endpoint"],
                    "local_endpoint": info.get("local_endpoint"),
                    "internal_ip": info["internal_ip"],
                    "allowed_ips": info["internal_ip"] + "/32",
                    "key_generation": self.keys.get_pubkey(uid)[1],
                })

            # Apply ACL filtering
            allowed = self.acls.filter_peers(source_name or source_uuid, candidates)

        return allowed

    def get_peer_keys(self, peer_uuid):
        """Get the current keypair for a peer (privkey + pubkey + generation)."""
        with self.lock:
            privkey, pubkey, gen = self.keys.get_keypair(peer_uuid)
            if privkey is None:
                return None
            return {
                "privkey": privkey,
                "pubkey": pubkey,
                "key_generation": gen,
            }

    def get_status(self):
        """Full status for web dashboard."""
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
            peers.sort(key=lambda p: (not p["online"], p["name"]))
            online_count = sum(1 for p in peers if p["online"])

        return {
            "uptime": round(uptime, 1),
            "total_peers": len(peers),
            "online": online_count,
            "offline": len(peers) - online_count,
            "peers": peers,
        }

    def get_dns_records(self):
        """Return {name_lower: ip} for DNS A records."""
        with self.lock:
            records = {}
            for uid, info in self.peers.items():
                if info["online"]:
                    records[info["name"].lower()] = info["internal_ip"]
                    records[uid[:8]] = info["internal_ip"]
        return records

    def timeout_check(self):
        """Mark peers stale as offline."""
        now = time.time()
        with self.lock:
            changed = False
            for info in self.peers.values():
                if (
                    info["last_hello"] < now - shared.HEARTBEAT_TIMEOUT
                    and info.get("online")
                ):
                    info["online"] = False
                    changed = True
            if changed:
                self._save_unlocked()

    def reload_acls(self):
        """Reload ACL configuration from disk."""
        self.acls.reload()

    def get_topology(self):
        """Return nodes + edges for the ACL topology graph.
        
        Returns all peers as nodes, and ALL pairwise directed edges
        showing whether the ACL allows or blocks communication.
        This reveals the full policy even for peers that can't see
        each other (unlike get_peers which filters out blocked peers).
        """
        with self.lock:
            nodes = []
            peer_names = []  # for group resolution
            for uid, info in self.peers.items():
                nodes.append({
                    "name": info["name"],
                    "uuid": uid,
                    "internal_ip": info["internal_ip"],
                    "online": info.get("online", False),
                    "_k": uid,
                })
                peer_names.append(info["name"])
            
            edges = []
            peer_lookup = {p["name"]: p["uuid"] for p in nodes}
            for src_name, src_uuid in peer_lookup.items():
                for dst_name, dst_uuid in peer_lookup.items():
                    if src_uuid == dst_uuid:
                        continue
                    allowed = self.acls.is_allowed(src_name, dst_name)
                    edges.append({
                        "from": src_uuid,
                        "to": dst_uuid,
                        "allowed": allowed,
                    })
            
        rules_data = self.acls.get_rules_data(peer_names)
        return {
            "nodes": nodes,
            "edges": edges,
            "rules": rules_data,
        }
