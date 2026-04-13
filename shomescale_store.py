"""shomescale server: thread-safe peers store with ACL support."""

import json
import logging
import os
import threading
import time
import uuid

import shared
from shomescale_store_acls import AclEngine

logger = logging.getLogger("shomescale-store")

class PeersStore:
    """Thread-safe peers registry backed by a JSON file.

    Keys are uuid4 strings. Human names are display names only.
    """

    def __init__(self, peers_file, acls_file=None):
        self.peers_file = peers_file
        self.lock = threading.Lock()
        self.peers = {}
        self.name_index = {}
        self.ip_counter = 1
        self.start_time = time.time()
        self.acls = AclEngine(acls_file)
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
        for info in self.peers.values():
            if info.get("online", False):
                info["last_hello"] = now
            else:
                info["online"] = False
                info["last_hello"] = 0

    def _save_unlocked(self):
        tmp = self.peers_file + ".tmp"
        with open(tmp, "w") as f:
            json.dump(self.peers, f, indent=2)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, self.peers_file)

    def _name_taken(self, name):
        return name in self.name_index

    # -- public, lock-protected methods --

    def register(self, name, pubkey, endpoint):
        """Register a new peer or return error if name already taken."""
        with self.lock:
            if self._name_taken(name):
                return False, {"status": "error", "msg": "Name already taken"}

            node_uuid = str(uuid.uuid4())
            prefix = shared.INTERNAL_NETWORK.rsplit(".", 1)[0]
            internal_ip = f"{prefix}.{self.ip_counter}"
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
        """Update heartbeat. Accepts name or uuid."""
        with self.lock:
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

    def get_peers(self, source_name=None, source_uuid=None):
        """Return list of online peers filtered by ACL rules.

        Only returns peers that the requesting peer is allowed to see.
        """
        with self.lock:
            candidates = []
            for uid, info in self.peers.items():
                if not info["online"]:
                    continue
                if source_name and info.get("name") == source_name:
                    continue
                if source_uuid and uid == source_uuid:
                    continue
                candidates.append({
                    "name": info["name"],
                    "uuid": uid,
                    "pubkey": info["pubkey"],
                    "endpoint": info["endpoint"],
                    "internal_ip": info["internal_ip"],
                    "allowed_ips": info["internal_ip"] + "/32",
                })

            # Apply ACL filtering
            allowed = self.acls.filter_peers(source_name or source_uuid, candidates)

        return allowed

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
