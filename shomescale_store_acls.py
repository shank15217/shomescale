"""shomescale ACL engine.

Rules are loaded from an acls.json file and applied when get_peers()
is called. Supports groups, glob patterns, and ordered allow/deny rules.

acls.json format:
{
  "groups": {
    "all": ["*"],
    "cluster": ["pi-cluster*-wg"]
  },
  "rules": [
    {"from": "all", "to": "all", "action": "allow"}
  ]
}

Rules are evaluated in order. First match wins.
If no rule matches, the default is DENY.
"""

import json
import logging
import os
import fnmatch

logger = logging.getLogger("shomescale-acls")


class AclEngine:
    """Access control list engine for mesh peer filtering."""

    def __init__(self, acls_file=None):
        self.acls_file = acls_file
        self.groups = {}
        self.rules = []
        self._load()

    def _load(self):
        """Load or create default ACLs (allow all)."""
        if not self.acls_file or not os.path.exists(self.acls_file):
            # Default: allow everything
            self.groups = {}
            self.rules = [{"from": "*", "to": "*", "action": "allow"}]
            return

        try:
            with open(self.acls_file, "r") as f:
                data = json.load(f)
            self.groups = data.get("groups", {})
            self.rules = data.get("rules", [{"from": "*", "to": "*", "action": "allow"}])
        except Exception:
            logger.exception("Failed to load ACLs, using allow-all default")
            self.groups = {}
            self.rules = [{"from": "*", "to": "*", "action": "allow"}]

    def reload(self):
        """Reload ACLs from disk."""
        self._load()

    def _match(self, pattern, name):
        """Check if a pattern matches a peer name.
        Supports '*', '?', and glob patterns like 'pi-cluster*-wg'.
        """
        if pattern == "*":
            return True
        if name is None:
            return False
        return fnmatch.fnmatch(name, pattern)

    def _peers_in_set(self, spec, source_name):
        """Check if source_name matches any pattern in a group or list."""
        # Check group names first (before pattern matching)
        if isinstance(spec, str) and spec in self.groups:
            return any(self._match(p, source_name) for p in self.groups[spec])
        if isinstance(spec, list):
            return any(self._match(p, source_name) for p in spec)
        if isinstance(spec, str):
            return self._match(spec, source_name)
        return False

    def filter_peers(self, source_name, candidates):
        """Filter peer list based on ACL rules.

        For each candidate, check if source_name is allowed to see it.
        Returns only allowed peers.
        """
        if source_name is None:
            # No identity provided (e.g. API call without auth) - return all
            return candidates

        allowed = []
        for peer in candidates:
            dest_name = peer.get("name", "")

            for rule in self.rules:
                from_spec = rule.get("from", "*")
                to_spec = rule.get("to", "*")
                action = rule.get("action", "deny")

                if self._peers_in_set(from_spec, source_name) and self._peers_in_set(
                    to_spec, dest_name
                ):
                    if action == "allow":
                        allowed.append(peer)
                    # else: deny - skip this peer
                    break  # first match wins
            # If no rule matches, default is DENY

        return allowed

    def is_allowed(self, source_name, dest_name):
        """Check if source_name can communicate with dest_name."""
        for rule in self.rules:
            from_spec = rule.get("from", "*")
            to_spec = rule.get("to", "*")
            action = rule.get("action", "deny")

            if self._peers_in_set(from_spec, source_name) and self._peers_in_set(
                to_spec, dest_name
            ):
                return action == "allow"
        return False

    def get_rules_summary(self):
        """Return a human-readable summary of ACL rules."""
        summary = []
        for i, rule in enumerate(self.rules):
            frm = rule.get("from", "*")
            to = rule.get("to", "*")
            act = rule.get("action", "deny").upper()
            summary.append(f"  Rule {i+1}: ({frm} -> {to}) {act}")
        return "\n".join(summary)

    def get_rules_data(self):
        """Return structured rule data for the dashboard table."""
        rules = []
        for i, rule in enumerate(self.rules):
            rules.append({
                "idx": i + 1,
                "from": rule.get("from", "*"),
                "to": rule.get("to", "*"),
                "action": rule.get("action", "deny"),
            })
        return rules
