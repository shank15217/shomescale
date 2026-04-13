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
            self.isolation_pairs = []  # Symmetric group-pair isolations
            return

        try:
            with open(self.acls_file, "r") as f:
                data = json.load(f)
            self.groups = data.get("groups", {})
            self.rules = data.get("rules", [{"from": "*", "to": "*", "action": "allow"}])
            # Parse symmetric isolation pairs (new format)
            self.isolation_pairs = data.get("isolate", [])
            if not self.isolation_pairs:
                # Backward compat: convert deny rules to symmetric isolation pairs
                seen = set()
                for rule in self.rules:
                    if rule.get("action") == "deny":
                        a, b = rule.get("from", "*"), rule.get("to", "*")
                        pair = tuple(sorted([a, b]))
                        if pair not in seen:
                            seen.add(pair)
                            self.isolation_pairs.append({
                                "group_a": a,
                                "group_b": b,
                            })
                # Remove deny rules from the rules list (they're handled by isolation)
                self.rules = [r for r in self.rules if r.get("action") != "deny"]
                if not self.rules:
                    self.rules = [{"from": "*", "to": "*", "action": "allow"}]
        except Exception:
            logger.exception("Failed to load ACLs, using allow-all default")
            self.groups = {}
            self.rules = [{"from": "*", "to": "*", "action": "allow"}]
            self.isolation_pairs = []

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
        Symmetric isolation: if source is in isolation pair with dest,
        neither can see the other.
        Returns only allowed peers.
        """
        if source_name is None:
            # No identity provided (e.g. API call without auth) - return all
            return candidates

        allowed = []
        for peer in candidates:
            dest_name = peer.get("name", "")

            # Check symmetric isolation first
            if self._is_isolated(source_name, dest_name):
                continue

            # Check allow rules
            for rule in self.rules:
                from_spec = rule.get("from", "*")
                to_spec = rule.get("to", "*")
                action = rule.get("action", "allow")

                if self._peers_in_set(from_spec, source_name) and self._peers_in_set(
                    to_spec, dest_name
                ):
                    if action == "allow":
                        allowed.append(peer)
                    break  # first match wins

        return allowed

    def _is_isolated(self, source_name, dest_name):
        """Check if two peers are in a symmetric isolation pair."""
        for iso in self.isolation_pairs:
            a = iso.get("group_a", "*")
            b = iso.get("group_b", "*")
            src_in_a = self._matches_group(a, source_name)
            src_in_b = self._matches_group(b, source_name)
            dst_in_a = self._matches_group(a, dest_name)
            dst_in_b = self._matches_group(b, dest_name)
            # Symmetric: if one is in group_a and the other is in group_b
            if (src_in_a and dst_in_b) or (src_in_b and dst_in_a):
                return True
        return False

    def _matches_group(self, group_name, peer_name):
        """Check if a peer name belongs to a named group."""
        if peer_name is None:
            return False
        if group_name == "*":
            return True
        if group_name in self.groups:
            patterns = self.groups[group_name]
        else:
            patterns = [group_name]
        return any(self._match(p, peer_name) for p in patterns)

    def is_allowed(self, source_name, dest_name):
        """Check if two peers can communicate (symmetric).
        
        WireGuard tunnels are bidirectional - if A can reach B, B can reach A.
        Isolation pairs are checked symmetrically.
        """
        # Check symmetric isolation first
        if self._is_isolated(source_name, dest_name):
            return False

        # Check allow rules
        for rule in self.rules:
            action = rule.get("action", "allow")
            from_spec = rule.get("from", "*")
            to_spec = rule.get("to", "*")
            if self._peers_in_set(from_spec, source_name) and self._peers_in_set(
                to_spec, dest_name
            ):
                return action == "allow"
        return True

    def get_rules_summary(self):
        """Return a human-readable summary of ACL rules."""
        summary = []
        for i, rule in enumerate(self.rules):
            frm = rule.get("from", "*")
            to = rule.get("to", "*")
            act = rule.get("action", "deny").upper()
            summary.append(f"  Rule {i+1}: ({frm} -> {to}) {act}")
        return "\n".join(summary)

    def get_rules_data(self, peers_info=None):
        """Return structured rule data for the dashboard table and topology graph.
        
        Returns a dict with:
          - groups: {name: [members]} with resolved peer names
          - isolations: list of {group_a, group_b, members_a, members_b}
          - legacy_rules: the old-style rules list (compatibility)
        """
        groups = {k: list(v) for k, v in self.groups.items()}
        
        # Resolve group membership with actual peer names
        resolved_groups = {}
        for grp_name, patterns in groups.items():
            resolved = set()
            for pattern in patterns:
                if peers_info:
                    # Expand against actual peer list
                    for p in peers_info:
                        if fnmatch.fnmatch(p, pattern):
                            resolved.add(p)
                else:
                    # Fall back to raw patterns (wildcards stay as-is)
                    if "*" not in pattern and "?" not in pattern:
                        resolved.add(pattern)
                    else:
                        resolved.add(pattern)  # keep wildcard as display
            resolved_groups[grp_name] = sorted(resolved)

        isolations = []
        seen_pairs = set()
        for iso in self.isolation_pairs:
            a, b = iso.get("group_a", "*"), iso.get("group_b", "*")
            pair_key = tuple(sorted([a, b]))
            if pair_key in seen_pairs:
                continue
            seen_pairs.add(pair_key)
            isolations.append({
                "group_a": a,
                "members_a": resolved_groups.get(a, [a]),
                "group_b": b,
                "members_b": resolved_groups.get(b, [b]),
            })
        
        return {
            "groups": resolved_groups,
            "isolations": isolations,
        }
