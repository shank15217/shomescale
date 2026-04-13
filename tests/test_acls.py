"""shomescale test suite - ACL engine tests."""

import sys, os
import unittest.mock
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from shomescale_store_acls import AclEngine


class TestAclBasic:
    def test_default_allow_all(self, tmp_path):
        engine = AclEngine(str(tmp_path / "nonexistent.json"))
        assert engine.rules == [{"from": "*", "to": "*", "action": "allow"}]
        assert engine._matches_group("*", "any-node") is True

    def test_load_valid_config(self, tmp_path):
        config = tmp_path / "acls.json"
        config.write_text('{"groups": {"test": ["node-a"]}, "rules": []}')
        engine = AclEngine(str(config))
        assert engine.groups == {"test": ["node-a"]}
        assert engine.isolation_pairs == []


class TestAclIsolation:
    def test_isolation_blocks_both_directions(self, tmp_path):
        engine = AclEngine(str(tmp_path / "acls.json"))
        engine.groups = {"groupA": ["node-a"], "groupB": ["node-b"]}
        engine.isolation_pairs = [{"group_a": "groupA", "group_b": "groupB"}]

        assert engine._is_isolated("node-a", "node-b") is True
        assert engine._is_isolated("node-b", "node-a") is True

    def test_same_group_not_isolated(self, tmp_path):
        engine = AclEngine(str(tmp_path / "acls.json"))
        engine.groups = {"groupA": ["node-a", "node-b"]}
        engine.isolation_pairs = [{"group_a": "groupA", "group_b": "groupB"}]

        assert engine._is_isolated("node-a", "node-b") is False
        assert engine._is_isolated("node-b", "node-a") is False

    def test_isolation_with_multiple_groups(self, tmp_path):
        engine = AclEngine(str(tmp_path / "acls.json"))
        engine.groups = {
            "isolated1": ["node-1a", "node-1b"],
            "isolated2": ["node-2a"],
            "isolated3": ["node-3a"],
        }
        engine.isolation_pairs = [
            {"group_a": "isolated1", "group_b": "isolated2"},
            {"group_a": "isolated1", "group_b": "isolated3"},
        ]

        assert engine._is_isolated("node-1a", "node-2a") is True
        assert engine._is_isolated("node-1a", "node-3a") is True
        assert engine._is_isolated("node-2a", "node-3a") is False
        assert engine._is_isolated("node-1a", "node-1b") is False

    def test_filter_peers_removes_isolated(self, tmp_path):
        engine = AclEngine(str(tmp_path / "acls.json"))
        engine.groups = {"isolated1": ["node-a"], "isolated2": ["node-b"]}
        engine.isolation_pairs = [{"group_a": "isolated1", "group_b": "isolated2"}]

        candidates = [
            {"name": "node-x", "uuid": "x"},
            {"name": "node-b", "uuid": "b"},
            {"name": "node-c", "uuid": "c"},
        ]
        allowed = engine.filter_peers("node-a", candidates)
        allowed_names = [p["name"] for p in allowed]
        assert "node-b" not in allowed_names
        assert "node-x" in allowed_names
        assert "node-c" in allowed_names


class TestAclRulesData:
    def test_returns_groups_with_members(self, tmp_path):
        engine = AclEngine(None)
        engine.groups = {"groupA": ["node-a", "node-b"], "groupB": ["node-c"]}
        engine.isolation_pairs = [{"group_a": "groupA", "group_b": "groupB"}]

        peers = ["node-a", "node-b", "node-c"]
        data = engine.get_rules_data(peers)

        assert data["groups"]["groupA"] == ["node-a", "node-b"]
        assert data["groups"]["groupB"] == ["node-c"]
        assert len(data["isolations"]) == 1
        assert data["isolations"][0]["group_a"] == "groupA"
        assert data["isolations"][0]["group_b"] == "groupB"

    def test_no_isolations(self, tmp_path):
        engine = AclEngine(None)
        engine.groups = {}
        engine.isolation_pairs = []
        data = engine.get_rules_data([])
        assert data["groups"] == {}
        assert data["isolations"] == []

    def test_revocation(self, tmp_path):
        """Revocation lives in KeyEngine, not AclEngine."""
        from shomescale_rotation import KeyEngine
        with unittest.mock.patch("shomescale_rotation.generate_keypair",
                                  return_value=("X" * 43 + "=", "Y" * 43 + "=")), \
             unittest.mock.patch("shomescale_rotation.KeyEngine._save"):
            engine = KeyEngine(str(tmp_path / "ks.json"))
            engine.create_keypair("peer-1")
            assert engine.is_revoked("peer-1") is False
            engine.revoke("peer-1")
            assert engine.is_revoked("peer-1") is True
            engine.clear_revocation("peer-1")
            assert engine.is_revoked("peer-1") is False
