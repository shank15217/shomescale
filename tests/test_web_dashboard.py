"""shomescale test suite - web dashboard tests."""

import json
import socket
import threading
import time
import unittest.mock

import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import shared
from shomescale_web import DASHBOARD_HTML, DashboardHandler
from http.server import HTTPServer


class MockPeersStore:
    """Mock store for dashboard API testing."""

    def __init__(self):
        self.start_time = time.time()
        self.peers_data = {
            "uuid-1": {
                "name": "node-a", "uuid": "uuid-1", "internal_ip": "100.64.0.1",
                "pubkey": "AAAA", "endpoint": "1.1.1.1:51820", "online": True,
                "last_hello": time.time() - 10, "time_since_hello": 10,
                "key_generation": 1,
            },
            "uuid-2": {
                "name": "node-b", "uuid": "uuid-2", "internal_ip": "100.64.0.2",
                "pubkey": "BBBB", "endpoint": "2.2.2.2:51820", "online": False,
                "last_hello": time.time() - 120, "time_since_hello": 120,
                "key_generation": 1,
            }
        }
        self.acls_data = {
            "groups": {"group-a": ["node-a"]},
            "isolations": [],
        }
        self.topology_edges = [
            {"from": "uuid-1", "to": "uuid-2", "allowed": True},
            {"from": "uuid-2", "to": "uuid-1", "allowed": True},
        ]

    def get_status(self):
        return {
            "uptime": time.time() - self.start_time,
            "total_peers": len(self.peers_data),
            "online": sum(1 for p in self.peers_data.values() if p["online"]),
            "offline": sum(1 for p in self.peers_data.values() if not p["online"]),
            "peers": list(self.peers_data.values()),
        }

    def get_topology(self):
        return {
            "nodes": [
                {"_k": "uuid-1", "name": "node-a", "uuid": "uuid-1",
                 "internal_ip": "100.64.0.1", "online": True},
                {"_k": "uuid-2", "name": "node-b", "uuid": "uuid-2",
                 "internal_ip": "100.64.0.2", "online": False},
            ],
            "edges": self.topology_edges,
            "rules": self.acls_data,
        }


class TestDashboardAPI:
    """Tests for JSON API endpoints using a real HTTP server + mock store."""

    def setup_method(self):
        self.store = MockPeersStore()
        self.server = None
        self.port = None

    def _start_server(self):
        """Start a real HTTP server bound to a random port."""
        class Handler(DashboardHandler):
            pass  # no need to override, store already set
        self.server = HTTPServer(("127.0.0.1", 0), Handler)
        self.server.RequestHandlerClass.store = self.store
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        time.sleep(0.2)

    def teardown_method(self):
        if self.server:
            self.server.shutdown()
            self.server.server_close()

    def _get_json(self, path):
        """Make an HTTP GET request and parse JSON response."""
        import urllib.request
        url = f"http://127.0.0.1:{self.port}{path}"
        req = urllib.request.Request(url)
        with urllib.request.urlopen(req, timeout=5) as resp:
            return json.loads(resp.read().decode()), resp.status

    def _get_html(self, path):
        """Make an HTTP GET request and return raw HTML."""
        import urllib.request
        url = f"http://127.0.0.1:{self.port}{path}"
        req = urllib.request.Request(url)
        with urllib.request.urlopen(req, timeout=5) as resp:
            return resp.read().decode(), resp.status

    def test_status_endpoint_returns_json(self):
        self._start_server()
        data, status = self._get_json("/api/status")
        assert status == 200
        assert data["total_peers"] == 2
        assert data["online"] == 1
        assert data["offline"] == 1

    def test_status_endpoint_has_peers(self):
        self._start_server()
        data, _ = self._get_json("/api/status")
        names = [p["name"] for p in data["peers"]]
        assert "node-a" in names
        assert "node-b" in names

    def test_topology_endpoint_returns_json(self):
        self._start_server()
        data, status = self._get_json("/api/topology")
        assert status == 200
        assert len(data["nodes"]) == 2
        assert len(data["edges"]) == 2
        assert "groups" in data["rules"]
        assert "isolations" in data["rules"]

    def test_topology_nodes_have_required_fields(self):
        self._start_server()
        data, _ = self._get_json("/api/topology")
        for node in data["nodes"]:
            assert "name" in node
            assert "uuid" in node
            assert "internal_ip" in node
            assert "online" in node

    def test_dashboard_html_serves(self):
        self._start_server()
        html, status = self._get_html("/")
        assert status == 200
        assert "shomescale" in html
        assert "auto-refreshes" in html

    def test_dashboard_has_tabs(self):
        self._start_server()
        html, _ = self._get_html("/")
        assert "Peer List" in html
        assert "ACL Topology" in html
        assert "ACL Groups" in html

    def test_dashboard_has_stats(self):
        self._start_server()
        html, _ = self._get_html("/")
        assert "Total Peers" in html
        assert "Online" in html
        assert "Uptime" in html
        assert "Isolations" in html

    def test_unknown_path_returns_404(self):
        self._start_server()
        import urllib.error
        try:
            self._get_html("/nonexistent")
            assert False, "Should have raised 404"
        except urllib.error.HTTPError as e:
            assert e.code == 404

    def test_dashboard_has_graph_container(self):
        self._start_server()
        html, _ = self._get_html("/")
        assert "graphSvg" in html
        assert "ACL Topology" in html

    def test_dashboard_has_acl_tab(self):
        self._start_server()
        html, _ = self._get_html("/")
        assert "tab-acls" in html
        assert "aclContent" in html
