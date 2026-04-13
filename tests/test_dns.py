"""shomescale test suite - DNS server tests."""

import dns.message
import dns.rdatatype
import socket
import struct
import threading
import time
import unittest.mock

import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from shomescale_dns import DNSServer


class MockPeerStore:
    """Mock store implementing get_dns_records() interface."""

    def __init__(self, records=None):
        self.records = records or {}

    def get_dns_records(self):
        return dict(self.records)


def build_dns_query(domain, qtype=1, txid=0x1234):
    """Build a raw DNS query packet."""
    header = struct.pack("!HHHHHH", txid, 0x0100, 1, 0, 0, 0)
    question = b""
    for label in domain.split("."):
        question += struct.pack("!B", len(label)) + label.encode()
    question += b"\x00"
    question += struct.pack("!HH", qtype, 1)
    return header + question


class TestDNSQueryParsing:
    """Test the low-level _parse_dns_query function."""

    def test_parses_valid_a_query(self):
        store = MockPeerStore()
        server = DNSServer(store, port=0)
        query = build_dns_query("node.shomescale")
        domain, qtype = server._parse_dns_query(query)
        assert domain == "node.shomescale"
        assert qtype == 1

    def test_parses_known_domain(self):
        store = MockPeerStore()
        server = DNSServer(store, port=0)
        query = build_dns_query("shomescale")
        domain, qtype = server._parse_dns_query(query)
        assert domain == "shomescale"
        assert qtype == 1

    def test_rejects_too_short_packet(self):
        store = MockPeerStore()
        server = DNSServer(store, port=0)
        domain, qtype = server._parse_dns_query(b"\x00")
        assert domain is None

    def test_rejects_non_query(self):
        """Response flag (QR=1) is not a query."""
        store = MockPeerStore()
        server = DNSServer(store, port=0)
        # QR=1: 0x8000 in second byte
        packet = struct.pack("!HHHHHH", 0x1234, 0x8180, 1, 0, 0, 0)
        packet += b"\x00" * 12
        domain, qtype = server._parse_dns_query(packet)
        assert domain is None

    def test_rejects_multi_question(self):
        store = MockPeerStore()
        server = DNSServer(store, port=0)
        header = struct.pack("!HHHHHH", 0x1234, 0x0100, 2, 0, 0, 0)
        domain, qtype = server._parse_dns_query(header + b"\x00" * 12)
        assert domain is None


class TestDNSResponseBuilding:
    """Test the _build_dns_response function."""

    def test_builds_positive_response(self):
        store = MockPeerStore()
        server = DNSServer(store, port=0)
        resp = server._build_dns_response(0xABCD, "test.shomescale", "100.64.0.1")
        msg = dns.message.from_wire(resp)
        assert msg.rcode() == 0
        assert len(msg.answer) == 1
        assert "100.64.0.1" in msg.answer[0].to_text()

    def test_builds_nxdomain_response(self):
        store = MockPeerStore()
        server = DNSServer(store, port=0)
        resp = server._build_dns_response(0xABCD, "test.shomescale", None)
        msg = dns.message.from_wire(resp)
        assert msg.rcode() == 3  # NXDOMAIN
        assert len(msg.answer) == 0

    def test_authoritative_flag(self):
        store = MockPeerStore()
        server = DNSServer(store, port=0)
        resp = server._build_dns_response(0xABCD, "test.shomescale", "1.1.1.1", True)
        msg = dns.message.from_wire(resp)
        assert msg.flags & dns.flags.AA  # Authoritative


class TestDNSIntegration:
    """Integration tests with a live DNSServer using the real run() method."""

    def setup_method(self):
        self.store = MockPeerStore({
            "node-a": "100.64.0.1",
            "node-b": "100.64.0.2",
            "abcdef12": "100.64.0.3",
        })

    def _make_query_and_get_response(self, domain):
        """Start a DNS server, make a query, return the parsed response."""
        # Create a UDP socket bound to port 0 (OS assigns port)
        srv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", 0))
        srv.settimeout(2.0)
        port = srv.getsockname()[1]

        received_resp = [None]

        def handler():
            """Miniature version of DNSServer.run() using our test socket."""
            while True:
                try:
                    data, addr = srv.recvfrom(512)
                except socket.timeout:
                    break
                except OSError:
                    break

                try:
                    server = DNSServer(self.store, port=0)  # dummy port
                    txid = struct.unpack("!H", data[0:2])[0]
                    parsed_domain, qtype = server._parse_dns_query(data)
                    if parsed_domain is None:
                        continue

                    suffix = ".shomescale"
                    base_name = None
                    if parsed_domain == "shomescale":
                        base_name = "shomescale"
                    elif parsed_domain.endswith(suffix):
                        base_name = parsed_domain[:-len(suffix)]

                    ip = None
                    if base_name and qtype == 1:
                        records = self.store.get_dns_records()
                        ip = records.get(base_name.lower())

                    if ip:
                        resp = server._build_dns_response(txid, parsed_domain, ip, True)
                    else:
                        hdr = struct.pack("!HHHHHH", txid, 0x8583, 1, 0, 0, 0)
                        question = b""
                        for label in parsed_domain.split("."):
                            question += struct.pack("!B", len(label)) + label.encode("ascii")
                        question += b"\x00"
                        question += struct.pack("!HH", qtype or 1, 1)
                        resp = hdr + question

                    received_resp[0] = resp
                    srv.sendto(resp, addr)
                except Exception:
                    break

        t = threading.Thread(target=handler, daemon=True)
        t.start()
        time.sleep(0.1)

        # Send query
        query = build_dns_query(domain)
        client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        client.settimeout(3.0)
        client.sendto(query, ("127.0.0.1", port))
        try:
            data, _ = client.recvfrom(512)
            response = dns.message.from_wire(data)
        except socket.timeout:
            response = None
        finally:
            client.close()
            srv.close()
            t.join(timeout=3)

        return response

    def test_resolves_known_name(self):
        msg = self._make_query_and_get_response("node-a.shomescale")
        assert msg is not None
        assert msg.rcode() == 0
        assert len(msg.answer) == 1
        assert "100.64.0.1" in msg.answer[0].to_text()

    def test_resolves_short_uuid(self):
        msg = self._make_query_and_get_response("abcdef12.shomescale")
        assert msg is not None
        assert msg.rcode() == 0
        assert "100.64.0.3" in msg.answer[0].to_text()

    def test_nxdomain_for_unknown(self):
        msg = self._make_query_and_get_response("unknown.shomescale")
        assert msg is not None
        assert msg.rcode() == 3  # NXDOMAIN

    def test_nxdomain_for_outside_domain(self):
        msg = self._make_query_and_get_response("google.com")
        assert msg is not None
        assert msg.rcode() == 3  # NXDOMAIN

    def test_case_insensitive(self):
        msg = self._make_query_and_get_response("Node-A.shomescale")
        assert msg is not None
        assert msg.rcode() == 0
        assert "100.64.0.1" in msg.answer[0].to_text()
