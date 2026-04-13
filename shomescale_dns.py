"""shomescale DNS server - minimal A record responder for *.shomescale."""

import logging
import socket
import struct

import shared

logger = logging.getLogger("shomescale-dns")


class DNSServer:
    """Minimal DNS server that resolves A records for *.shomescale."""

    def __init__(self, store, port=shared.DEFAULT_DNS_PORT):
        self.store = store
        self.port = port
        self.running = False

    def _parse_dns_query(self, data):
        if len(data) < 12:
            return None, None
        flags = struct.unpack("!H", data[2:4])[0]
        qr = (flags >> 15) & 1
        if qr != 0:
            return None, None
        qdcount = struct.unpack("!H", data[4:6])[0]
        if qdcount != 1:
            return None, None

        offset = 12
        labels = []
        while offset < len(data):
            length = data[offset]
            if length == 0:
                offset += 1
                break
            labels.append(data[offset + 1 : offset + 1 + length].decode("ascii"))
            offset += 1 + length

        if offset + 4 > len(data):
            return None, None
        qtype = struct.unpack("!H", data[offset : offset + 2])[0]

        domain = ".".join(labels).lower()
        return domain, qtype

    def _build_dns_response(self, txid, domain, ip_address, authoritative=False):
        flags = 0x8180
        if authoritative:
            flags |= 0x0400
        ancount = 1 if ip_address else 0
        header = struct.pack("!HHHHHH", txid, flags, 1, ancount, 0, 0)

        question = b""
        for label in domain.split("."):
            question += struct.pack("!B", len(label)) + label.encode("ascii")
        question += b"\x00"
        question += struct.pack("!HH", 1, 1)

        if not ip_address:
            return header + question

        answer = b"\xc0\x0c"
        answer += struct.pack("!HHIH", 1, 1, 300, 4)
        answer += socket.inet_aton(ip_address)

        return header + question + answer

    def run(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("0.0.0.0", self.port))
        sock.settimeout(1.0)
        self.running = True
        logger.info("DNS server listening on port %d", self.port)

        while self.running:
            try:
                data, addr = sock.recvfrom(512)
            except socket.timeout:
                continue

            try:
                txid = struct.unpack("!H", data[0:2])[0]
                domain, qtype = self._parse_dns_query(data)
                if domain is None:
                    continue

                suffix = "." + shared.DNS_DOMAIN
                base_name = None
                if domain == shared.DNS_DOMAIN:
                    base_name = shared.DNS_DOMAIN
                elif domain.endswith(suffix):
                    base_name = domain[: -len(suffix)]

                ip = None
                if base_name and qtype == 1:
                    records = self.store.get_dns_records()
                    ip = records.get(base_name.lower())
                    if ip:
                        logger.info("DNS resolved: %s -> %s", domain, ip)

                if ip:
                    response = self._build_dns_response(
                        txid, domain, ip, authoritative=True
                    )
                else:
                    hdr = struct.pack("!HHHHHH", txid, 0x8583, 1, 0, 0, 0)
                    question = b""
                    for label in domain.split("."):
                        question += struct.pack("!B", len(label)) + label.encode(
                            "ascii"
                        )
                    question += b"\x00"
                    question += struct.pack("!HH", qtype or 1, 1)
                    response = hdr + question

                sock.sendto(response, addr)
            except Exception:
                logger.exception("DNS handler error for %s", addr)

        sock.close()

    def stop(self):
        self.running = False
