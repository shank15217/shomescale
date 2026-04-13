"""shomescale protocol: length-prefixed JSON framing over TCP.

Both server and client use this same module for encoding/decoding.
"""

import json


def send_json(sock, obj):
    """Send a JSON object with 4-byte big-endian length-prefixed framing."""
    payload = json.dumps(obj).encode("utf-8")
    header = len(payload).to_bytes(4, byteorder="big", signed=False)
    sock.sendall(header + payload)


def recv_json(sock):
    """Read a complete JSON message from the socket.

    Protocol: 4-byte big-endian length prefix + UTF-8 JSON body.
    Blocks until the full message is received or connection closes.
    """
    header = b""
    while len(header) < 4:
        chunk = sock.recv(4 - len(header))
        if not chunk:
            raise ConnectionError("Connection closed while reading length prefix")
        header += chunk

    body_length = int.from_bytes(header, byteorder="big", signed=False)
    if body_length > 10 * 1024 * 1024:  # 10 MB limit
        raise ValueError(f"Message too large: {body_length} bytes")

    body = b""
    while len(body) < body_length:
        chunk = sock.recv(min(body_length - len(body), 4096))
        if not chunk:
            raise ConnectionError("Connection closed while reading message body")
        body += chunk

    return json.loads(body.decode("utf-8"))
