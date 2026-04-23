"""
client.py — SSL/TLS Client (TCP) and HMAC UDP Client
=====================================================
Demonstrates:
  1. TCP client that establishes a TLS 1.2+ connection and queries the server
  2. UDP client that signs datagrams with HMAC-SHA256 before sending

Usage (after starting main.py in another terminal):
    python client.py tcp ping
    python client.py tcp recent 5
    python client.py tcp stats
    python client.py udp ping
    python client.py udp stats
"""

import hashlib
import hmac
import json
import socket
import ssl
import sys
import time
from pathlib import Path

# ---------------------------------------------------------------------------
# Configuration — must match secure_server.py
# ---------------------------------------------------------------------------
SERVER_HOST  = "127.0.0.1"
TCP_PORT     = 9443
UDP_PORT     = 9444
CERT_FILE    = Path("certs/server.crt")    # server's self-signed cert (for verification)
UDP_SECRET   = b"jackfruit-sdn-shared-secret"
BUFFER_SIZE  = 65535
TIMEOUT      = 5.0


# ---------------------------------------------------------------------------
# HMAC helpers (duplicated from server to keep client self-contained)
# ---------------------------------------------------------------------------
def _sign(payload: bytes) -> bytes:
    return hmac.new(UDP_SECRET, payload, hashlib.sha256).digest()


def _verify(payload: bytes, tag: bytes) -> bool:
    return hmac.compare_digest(_sign(payload), tag)


# ---------------------------------------------------------------------------
# TCP Client
# ---------------------------------------------------------------------------
class TCPClient:
    """
    TLS-wrapped TCP client.
    Creates a fresh connection per command (connection-per-request model).
    For a persistent client extend with a reconnect loop.
    """

    def __init__(self, host: str = SERVER_HOST, port: int = TCP_PORT):
        self.host = host
        self.port = port

    def _build_ssl_context(self) -> ssl.SSLContext:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2

        if CERT_FILE.exists():
            # Load the server's self-signed cert as the trusted CA
            ctx.load_verify_locations(cafile=CERT_FILE)
            ctx.verify_mode  = ssl.CERT_REQUIRED
            ctx.check_hostname = False      # self-signed cert has no DNS SAN
        else:
            # Dev fallback: no certificate verification
            print("[Client] ⚠  No cert file — skipping TLS verification (insecure!)")
            ctx.check_hostname = False
            ctx.verify_mode    = ssl.CERT_NONE
        return ctx

    def send(self, command: str) -> dict:
        """
        Open a TLS connection, send command, receive one JSON response, close.

        Parameters
        ----------
        command : e.g. "PING", "GET_RECENT 5", "GET_STATS"

        Returns
        -------
        Parsed JSON response dict
        """
        ctx = self._build_ssl_context()
        raw = socket.create_connection((self.host, self.port), timeout=TIMEOUT)

        try:
            conn = ctx.wrap_socket(raw, server_hostname=self.host)
        except ssl.SSLError as exc:
            raw.close()
            raise ConnectionError(f"TLS handshake failed: {exc}") from exc

        try:
            # Send command as a newline-terminated line
            conn.settimeout(TIMEOUT)
            conn.sendall((command + "\n").encode("utf-8"))

            # Read until newline
            buf = b""
            while b"\n" not in buf:
                chunk = conn.recv(BUFFER_SIZE)
                if not chunk:
                    break
                buf += chunk

            line = buf.split(b"\n")[0]
            return json.loads(line.decode("utf-8"))
        finally:
            try:
                conn.shutdown(socket.SHUT_RDWR)
                conn.close()
            except OSError:
                pass


# ---------------------------------------------------------------------------
# UDP Client
# ---------------------------------------------------------------------------
class UDPClient:
    """
    HMAC-authenticated UDP client.
    Wire format (send):   [32-byte HMAC tag][JSON payload]
    Wire format (recv):   [32-byte HMAC tag][JSON payload]
    """

    def __init__(self, host: str = SERVER_HOST, port: int = UDP_PORT):
        self.host = host
        self.port = port

    def send(self, cmd: str) -> dict:
        """
        Send a signed UDP command and wait for a signed response.

        Parameters
        ----------
        cmd : "PING" or "GET_STATS"
        """
        payload = json.dumps({"cmd": cmd}).encode("utf-8")
        packet  = _sign(payload) + payload

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(TIMEOUT)
        try:
            sock.sendto(packet, (self.host, self.port))
            data, _ = sock.recvfrom(BUFFER_SIZE)
        except socket.timeout:
            raise TimeoutError(f"UDP timeout waiting for response from {self.host}:{self.port}")
        finally:
            sock.close()

        HMAC_LEN = 32
        if len(data) < HMAC_LEN + 1:
            raise ValueError("Response too short")

        tag, resp_payload = data[:HMAC_LEN], data[HMAC_LEN:]
        if not _verify(resp_payload, tag):
            raise ValueError("Server response HMAC verification failed!")

        return json.loads(resp_payload.decode("utf-8"))


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------
def _pretty(data: dict) -> None:
    print(json.dumps(data, indent=2))


def main():
    if len(sys.argv) < 3:
        print("Usage: python client.py <tcp|udp> <ping|recent [n]|stats>")
        sys.exit(1)

    transport = sys.argv[1].lower()
    cmd_parts = sys.argv[2:]
    command   = " ".join(cmd_parts).upper()

    t0 = time.perf_counter()

    try:
        if transport == "tcp":
            client = TCPClient()
            result = client.send(command)
        elif transport == "udp":
            client = UDPClient()
            result = client.send(cmd_parts[0])
        else:
            print(f"Unknown transport: {transport}")
            sys.exit(1)

    except (ConnectionError, TimeoutError, ValueError) as exc:
        print(f"[Client] Error: {exc}")
        sys.exit(1)

    elapsed_ms = (time.perf_counter() - t0) * 1000
    _pretty(result)
    print(f"\n[RTT: {elapsed_ms:.1f} ms]")


if __name__ == "__main__":
    main()
