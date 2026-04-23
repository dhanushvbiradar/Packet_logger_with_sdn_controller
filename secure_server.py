"""
secure_server.py — SSL/TLS Secure Server (TCP + UDP)
=====================================================
Implements the server side of the networked application:

  TCP path  : Wraps each accepted socket in ssl.SSLContext for encrypted,
              authenticated communication.  A new thread handles each client
              so the server supports multiple concurrent connections.

  UDP path  : A separate thread receives UDP datagrams.  While TLS is not
              natively available for UDP in Python's ssl module without DTLS
              support, we implement an application-layer HMAC-SHA256
              authentication to protect message integrity.

  Protocol  : Custom line-based text protocol over both transports.
              Commands:
                GET_RECENT [n]  — return last n log entries as JSON
                GET_STATS       — return protocol statistics as JSON
                PING            — returns PONG (liveness check)

Security design
---------------
  • TLS 1.2 / 1.3 enforced; SSLv2/3 disabled
  • Server certificate checked by client (self-signed for demo)
  • Cipher suite restricted to ECDHE + AES-GCM / ChaCha20
  • UDP integrity via HMAC-SHA256 shared secret
  • Timeouts on every socket operation to prevent resource exhaustion
"""

import hashlib
import hmac
import json
import socket
import ssl
import struct
import threading
import time
from pathlib import Path
from typing import Optional

from packet_logger import PacketLogger

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
TCP_HOST      = "0.0.0.0"
TCP_PORT      = 9443        # TLS-wrapped TCP
UDP_HOST      = "0.0.0.0"
UDP_PORT      = 9444        # HMAC-authenticated UDP
BUFFER_SIZE   = 4096
SOCKET_TIMEOUT = 10.0       # seconds; prevents slow-loris attacks
MAX_CLIENTS   = 50

CERT_FILE     = Path("certs/server.crt")
KEY_FILE      = Path("certs/server.key")
UDP_SECRET    = b"jackfruit-sdn-shared-secret"   # rotate in production!


# ---------------------------------------------------------------------------
# Helper: compute / verify UDP HMAC tag
# ---------------------------------------------------------------------------
def _hmac_sign(payload: bytes) -> bytes:
    return hmac.new(UDP_SECRET, payload, hashlib.sha256).digest()


def _hmac_verify(payload: bytes, tag: bytes) -> bool:
    expected = _hmac_sign(payload)
    return hmac.compare_digest(expected, tag)  # constant-time compare


# ---------------------------------------------------------------------------
# TCP Client Handler (runs in its own thread per accepted connection)
# ---------------------------------------------------------------------------
class TCPClientHandler(threading.Thread):
    """
    Handles one TLS-wrapped TCP connection.

    Protocol framing
    ----------------
    Each message is a UTF-8 line terminated by \\n.
    The server responds with a JSON line terminated by \\n.
    """

    def __init__(self, conn: ssl.SSLSocket, addr, logger: PacketLogger):
        super().__init__(daemon=True, name=f"TCP-{addr[0]}:{addr[1]}")
        self.conn   = conn
        self.addr   = addr
        self.logger = logger

    def run(self) -> None:
        client_str = f"{self.addr[0]}:{self.addr[1]}"
        print(f"[TCP] ✓ Connected  {client_str}  (TLS peer cert present: "
              f"{self.conn.getpeercert() is not None})")
        try:
            self.conn.settimeout(SOCKET_TIMEOUT)
            buf = b""
            while True:
                chunk = self.conn.recv(BUFFER_SIZE)
                if not chunk:
                    break                              # client closed connection
                buf += chunk
                while b"\n" in buf:
                    line, buf = buf.split(b"\n", 1)
                    response  = self._handle_command(line.decode("utf-8").strip())
                    # Send response as a newline-terminated JSON line
                    self.conn.sendall((response + "\n").encode("utf-8"))

        except ssl.SSLError as exc:
            print(f"[TCP] SSL error from {client_str}: {exc}")
        except (ConnectionResetError, BrokenPipeError, TimeoutError) as exc:
            print(f"[TCP] Connection error {client_str}: {exc}")
        except Exception as exc:
            print(f"[TCP] Unexpected error {client_str}: {exc}")
        finally:
            try:
                self.conn.shutdown(socket.SHUT_RDWR)
                self.conn.close()
            except OSError:
                pass
            print(f"[TCP] Disconnected {client_str}")

    def _handle_command(self, cmd: str) -> str:
        """Parse a command string and return a JSON-serialisable response."""
        parts = cmd.split()
        if not parts:
            return json.dumps({"error": "empty command"})

        verb = parts[0].upper()

        if verb == "PING":
            return json.dumps({"result": "PONG", "ts": time.time()})

        elif verb == "GET_RECENT":
            n = int(parts[1]) if len(parts) > 1 else 10
            n = max(1, min(n, 100))   # clamp to [1, 100]
            pkts = self.logger.get_recent(n)
            data = [
                {
                    "time": time.strftime('%H:%M:%S', time.localtime(p.timestamp)),
                    "switch": p.switch_id,
                    "src": f"{p.src_ip}:{p.src_port}",
                    "dst": f"{p.dst_ip}:{p.dst_port}",
                    "proto": p.protocol_name,
                    "bytes": p.payload_len,
                }
                for p in pkts
            ]
            return json.dumps({"result": data, "count": len(data)})

        elif verb == "GET_STATS":
            return json.dumps({"result": self.logger.stats()})

        else:
            return json.dumps({"error": f"unknown command: {verb}"})


# ---------------------------------------------------------------------------
# Secure Server (TCP + UDP)
# ---------------------------------------------------------------------------
class SecureServer:
    """
    Manages the TCP (TLS) listener and UDP listener in separate threads.
    Call .start() to launch both, .stop() to shut down gracefully.
    """

    def __init__(self, logger: PacketLogger):
        self.logger   = logger
        self._threads = []
        self._stop    = threading.Event()

    # ------------------------------------------------------------------
    # TLS context
    # ------------------------------------------------------------------
    def _build_ssl_context(self) -> ssl.SSLContext:
        """
        Build a server-side SSLContext:
          - TLS 1.2 minimum (disables SSLv2, SSLv3, TLS 1.0, TLS 1.1)
          - OP_NO_COMPRESSION to prevent CRIME/BEAST
          - HIGH cipher suite string (ECDHE + AESGCM preferred)
          - Client certificate *optional* (set CERT_REQUIRED to enforce mTLS)
        """
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.options        |= ssl.OP_NO_COMPRESSION
        ctx.options        |= ssl.OP_SINGLE_DH_USE
        ctx.options        |= ssl.OP_SINGLE_ECDH_USE

        # Restrict to strong cipher suites (ECDHE for forward secrecy)
        ctx.set_ciphers(
            "ECDHE+AESGCM:ECDHE+CHACHA20:!aNULL:!eNULL:!EXPORT:!RC4:!3DES"
        )

        # Load server certificate and private key
        if not CERT_FILE.exists() or not KEY_FILE.exists():
            print("[SecureServer] ⚠  No TLS certs found — run cert_gen.sh first")
            print("               Falling back to plain TCP (dev mode only!)")
            return None

        ctx.load_cert_chain(certfile=CERT_FILE, keyfile=KEY_FILE)
        ctx.verify_mode = ssl.CERT_NONE    # no client cert required (change for mTLS)
        return ctx

    # ------------------------------------------------------------------
    # TCP listener thread
    # ------------------------------------------------------------------
    def _tcp_listener(self) -> None:
        ctx = self._build_ssl_context()
        raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # SO_REUSEADDR avoids TIME_WAIT blocking re-starts
        raw.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        raw.bind((TCP_HOST, TCP_PORT))
        raw.listen(MAX_CLIENTS)
        raw.settimeout(1.0)   # allows clean shutdown check

        if ctx:
            srv_sock = ctx.wrap_socket(raw, server_side=True)
            print(f"[TCP] Listening on {TCP_HOST}:{TCP_PORT} (TLS 1.2+)")
        else:
            srv_sock = raw
            print(f"[TCP] Listening on {TCP_HOST}:{TCP_PORT} (plain — no cert)")

        try:
            while not self._stop.is_set():
                try:
                    conn, addr = srv_sock.accept()
                except socket.timeout:
                    continue                   # loop back to check stop flag
                except ssl.SSLError as exc:
                    print(f"[TCP] Handshake failed: {exc}")
                    continue
                handler = TCPClientHandler(conn, addr, self.logger)
                handler.start()
        finally:
            srv_sock.close()
            print("[TCP] Listener closed")

    # ------------------------------------------------------------------
    # UDP listener thread
    # ------------------------------------------------------------------
    def _udp_listener(self) -> None:
        """
        Receive UDP datagrams.

        Wire format:
            [32 bytes HMAC-SHA256 tag] [payload bytes (UTF-8 JSON)]

        Any datagram that fails HMAC verification is silently dropped to
        avoid information leakage to the attacker.
        """
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((UDP_HOST, UDP_PORT))
        sock.settimeout(1.0)

        HMAC_LEN = 32   # SHA-256 digest is 32 bytes

        print(f"[UDP] Listening on {UDP_HOST}:{UDP_PORT} (HMAC-SHA256 auth)")

        while not self._stop.is_set():
            try:
                data, addr = sock.recvfrom(BUFFER_SIZE)
            except socket.timeout:
                continue
            except OSError:
                break

            # --- Minimum length check ---
            if len(data) < HMAC_LEN + 1:
                print(f"[UDP] Dropped short datagram from {addr}")
                continue

            tag     = data[:HMAC_LEN]
            payload = data[HMAC_LEN:]

            # --- HMAC verification (constant-time) ---
            if not _hmac_verify(payload, tag):
                print(f"[UDP] ⚠  HMAC mismatch from {addr} — dropped")
                continue

            try:
                msg = json.loads(payload.decode("utf-8"))
                cmd = msg.get("cmd", "").upper()
            except (json.JSONDecodeError, UnicodeDecodeError) as exc:
                print(f"[UDP] Bad payload from {addr}: {exc}")
                continue

            # --- Dispatch command ---
            if cmd == "PING":
                response = {"result": "PONG", "ts": time.time()}
            elif cmd == "GET_STATS":
                response = {"result": self.logger.stats()}
            else:
                response = {"error": f"unknown cmd: {cmd}"}

            # Sign and send response
            resp_bytes = json.dumps(response).encode("utf-8")
            sock.sendto(_hmac_sign(resp_bytes) + resp_bytes, addr)

        sock.close()
        print("[UDP] Listener closed")

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------
    def start(self) -> None:
        tcp_t = threading.Thread(target=self._tcp_listener, daemon=True, name="TCP-Listener")
        udp_t = threading.Thread(target=self._udp_listener, daemon=True, name="UDP-Listener")
        self._threads = [tcp_t, udp_t]
        tcp_t.start()
        udp_t.start()
        print("[SecureServer] TCP + UDP listeners started")

    def stop(self) -> None:
        self._stop.set()
        for t in self._threads:
            t.join(timeout=3)
        print("[SecureServer] Stopped")
