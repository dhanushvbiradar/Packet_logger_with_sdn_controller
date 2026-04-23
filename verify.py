"""
verify.py — Automated Verification Script
==========================================
Runs a suite of checks against the running SecureServer to confirm:
  1. TCP + TLS handshake succeeds
  2. PING command returns PONG
  3. GET_STATS returns valid protocol counts
  4. GET_RECENT returns packet records
  5. UDP PING with correct HMAC succeeds
  6. UDP packet with wrong HMAC is rejected (expected: no/wrong response)

Usage:
    # In terminal 1: python main.py
    # In terminal 2: python verify.py

Exit codes:
    0  — all checks passed
    1  — one or more checks failed
"""

import hashlib
import hmac
import json
import socket
import ssl
import sys
import time
from pathlib import Path

SERVER_HOST  = "127.0.0.1"
TCP_PORT     = 9443
UDP_PORT     = 9444
CERT_FILE    = Path("certs/server.crt")
UDP_SECRET   = b"jackfruit-sdn-shared-secret"
TIMEOUT      = 5.0
BUFFER_SIZE  = 65535

PASS = "✓ PASS"
FAIL = "✗ FAIL"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _sign(payload: bytes) -> bytes:
    return hmac.new(UDP_SECRET, payload, hashlib.sha256).digest()


def _tls_context() -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    if CERT_FILE.exists():
        ctx.load_verify_locations(cafile=CERT_FILE)
    ctx.check_hostname = False
    ctx.verify_mode    = ssl.CERT_REQUIRED if CERT_FILE.exists() else ssl.CERT_NONE
    return ctx


def tcp_send(command: str) -> dict:
    ctx = _tls_context()
    raw = socket.create_connection((SERVER_HOST, TCP_PORT), timeout=TIMEOUT)
    conn = ctx.wrap_socket(raw, server_hostname=SERVER_HOST)
    conn.settimeout(TIMEOUT)
    conn.sendall((command + "\n").encode())
    buf = b""
    while b"\n" not in buf:
        chunk = conn.recv(BUFFER_SIZE)
        if not chunk:
            break
        buf += chunk
    conn.close()
    return json.loads(buf.split(b"\n")[0])


def udp_send(cmd: str, corrupt: bool = False) -> bytes:
    payload = json.dumps({"cmd": cmd}).encode()
    tag     = _sign(payload)
    if corrupt:
        tag = bytes([b ^ 0xFF for b in tag])   # flip all bits to corrupt HMAC
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(TIMEOUT)
    sock.sendto(tag + payload, (SERVER_HOST, UDP_PORT))
    try:
        data, _ = sock.recvfrom(BUFFER_SIZE)
        return data
    except socket.timeout:
        return b""
    finally:
        sock.close()


# ---------------------------------------------------------------------------
# Test cases
# ---------------------------------------------------------------------------
results = []

def check(name: str, passed: bool, detail: str = "") -> None:
    status = PASS if passed else FAIL
    print(f"  {status}  {name}")
    if detail:
        print(f"         {detail}")
    results.append(passed)


print()
print("=" * 55)
print("  SDN Packet Logger — Verification Suite")
print("=" * 55)
print()

# --- 1: TCP TLS handshake + PING ---
try:
    r = tcp_send("PING")
    check("TCP TLS handshake + PING", r.get("result") == "PONG",
          f"response={r}")
except Exception as exc:
    check("TCP TLS handshake + PING", False, str(exc))

# --- 2: GET_STATS ---
try:
    r = tcp_send("GET_STATS")
    stats = r.get("result", {})
    ok = (isinstance(stats.get("total"), int) and
          "proto_counts" in stats)
    check("TCP GET_STATS structure", ok,
          f"total={stats.get('total')}, protos={list(stats.get('proto_counts', {}).keys())}")
except Exception as exc:
    check("TCP GET_STATS structure", False, str(exc))

# --- 3: GET_RECENT ---
try:
    r = tcp_send("GET_RECENT 3")
    records = r.get("result", [])
    ok = isinstance(records, list)
    check("TCP GET_RECENT returns list", ok,
          f"got {len(records)} record(s)")
    if ok and records:
        first = records[0]
        has_fields = all(k in first for k in ["src", "dst", "proto", "bytes"])
        check("  Packet record has expected fields", has_fields,
              f"keys={list(first.keys())}")
except Exception as exc:
    check("TCP GET_RECENT returns list", False, str(exc))

# --- 4: Unknown TCP command returns error ---
try:
    r = tcp_send("FOOBAR")
    check("TCP unknown command returns error key", "error" in r,
          f"response={r}")
except Exception as exc:
    check("TCP unknown command returns error key", False, str(exc))

# --- 5: UDP PING with valid HMAC ---
try:
    data = udp_send("PING")
    HMAC_LEN = 32
    if len(data) >= HMAC_LEN + 1:
        tag, payload = data[:HMAC_LEN], data[HMAC_LEN:]
        valid_mac = hmac.compare_digest(_sign(payload), tag)
        resp = json.loads(payload)
        ok   = valid_mac and resp.get("result") == "PONG"
    else:
        ok = False
    check("UDP PING with valid HMAC", ok,
          f"response size={len(data)} bytes")
except Exception as exc:
    check("UDP PING with valid HMAC", False, str(exc))

# --- 6: UDP with corrupted HMAC is silently dropped ---
try:
    data = udp_send("PING", corrupt=True)
    # Server should NOT reply (or reply with error)
    # We expect empty bytes (timeout) — no response is the correct behaviour
    check("UDP with corrupted HMAC is rejected (no response)",
          data == b"",
          f"server sent {len(data)} bytes (expected 0)")
except Exception as exc:
    check("UDP with corrupted HMAC is rejected", False, str(exc))

# --- Summary ---
print()
print("=" * 55)
passed = sum(results)
total  = len(results)
print(f"  Results: {passed}/{total} checks passed")
print("=" * 55)
print()

sys.exit(0 if passed == total else 1)
