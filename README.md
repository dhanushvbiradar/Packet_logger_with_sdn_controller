# SDN Packet Logger — Jackfruit Mini Project

## Overview

A secure networked application that:
- Simulates an **SDN Controller** generating `packet_in` events
- **Captures and logs packet headers** (src/dst IP, MAC, port, protocol)
- **Identifies protocol types** (TCP / UDP / ICMP)
- Exposes a **TLS 1.2+ TCP server** and **HMAC-authenticated UDP server**
- Supports **multiple concurrent clients**
- Maintains a **rotating JSON log** and **live CLI display**

```
sdn_controller.py   SDN Controller (event source)
packet_logger.py    Core logger (subscriber + log writer)
secure_server.py    SSL/TLS TCP + HMAC UDP server
client.py           TCP + UDP client
main.py             Entry point
verify.py           Automated verification suite
cert_gen.sh         TLS certificate generator
logs/               JSON log output directory
certs/              TLS key + certificate
```

---

## Setup

### 1. Prerequisites
```bash
python --version   # Python 3.9+
openssl version    # For cert generation
```

No external pip packages required — uses only Python standard library.

### 2. Generate TLS Certificates
```bash
chmod +x cert_gen.sh
./cert_gen.sh
```
This creates `certs/server.key` and `certs/server.crt`.

---

## Running

### Terminal 1 — Start the Server
```bash
python main.py
```

Optional environment variables:
```bash
SDN_RATE=3.0 python main.py      # 3 packets/second
SDN_DISPLAY=0 python main.py     # no live display (headless mode)
```

You will see a live updating table like:
```
╔═══════════════════════════════════════════════════════════════╗
║          SDN PACKET LOGGER  –  Live Capture View             ║
╚═══════════════════════════════════════════════════════════════╝

  Total captured:     47   TCP:   28  UDP:   17  ICMP:   2  Other:   0

  TIME      SW               SRC                  DST  PROTO  BYTES
  ────────────────────────────────────────────────────────────────────
  14:32:01   2    192.0.2.54:52341    10.0.0.88:443    TCP     1200
  14:32:02   1   203.0.113.7:45901   198.51.100.3:53   UDP       72
  ...
```

### Terminal 2 — Query via Client

**TCP (TLS-encrypted):**
```bash
# Liveness check
python client.py tcp ping

# Get last 5 captured packets
python client.py tcp recent 5

# Get protocol statistics
python client.py tcp stats
```

**UDP (HMAC-signed):**
```bash
python client.py udp ping
python client.py udp stats
```

### Terminal 2 — Run Verification Suite
```bash
python verify.py
```

Expected output:
```
  ✓ PASS  TCP TLS handshake + PING
  ✓ PASS  TCP GET_STATS structure
  ✓ PASS  TCP GET_RECENT returns list
  ✓ PASS    Packet record has expected fields
  ✓ PASS  TCP unknown command returns error key
  ✓ PASS  UDP PING with valid HMAC
  ✓ PASS  UDP with corrupted HMAC is rejected (no response)

  Results: 7/7 checks passed
```

---

## Manual Verification with OpenSSL

```bash
# Verify the TLS handshake directly (no Python needed)
openssl s_client -connect 127.0.0.1:9443 -CAfile certs/server.crt

# After the handshake, type a command:
PING
# Expected: {"result": "PONG", "ts": 1234567890.123}

GET_STATS
# Expected: {"result": {"total": 47, "proto_counts": {...}}}
```

---

## Log File

Packets are appended to `logs/packet_log.json`:
```json
[
  {
    "timestamp": 1700000000.0,
    "time_str": "2024-11-14 10:00:00",
    "switch_id": 2,
    "src_mac": "a4:b8:c2:d1:e0:f9",
    "dst_mac": "11:22:33:44:55:66",
    "eth_type_hex": "0x0800",
    "src_ip": "192.0.2.54",
    "dst_ip": "10.0.0.88",
    "protocol": "TCP",
    "src_port": 52341,
    "dst_port": 443,
    "payload_len": 1200
  }
]
```

---

## Security Features

| Feature | Implementation |
|---|---|
| TLS 1.2 minimum | `ssl.TLSVersion.TLSv1_2` |
| Forward secrecy | ECDHE cipher suites only |
| Compression disabled | `ssl.OP_NO_COMPRESSION` (prevents CRIME) |
| UDP integrity | HMAC-SHA256 on every datagram |
| Constant-time compare | `hmac.compare_digest()` (prevents timing attacks) |
| Socket timeout | 10 s on all socket ops |
| Log rotation | Trims to last 10,000 entries |
| Thread safety | `threading.Lock` on all shared state |

---

## Architecture — Component Flow

```
SDNController (thread)
   │  packet_in events (PacketHeader)
   ▼
EventBus.publish()
   │
   ├──▶ PacketLogger._on_packet_in()
   │        ├── update proto counters
   │        ├── append to ring buffer (for display)
   │        └── append to logs/packet_log.json
   │
   └──▶ (future subscribers)

SecureServer
   ├── TCP Listener Thread (TLS 1.2+)
   │     └── per-client TCPClientHandler thread
   │           ├── PING → PONG
   │           ├── GET_RECENT n → last n packets (JSON)
   │           └── GET_STATS → protocol counts (JSON)
   └── UDP Listener Thread (HMAC-SHA256)
         ├── verify HMAC tag
         ├── PING → PONG (signed)
         └── GET_STATS → stats (signed)
```
