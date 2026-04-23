"""
packet_logger.py — Packet Logger Application
=============================================
Subscribes to the EventBus and:
  1. Captures packet headers emitted by the SDN Controller
  2. Identifies protocol types (TCP / UDP / ICMP)
  3. Maintains a rotating JSON log file
  4. Displays a live table of captured packets to stdout

All log writes are protected by a threading.Lock so concurrent
socket-server threads can safely append entries.
"""

import json
import os
import threading
import time
from collections import deque
from pathlib import Path
from typing import Deque, Optional

from sdn_controller import PacketHeader, EventBus, IPProto


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
LOG_DIR          = Path("logs")
LOG_FILE         = LOG_DIR / "packet_log.json"
MAX_LOG_ENTRIES  = 10_000      # rotate / trim after this many entries
DISPLAY_ROWS     = 20          # last N packets shown in live table


# ---------------------------------------------------------------------------
# Packet Logger
# ---------------------------------------------------------------------------
class PacketLogger:
    """
    Core logger that subscribes to SDN Controller events, persists them to
    disk, and exposes a thread-safe ring-buffer for the live display.

    Thread safety
    -------------
    _lock  : protects both _ring_buffer and the log file
    """

    def __init__(self, bus: EventBus, log_file: Path = LOG_FILE):
        self._lock        = threading.Lock()
        self._ring_buffer: Deque[PacketHeader] = deque(maxlen=DISPLAY_ROWS)
        self._log_file    = log_file
        self._total       = 0      # cumulative packets logged

        # Protocol counters for summary statistics
        self._proto_counts = {
            "TCP": 0, "UDP": 0, "ICMP": 0, "OTHER": 0
        }

        # Ensure log directory exists
        LOG_DIR.mkdir(exist_ok=True)

        # Truncate existing log on startup
        self._log_file.write_text("[]")

        # Register handler with the event bus
        bus.subscribe(self._on_packet_in)

        print(f"[PacketLogger] Logging to {self._log_file.resolve()}")

    # ------------------------------------------------------------------
    # Event handler (called from SDNController thread)
    # ------------------------------------------------------------------
    def _on_packet_in(self, pkt: PacketHeader) -> None:
        """Handles a packet_in event from the SDN controller."""
        self._identify_protocol(pkt)   # side-effect: update counters

        with self._lock:
            self._ring_buffer.append(pkt)
            self._total += 1
            self._append_to_log(pkt)

    # ------------------------------------------------------------------
    # Protocol identification
    # ------------------------------------------------------------------
    def _identify_protocol(self, pkt: PacketHeader) -> None:
        """
        Classifies the packet's IP protocol and updates counters.
        In a production logger you would also inspect port numbers to
        identify application-layer protocols (HTTP, DNS, SMTP, …).
        """
        name = pkt.protocol_name
        with self._lock:
            if name in self._proto_counts:
                self._proto_counts[name] += 1
            else:
                self._proto_counts["OTHER"] += 1

    # ------------------------------------------------------------------
    # Persistent JSON log (rotation)
    # ------------------------------------------------------------------
    def _append_to_log(self, pkt: PacketHeader) -> None:
        """
        Appends a single packet record to the JSON log.
        Called under self._lock — do NOT acquire lock inside.
        Rotates (trims head) if log exceeds MAX_LOG_ENTRIES.
        """
        record = {
            "timestamp":   pkt.timestamp,
            "time_str":    time.strftime('%Y-%m-%d %H:%M:%S',
                                         time.localtime(pkt.timestamp)),
            "switch_id":   pkt.switch_id,
            "src_mac":     pkt.src_mac,
            "dst_mac":     pkt.dst_mac,
            "eth_type_hex": f"0x{pkt.eth_type:04X}",
            "src_ip":      pkt.src_ip,
            "dst_ip":      pkt.dst_ip,
            "protocol":    pkt.protocol_name,
            "src_port":    pkt.src_port,
            "dst_port":    pkt.dst_port,
            "payload_len": pkt.payload_len,
        }

        try:
            # Read existing entries
            raw = self._log_file.read_text()
            entries = json.loads(raw) if raw.strip() else []

            entries.append(record)

            # Rotate: keep only the last MAX_LOG_ENTRIES entries
            if len(entries) > MAX_LOG_ENTRIES:
                entries = entries[-MAX_LOG_ENTRIES:]

            # Write back atomically using a temp file + rename
            tmp = self._log_file.with_suffix(".tmp")
            tmp.write_text(json.dumps(entries, indent=2))
            tmp.replace(self._log_file)

        except (json.JSONDecodeError, OSError) as exc:
            # Don't crash the event loop — log the error and continue
            print(f"[PacketLogger] Log write error: {exc}")

    # ------------------------------------------------------------------
    # Live display
    # ------------------------------------------------------------------
    def display(self) -> None:
        """Print a formatted snapshot of the latest captured packets."""
        with self._lock:
            recent = list(self._ring_buffer)
            counts = dict(self._proto_counts)
            total  = self._total

        # ANSI clear screen
        print("\033[2J\033[H", end="")

        header = (
            f"{'TIME':>8}  "
            f"{'SW':>4}  "
            f"{'SRC IP':>15}:{'':<5}  "
            f"{'DST IP':>15}:{'':<5}  "
            f"{'PROTO':<5}  "
            f"{'LEN':>5}"
        )
        sep = "-" * len(header)

        print("╔══════════════════════════════════════════════════════════════╗")
        print("║          SDN PACKET LOGGER  –  Live Capture View             ║")
        print("╚══════════════════════════════════════════════════════════════╝")
        print()
        print(f"  Total captured: {total:>6}   "
              f"TCP: {counts['TCP']:>4}  "
              f"UDP: {counts['UDP']:>4}  "
              f"ICMP: {counts['ICMP']:>3}  "
              f"Other: {counts['OTHER']:>3}")
        print()
        print(f"  {'TIME':>8}  {'SW':>3}  {'SRC':>21}  {'DST':>21}  {'PROTO':<5}  {'BYTES':>5}")
        print("  " + "─" * 72)

        for pkt in recent[-DISPLAY_ROWS:]:
            src = f"{pkt.src_ip}:{pkt.src_port}"
            dst = f"{pkt.dst_ip}:{pkt.dst_port}"
            ts  = time.strftime('%H:%M:%S', time.localtime(pkt.timestamp))
            print(
                f"  {ts:>8}  "
                f"{pkt.switch_id:>3}  "
                f"{src:>21}  "
                f"{dst:>21}  "
                f"{pkt.protocol_name:<5}  "
                f"{pkt.payload_len:>5}"
            )

        print()
        print(f"  Log file: {LOG_FILE}  (press Ctrl-C to stop)")

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    def get_recent(self, n: int = 10):
        """Return the last n captured PacketHeader objects."""
        with self._lock:
            return list(self._ring_buffer)[-n:]

    def stats(self) -> dict:
        """Return current statistics snapshot."""
        with self._lock:
            return {
                "total": self._total,
                "proto_counts": dict(self._proto_counts),
            }
