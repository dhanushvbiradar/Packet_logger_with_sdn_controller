"""
main.py — Application Entry Point
==================================
Wires together:
  SDNController  →  EventBus  →  PacketLogger  →  SecureServer
                                               ↘  Live Display (timer)

Run with:
    python main.py

Options (environment variables):
    SDN_RATE=2.0      packets per second from controller (default 1.5)
    SDN_DISPLAY=1     show live packet table (default 1)
"""

import os
import signal
import sys
import threading
import time

from sdn_controller  import SDNController, EventBus
from packet_logger   import PacketLogger
from secure_server   import SecureServer


# ---------------------------------------------------------------------------
# Configuration from environment
# ---------------------------------------------------------------------------
PKT_RATE    = float(os.environ.get("SDN_RATE", "1.5"))
SHOW_DISPLAY = os.environ.get("SDN_DISPLAY", "1") != "0"
REFRESH_SEC  = 2.0   # display refresh interval


# ---------------------------------------------------------------------------
# Graceful shutdown handler
# ---------------------------------------------------------------------------
_stop_event = threading.Event()

def _shutdown(signum, frame):
    print("\n\n[Main] Shutting down (signal received)…")
    _stop_event.set()

signal.signal(signal.SIGINT,  _shutdown)
signal.signal(signal.SIGTERM, _shutdown)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    print("=" * 65)
    print("  SDN Packet Logger — Jackfruit Mini Project")
    print("=" * 65)

    # 1. Create the central event bus
    bus = EventBus()

    # 2. Start the packet logger (subscribes to the bus)
    logger = PacketLogger(bus)

    # 3. Start the secure server (TCP TLS + UDP HMAC)
    server = SecureServer(logger)
    server.start()

    # 4. Start the SDN controller (publishes packet_in events)
    controller = SDNController(bus, rate=PKT_RATE)
    controller.start()

    # 5. Live display loop
    if SHOW_DISPLAY:
        print(f"[Main] Live display enabled (refreshes every {REFRESH_SEC}s)")
        time.sleep(1.0)   # let a few packets accumulate first
        while not _stop_event.is_set():
            try:
                logger.display()
            except Exception as exc:
                print(f"[Display] Error: {exc}")
            _stop_event.wait(timeout=REFRESH_SEC)
    else:
        print("[Main] Running without display — query via client.py")
        _stop_event.wait()

    # 6. Graceful shutdown sequence
    controller.stop()
    server.stop()
    print("[Main] All done. Log saved to logs/packet_log.json")


if __name__ == "__main__":
    main()
