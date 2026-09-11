"""
LISTENER - the far end of the beacon, so the attack traffic actually completes.

WHY THIS EXISTS
---------------
When src/scenario.py triggers a board, the board's firmware opens a TCP beacon
to 192.168.0.200:4444. If nothing is listening on 4444, that connection is
refused: the board gets a RST, the flow is a two-packet stub, and the capture
shows a failed connection rather than the exfil-shaped conversation the whole
exercise is meant to produce.

So this is the "C2" sink. It is deliberately the dumbest possible one: accept
the connection, read whatever the board sends, print it, keep the socket open
long enough for the exchange to look like a real beacon rather than a stray
SYN. It does not parse, interpret, or act on anything - it only has to be
there and answer, so the beacon connects cleanly and shows up in the pcap.

It has nothing to do with attribution and never touches the answer sheet; it
is pure network plumbing that happens to live next to the thing that uses it.

USAGE
-----
    python -m src.listener                 # listen on 0.0.0.0:4444
    python -m src.listener --port 4444     # same, explicitly
    python -m src.listener --ack pong      # send a reply to each beacon

Run it on the 192.168.0.200 host (the beacon target) before triggering an
attack with src/scenario.py. Stop it with Ctrl+C.
"""

from __future__ import annotations

import argparse
import socket
import sys
import threading
from datetime import datetime

LISTEN_HOST = "0.0.0.0"
LISTEN_PORT = 4444


def _stamp() -> str:
    return datetime.now().strftime("%H:%M:%S")


def handle_beacon(conn: socket.socket, addr, ack: str | None) -> None:
    """
    One beacon connection: print everything it sends until it hangs up.

    Kept trivial on purpose. A beacon may send one burst and wait, or dribble
    a few writes; either way we print each chunk with who it came from, and
    optionally send a short reply so the board sees an answering server rather
    than a silent one.
    """
    peer = "%s:%d" % addr
    print("  [%s] beacon opened from %s" % (_stamp(), peer))
    try:
        if ack:
            conn.sendall(ack.encode("utf-8"))
        while True:
            data = conn.recv(4096)
            if not data:
                break
            shown = data.decode("utf-8", errors="replace").rstrip()
            print("  [%s] %s -> %r (%d bytes)" % (_stamp(), peer, shown, len(data)))
    except OSError as exc:
        print("  [%s] %s error: %s" % (_stamp(), peer, exc))
    finally:
        conn.close()
        print("  [%s] beacon closed from %s" % (_stamp(), peer))


def serve(host: str = LISTEN_HOST, port: int = LISTEN_PORT,
          ack: str | None = None) -> int:
    """Accept beacons forever, one thread each, until Ctrl+C."""
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        server.bind((host, port))
    except OSError as exc:
        print("  cannot listen on %s:%d - %s" % (host, port, exc), file=sys.stderr)
        return 1
    server.listen(8)

    print("\n  listening for beacons on %s:%d  (Ctrl+C to stop)\n" % (host, port))
    try:
        while True:
            conn, addr = server.accept()
            thread = threading.Thread(
                target=handle_beacon, args=(conn, addr, ack), daemon=True
            )
            thread.start()
    except KeyboardInterrupt:
        print("\n  stopped.\n")
        return 0
    finally:
        server.close()


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description="Tiny TCP sink for attack beacons, so they connect and show in the capture."
    )
    parser.add_argument("--host", default=LISTEN_HOST, help="interface to bind (default 0.0.0.0)")
    parser.add_argument("--port", type=int, default=LISTEN_PORT, help="port to listen on (default 4444)")
    parser.add_argument("--ack", default=None,
                        help="optional reply sent to each beacon (default: none)")
    args = parser.parse_args(argv)
    return serve(args.host, args.port, args.ack)


if __name__ == "__main__":
    sys.exit(main())
