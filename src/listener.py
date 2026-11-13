"""
LISTENER - the far end of the beacon, so the attack traffic actually completes.

WHY THIS EXISTS
---------------
When src/scenario.py triggers a board, the board's firmware opens a TCP beacon
to 192.168.0.200:4444. If nothing is listening on 4444, that connection is
refused: the board gets a RST, the flow is a two-packet stub, and the capture
shows a failed connection rather than the exfil-shaped conversation the whole
exercise is meant to produce.

So this is the "C2" sink. It is deliberately simple: accept the connection,
read whatever the board sends until it hangs up, print it, and close. It never
replies with commands and never acts on anything - it only has to be there and
answer, so the beacon connects cleanly and shows up in the pcap.

WHAT IT PRINTS (Step 22)
------------------------
Since Step 22 the firmware's beacon carries what a real piece of malware on
that board could steal: the board's id, MAC, IP, the Wi-Fi network NAME (never
the password), the broker address, its MQTT topics, uptime and its last few
sensor readings - as JSON, padded with spaces to exactly 200 bytes, split over
three beacons ("part": "1/3", "2/3", "3/3"). Each beacon is shown as one
readable "attacker received:" block, and the listener keeps a running profile
per board so the demo can show everything the attacker has collected so far.
A beacon from the old firmware (a short header plus "x" padding) or anything
that is not JSON is still shown, as text.

The contents are for people watching the demo. The detector never sees them:
capture.py asks tshark only for addresses, ports, flags, times and packet
sizes (capture.TSHARK_FIELDS) - no payload field at all.

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
import json
import socket
import sys
import threading
from datetime import datetime

LISTEN_HOST = "0.0.0.0"
LISTEN_PORT = 4444


def _stamp() -> str:
    return datetime.now().strftime("%H:%M:%S")


# Readable labels for the beacon's JSON keys, in the order they are shown.
FIELD_LABELS = {
    "dev": "device id",
    "part": "beacon part",
    "n": "beacon number",
    "up": "uptime",
    "mac": "MAC address",
    "ip": "IP address",
    "gw": "gateway (router)",
    "ssid": "Wi-Fi network name",
    "rssi": "signal strength",
    "broker": "MQTT broker",
    "client": "MQTT client id",
    "sub": "subscribed topics",
    "pub": "publishes on",
    "heap": "free memory",
    "readings": "recent readings",
    # the old test firmware's beacon
    "id": "device id",
    "beacon": "beacon number",
    "t": "uptime (s)",
}

# What each board has given away so far: {device id: {key: value}}.
PROFILES: dict = {}
_PROFILE_LOCK = threading.Lock()


def say(text: str) -> None:
    """print(), but never crash on a character the console cannot show."""
    try:
        print(text)
    except UnicodeEncodeError:
        print(text.encode("ascii", "backslashreplace").decode("ascii"))


def _uptime(seconds) -> str:
    try:
        seconds = int(seconds)
    except (TypeError, ValueError):
        return str(seconds)
    hours, rest = divmod(seconds, 3600)
    return "%dh %02dm %02ds (%d s)" % (hours, rest // 60, rest % 60, seconds)


def _hundredths(value) -> str:
    """2452 -> "24.52", -5 -> "-0.05"; anything that is not a whole number is shown as it is."""
    if isinstance(value, bool) or not isinstance(value, int):
        return str(value)
    sign = "-" if value < 0 else ""
    whole, frac = divmod(abs(value), 100)
    return "%s%d.%02d" % (sign, whole, frac)


def _show(key, value) -> str:
    if key == "up":
        return _uptime(value)
    if key == "rssi":
        return "%s dBm" % value
    if key == "heap":
        return "%s bytes" % value
    if key == "sub" and isinstance(value, list):
        return ", ".join(str(v) for v in value)
    if key == "readings" and isinstance(value, list):
        # Each reading is [sequence number, temperature, humidity], the last
        # two in HUNDREDTHS (the firmware keeps them as whole numbers to save
        # beacon space): 2452 means 24.52 C, 5387 means 53.87 %.
        rows = []
        for item in value:
            if isinstance(item, list) and len(item) == 3:
                seq, temp, hum = item
                rows.append("#%s: %s C, %s %%" % (seq, _hundredths(temp), _hundredths(hum)))
            else:
                rows.append(str(item))
        return "; ".join(rows)
    return str(value)


def parse_beacon(data: bytes):
    """The beacon as a dict if it is JSON (padding spaces allowed), else None."""
    try:
        value = json.loads(data.decode("utf-8").strip())
    except (UnicodeDecodeError, ValueError):
        return None
    return value if isinstance(value, dict) else None


def format_beacon(data: bytes, peer: str, when: str | None = None) -> str:
    """
    One beacon as the "attacker received:" block printed by the listener.
    Kept apart from the socket code so it can be tested without a network.
    """
    when = when or _stamp()
    head = "  [%s] attacker received from %s (%d bytes):" % (when, peer, len(data))
    fields = parse_beacon(data)
    if fields is None:
        text = data.decode("utf-8", errors="backslashreplace").strip()
        return head + "\n      (not JSON) %r" % text
    lines = [head]
    pad = fields.pop("pad", None)
    ordered = ([k for k in FIELD_LABELS if k in fields]
               + [k for k in fields if k not in FIELD_LABELS])
    for key in ordered:
        lines.append("      %-20s %s" % (FIELD_LABELS.get(key, key), _show(key, fields[key])))
    if pad is not None:
        lines.append("      %-20s %d bytes of filler (old test firmware)"
                     % ("padding", len(str(pad))))
    return "\n".join(lines)


def remember(fields: dict) -> dict:
    """Add one beacon's fields to its board's profile; returns a copy of the profile."""
    device = str(fields.get("dev") or fields.get("id") or "unknown")
    with _PROFILE_LOCK:
        profile = PROFILES.setdefault(device, {})
        profile.update({k: v for k, v in fields.items()
                        if k not in ("part", "n", "pad", "beacon")})
        return dict(profile)


def handle_beacon(conn: socket.socket, addr, ack: str | None) -> None:
    """
    One beacon connection: collect everything it sends until it hangs up,
    then print it as one block. The board writes its 200 bytes in one go and
    closes, but TCP may still deliver them in pieces, so they are joined first.
    """
    peer = "%s:%d" % addr
    chunks = []
    try:
        if ack:
            conn.sendall(ack.encode("utf-8"))
        while True:
            data = conn.recv(4096)
            if not data:
                break
            chunks.append(data)
    except OSError as exc:
        print("  [%s] %s error: %s" % (_stamp(), peer, exc))
    finally:
        conn.close()
    data = b"".join(chunks)
    if not data:
        print("  [%s] %s connected and sent nothing" % (_stamp(), peer))
        return
    say(format_beacon(data, peer))
    fields = parse_beacon(data)
    if fields and fields.get("part"):
        profile = remember(fields)
        say("      -> attacker now holds %d facts about %s\n"
              % (len(profile), profile.get("dev", "?")))
    else:
        print()


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

    # Wake up once a second: on Windows a blocking accept() ignores Ctrl+C
    # until the next connection arrives.
    server.settimeout(1.0)

    print("\n  listening for beacons on %s:%d  (Ctrl+C to stop)\n" % (host, port))
    try:
        while True:
            try:
                conn, addr = server.accept()
            except socket.timeout:
                continue
            thread = threading.Thread(
                target=handle_beacon, args=(conn, addr, ack), daemon=True
            )
            thread.start()
    except KeyboardInterrupt:
        say(summary())
        print("\n  stopped.\n")
        return 0
    finally:
        server.close()


def summary() -> str:
    """Everything the attacker collected, per board - printed at Ctrl+C."""
    with _PROFILE_LOCK:
        profiles = {d: dict(p) for d, p in PROFILES.items()}
    if not profiles:
        return "\n  the attacker received nothing readable."
    lines = ["\n  EVERYTHING THE ATTACKER COLLECTED"]
    for device, profile in sorted(profiles.items()):
        lines.append("  %s" % device)
        keys = ([k for k in FIELD_LABELS if k in profile]
                + [k for k in profile if k not in FIELD_LABELS])
        for key in keys:
            lines.append("      %-20s %s" % (FIELD_LABELS.get(key, key), _show(key, profile[key])))
    return "\n".join(lines)


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
