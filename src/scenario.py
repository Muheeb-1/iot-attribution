"""
SCENARIO - running ONE real attack against the live lab and writing down the truth.

WHAT THIS FILE DOES
-------------------
src/generate.py invents an incident in software. This file causes one in
hardware. It is the physical-world twin of the generator, and it has the same
two jobs, in the same order:

    1. make the attack actually happen on the wire, and
    2. write down, in groundtruth/, who really started it.

The attack it runs is deliberately the simplest thing that still exercises the
whole pipeline end to end:

    pick one of the three ESP32 boards at random          <- the origin
    tell it to misbehave, by publishing "attack" to
        ctrl/<that board>  through the broker at 192.168.0.200
    the board's firmware, on seeing that message, opens a
        TCP beacon to 192.168.0.200:4444                  <- the "C2" channel

src/listener.py is what sits on 4444 and answers those beacons, so the
connection completes and the beacon traffic is real, routable, and visible to
whatever is capturing the network. src/capture.py later turns that capture
into a run_NNN flow table; this file writes the matching groundtruth/ answer.
Point evaluate.py at the pair and you find out whether the method fingers the
right board without ever having been told.

WHY THIS FILE IS ALLOWED TO NAME THE ANSWER FOLDER
--------------------------------------------------
Exactly the same reason src/generate.py is. It is the thing that CHOOSES the
origin, so it is the only thing in the universe that knows the answer, so it
is the one that has to write it down. That is not a leak. A leak is the answer
flowing back INTO the detection pipeline. So, like the generator, this file is
held to the stricter standard enforced by tests/test_no_groundtruth_leak.py:

    it may WRITE the answer. It may not READ anything, ever.

It reads no files - not the answer folder, not the data folder, not a config.
Everything it needs is either on the command line or in the small constant
table below, so the answer can never make a round trip.

THE ONE HONEST DIFFERENCE FROM THE SIMULATOR'S GROUND TRUTH
-----------------------------------------------------------
The simulator knows its own clock, so it can record the onset as "seconds into
the capture". Here there is no such clock until the capture is opened: the
attack happens in wall-clock time, and only later is a pcap cut around it. So
the truth file records the wall-clock instant the trigger was published
(start_time / start_epoch) rather than a capture-relative window, and leaves
aligning the two to whoever pairs this run with its capture. Recording a
capture-relative onset we cannot actually know would be a fabrication, not a
convenience.

USAGE
-----
    python -m src.scenario --dry-run          # print the plan, touch nothing
    python -m src.scenario --run run_031      # do it, write groundtruth/run_031.json
    python -m src.scenario --origin esp32-02  # force the origin instead of random
    python -m src.scenario --seed 7           # reproducible "random" pick

Typical live workflow:
    1. start src/listener.py on the 192.168.0.200 host (the beacon sink)
    2. start your capture (Wireshark / tcpdump) on the lab segment
    3. run this with --run run_NNN
    4. stop the capture; python -m src.capture <pcap> --run run_NNN
    5. python -m src.evaluate  (the only thing allowed to open the answer)
"""

from __future__ import annotations

import argparse
import json
import random
import socket
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ANSWER_DIR = ROOT / "groundtruth"

# The boards that can be the origin. These are the three real ESP32s in the
# lab; src/capture.MAC_TO_NAME is the canonical inventory they come from, but
# they are repeated here as plain strings so this script depends on nothing -
# it has to run on a bare box that drives hardware, not the analysis stack.
ORIGINS = ["esp32-01", "esp32-02", "esp32-03"]

# The broker relays the trigger; it is also the host the beacon lands on.
BROKER_HOST = "192.168.0.200"
BROKER_PORT = 1883
BEACON_HOST = "192.168.0.200"
BEACON_PORT = 4444

# What we publish, and where. The firmware watches ctrl/<its-own-name>.
TRIGGER_TOPIC = "ctrl/%s"
TRIGGER_PAYLOAD = "attack"

# How we sign ourselves to the broker. A red-team tool has no reason to hide
# as which client it is; a clear id makes the injection easy to find later.
MQTT_CLIENT_ID = "redteam-injector"


# --------------------------------------------------------------------------
# A minimal MQTT 3.1.1 publisher, by hand, over a raw socket.
#
# paho-mqtt would do this too, but it is not a project dependency and this is
# meant to run on a lab box with nothing installed. A QoS-0 publish is three
# packets - CONNECT, PUBLISH, DISCONNECT - and small enough to read here, so
# what actually goes on the wire is in front of you rather than in a library.
# --------------------------------------------------------------------------

def _remaining_length(n: int) -> bytes:
    """MQTT's variable-length integer: 7 bits per byte, high bit = 'more'."""
    out = bytearray()
    while True:
        byte = n % 128
        n //= 128
        if n > 0:
            byte |= 0x80
        out.append(byte)
        if n == 0:
            return bytes(out)


def _mqtt_string(text: str) -> bytes:
    """An MQTT UTF-8 string: two-byte big-endian length, then the bytes."""
    raw = text.encode("utf-8")
    return len(raw).to_bytes(2, "big") + raw


def _connect_packet(client_id: str, keepalive: int = 30) -> bytes:
    variable_header = (
        _mqtt_string("MQTT")            # protocol name
        + bytes([0x04])                 # protocol level 4 = MQTT 3.1.1
        + bytes([0x02])                 # connect flags: clean session
        + keepalive.to_bytes(2, "big")
    )
    body = variable_header + _mqtt_string(client_id)
    return bytes([0x10]) + _remaining_length(len(body)) + body


def _publish_packet(topic: str, message: str) -> bytes:
    # QoS 0: no packet identifier, fire and forget - which is exactly the
    # semantics a one-shot trigger wants.
    body = _mqtt_string(topic) + message.encode("utf-8")
    return bytes([0x30]) + _remaining_length(len(body)) + body


_DISCONNECT_PACKET = bytes([0xE0, 0x00])


def publish_trigger(topic: str, payload: str,
                    host: str = BROKER_HOST, port: int = BROKER_PORT,
                    client_id: str = MQTT_CLIENT_ID, timeout: float = 5.0) -> None:
    """
    Connect to the broker, publish one retained-free QoS-0 message, disconnect.

    Raises on a refused connection or a broker that rejects the CONNECT, so a
    failed injection is loud rather than a truth file describing an attack that
    never left the building.
    """
    with socket.create_connection((host, port), timeout=timeout) as sock:
        sock.sendall(_connect_packet(client_id))

        # CONNACK is four bytes: 0x20, len 2, flags, return code. Return code 0
        # means accepted; anything else means the broker said no.
        connack = sock.recv(4)
        if len(connack) < 4 or connack[0] != 0x20:
            raise ConnectionError(
                "broker at %s:%d did not answer with a CONNACK (got %r)"
                % (host, port, connack)
            )
        if connack[3] != 0x00:
            raise ConnectionError(
                "broker at %s:%d refused the connection, CONNACK code %d"
                % (host, port, connack[3])
            )

        sock.sendall(_publish_packet(topic, payload))
        sock.sendall(_DISCONNECT_PACKET)


# --------------------------------------------------------------------------
# Choosing the origin and describing the plan
# --------------------------------------------------------------------------

def choose_origin(origin: str | None, seed: int | None) -> str:
    """The stated origin, or a random board. --seed makes the pick repeatable."""
    if origin is not None:
        if origin not in ORIGINS:
            raise ValueError(
                "%r is not one of the lab boards: %s" % (origin, ", ".join(ORIGINS))
            )
        return origin
    rng = random.Random(seed)
    return rng.choice(ORIGINS)


def build_plan(origin: str, run_id: str,
               broker_host: str, broker_port: int,
               beacon_host: str, beacon_port: int) -> dict:
    """Everything about what is (or would be) done, in one dict."""
    return {
        "run_id": run_id,
        "origin": origin,
        "trigger_topic": TRIGGER_TOPIC % origin,
        "trigger_payload": TRIGGER_PAYLOAD,
        "broker": "%s:%d" % (broker_host, broker_port),
        "beacon_target": "%s:%d" % (beacon_host, beacon_port),
    }


def print_plan(plan: dict, dry_run: bool) -> None:
    head = "DRY RUN - nothing will be touched" if dry_run else "LIVE ATTACK"
    print("\n  %s" % head)
    print("  " + "-" * 60)
    print("  run id         %s" % plan["run_id"])
    print("  origin board   %s" % plan["origin"])
    print("  publish        %r  ->  %s" % (plan["trigger_payload"], plan["trigger_topic"]))
    print("  via broker     %s" % plan["broker"])
    print("  board beacons  ->  %s" % plan["beacon_target"])
    print("  truth file     groundtruth/%s.json" % plan["run_id"])
    print()


# --------------------------------------------------------------------------
# Writing the answer sheet
# --------------------------------------------------------------------------

def build_answer(origin: str, run_id: str, start: datetime,
                 broker_host: str, broker_port: int,
                 beacon_host: str, beacon_port: int) -> dict:
    """
    The ground truth for this incident, shaped to sit alongside the simulated
    ones (origin / chain / via_broker / c2_host) so evaluate.py cannot tell a
    live run from a generated one.

    chain is [origin] alone: this scenario has no lateral movement, only the
    origin board reaching out to the C2. The C2 is the beacon sink, recorded
    separately from the chain exactly as the simulator records its c2_host.
    """
    return {
        "run_id": run_id,
        "scenario": "live",
        "origin": origin,
        "chain": [origin],
        "via_broker": True,                       # the trigger is relayed by the broker
        "c2_host": "%s:%d" % (beacon_host, beacon_port),
        "trigger": {
            "topic": TRIGGER_TOPIC % origin,
            "payload": TRIGGER_PAYLOAD,
            "broker": "%s:%d" % (broker_host, broker_port),
        },
        "beacon_target": {"host": beacon_host, "port": beacon_port},
        "start_time": start.isoformat(timespec="seconds"),
        "start_epoch": start.timestamp(),
        # Wall-clock onset per compromised device. Not capture-relative on
        # purpose - see the module docstring - so alignment is left to whoever
        # pairs this with a capture rather than faked here.
        "true_onset_epoch": {origin: start.timestamp()},
        "devices": list(ORIGINS),
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }


def write_answer(answer: dict, answer_dir: Path = ANSWER_DIR) -> Path:
    """Write groundtruth/<run_id>.json. Writes only - never reads anything back."""
    answer_dir = Path(answer_dir)
    answer_dir.mkdir(parents=True, exist_ok=True)
    path = answer_dir / ("%s.json" % answer["run_id"])
    path.write_text(json.dumps(answer, indent=2), encoding="utf-8")
    return path


# --------------------------------------------------------------------------
# Command line
# --------------------------------------------------------------------------

def _default_run_id(now: datetime) -> str:
    """A timestamped id when none is given. Deliberately not run_NNN: this
    file may not glob the data folder to find the next free number (that is a
    read), and guessing one risks colliding with a simulated run."""
    return "live_%s" % now.strftime("%Y%m%d_%H%M%S")


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description="Run one real attack against the live lab and record the truth."
    )
    parser.add_argument("--run", default=None,
                        help="run id for the truth file (default: live_<timestamp>). "
                             "Save the matching capture under the same id.")
    parser.add_argument("--origin", default=None, choices=ORIGINS,
                        help="force the origin board (default: random)")
    parser.add_argument("--seed", type=int, default=None,
                        help="make the random origin pick reproducible")
    parser.add_argument("--broker-host", default=BROKER_HOST)
    parser.add_argument("--broker-port", type=int, default=BROKER_PORT)
    parser.add_argument("--beacon-host", default=BEACON_HOST)
    parser.add_argument("--beacon-port", type=int, default=BEACON_PORT)
    parser.add_argument("--dry-run", action="store_true",
                        help="print the plan and exit without touching hardware or disk")
    args = parser.parse_args(argv)

    now = datetime.now(timezone.utc)
    run_id = args.run or _default_run_id(now)

    try:
        origin = choose_origin(args.origin, args.seed)
    except ValueError as exc:
        print("\n  %s\n" % exc, file=sys.stderr)
        return 1

    plan = build_plan(origin, run_id, args.broker_host, args.broker_port,
                      args.beacon_host, args.beacon_port)
    print_plan(plan, dry_run=args.dry_run)

    if args.dry_run:
        print("  (dry run: no MQTT sent, no truth file written)\n")
        return 0

    topic = TRIGGER_TOPIC % origin
    try:
        publish_trigger(topic, TRIGGER_PAYLOAD,
                        host=args.broker_host, port=args.broker_port)
    except OSError as exc:
        print("  FAILED to publish the trigger: %s" % exc, file=sys.stderr)
        print("  No truth file written - an attack that did not happen has no "
              "answer.\n", file=sys.stderr)
        return 1

    print("  published %r to %s via %s:%d"
          % (TRIGGER_PAYLOAD, topic, args.broker_host, args.broker_port))

    answer = build_answer(origin, run_id, now,
                          args.broker_host, args.broker_port,
                          args.beacon_host, args.beacon_port)
    path = write_answer(answer)
    print("  wrote %s\n" % path)
    return 0


if __name__ == "__main__":
    sys.exit(main())
