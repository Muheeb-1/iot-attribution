"""
RUN_ATTACK - drive a batch of real attacks into ONE continuous capture.

WHY THIS FILE EXISTS
--------------------
src/scenario.py runs exactly one attack and writes one answer file. That is
the right shape for a single careful experiment, and the wrong shape for
measuring accuracy, which needs a dozen of them under identical conditions.

This file is the batch driver. It does not reimplement the attack - it calls
scenario.publish_trigger / build_answer / write_answer, so every answer file it
produces is identical in shape to one written by a hand-run scenario. If the
two ever disagree about what an attack IS, that is a bug, not a variant.

WHAT THIS FILE IS NOT ALLOWED TO KNOW
-------------------------------------
scenario.py may name the answer folder because it is the only thing that knows
its own answer and somebody has to write it down. It pays for that privilege by
being forbidden to read ANYTHING, ever, so the answer can never round-trip.

This file cannot pay that price: --split has to read the timing manifest back.
So it takes the other side of the bargain - it never names the answer folder,
and it delegates every write to scenario.write_answer(). The origin flows one
way only: chosen here, handed to scenario.py, never read back.

That is also why the manifest records no origin. It would be harmless today -
nothing feeds it to the detector - but a file under results/, containing the
answer, that a src/ module reads, is a second answer sheet in everything but
name. Which board each round hit is printed live and recorded by scenario.py;
the manifest carries only timings and QA counts.

WHY IT DOES NOT CAPTURE ANYTHING
--------------------------------
Npcap on this host is installed with AdminOnly=1:

    HKLM\\SYSTEM\\CurrentControlSet\\Services\\npcap\\Parameters   AdminOnly = 1

An unelevated process can ENUMERATE interfaces (dumpcap -D succeeds, listing
all nine) but cannot OPEN one. dumpcap does not fail when it tries - it blocks
forever, with no error, no output file, and no exit. A batch that shelled out
to dumpcap per run would therefore hang on round 1 and look like a slow
network rather than a permissions wall.

So capture is not this file's job. A human starts ONE continuous Wireshark
capture that spans the whole batch; this file fires scheduled attacks into it
and records exactly WHEN each round happened; afterwards --split cuts that one
capture into per-round segments with editcap, which is a file-to-file tool and
needs no driver access at all.

That division has a second benefit beyond working at all: one capture has one
clock. Per-run captures would each start at their own arbitrary instant, and
aligning a wall-clock trigger to a capture-relative window would have to be
redone, and could drift, twelve separate times.

HOW A ROUND IS SHAPED
---------------------
    [reset][ settle ][        baseline        ][attack][ beacons ]
           ^                                   ^
           latch cleared                       trigger published

  reset     publish "stop" to every board in play. The firmware clears its
            compromised flag (sensor.ino onMqttMessage), so the board stops
            beaconing but does NOT reboot - see THE RESET below.
  settle    IDLE_SECONDS (capture.py) of quiet, so the previous round's last
            beacon flow reaches its idle timeout and closes INSIDE the previous
            round's segment rather than straddling into this one's baseline.
  baseline  quiet. This is what the detector will learn as normal, so a single
            beacon landing here would poison the very run it is meant to
            measure. The sink below counts beacons during this phase and the
            round is marked BAD if that count is not zero. That is the whole
            ballgame.
  attack    the trigger, at a recorded wall-clock instant.
  beacons   the board beacons every BEACON_EVERY_MS. Long enough that the
            detector sees CONSECUTIVE windows above threshold.

THE RESET - why "stop" and not a power cycle
--------------------------------------------
The firmware already accepts "stop" as well as "attack":

    } else if (length == 4 && memcmp(payload, "stop", 4) == 0) {
        compromised = false;

No firmware change is needed, and "stop" is strictly BETTER than rebooting the
board, because a reboot is not silent. On boot the firmware calls publishHello()
and opens a fresh MQTT CONNECT - two anomalous-looking events that would land
in the very baseline this file works to keep clean. "stop" changes one bool in
RAM and puts nothing on the wire except the tiny control message that carried
it. Verified on live hardware over two arm/stop cycles: beaconing ceased within
one interval both times, while uptime and seq kept climbing, so the board
demonstrably did not restart.

The flag lives in RAM, so a power cycle clears it too. That is the fallback if
a board ever stops answering "stop", not the routine.

USAGE
-----
    # prove the hardware behaves, in ~9 minutes, writing no truth files
    python -m src.run_attack --dry-run --rounds 2

    # the real batch: start ONE Wireshark capture first, then
    python -m src.run_attack --rounds 12

    # afterwards, cut that one capture into per-round runs
    python -m src.run_attack --split pcap/live_batch.pcapng
"""

from __future__ import annotations

import argparse
import json
import shutil
import socket
import subprocess
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

from src import capture, scenario, windows

ROOT = Path(__file__).resolve().parents[1]
MANIFEST_DIR = ROOT / "results"

# Phase lengths, in seconds. The defaults reproduce live_test_02's shape so the
# batch is directly comparable to the run that established it.
BASELINE_SECONDS = 720.0     # 12 windows; live_test_02 used exactly this
SETTLE_SECONDS = capture.IDLE_SECONDS + 30.0   # last flow closes, plus margin

# Long enough for >= CONSECUTIVE windows of beaconing, with margin - but
# deliberately NOT a multiple of the firmware's BEACON_EVERY_MS (30s).
#
# At 300s the last beacon falls due at t+300.00 and the reset fires at t+300.00.
# The dry run caught exactly that: a beacon and its stop 0.02s apart, so the
# beacon escaped into the settle window. Harmless - settle exists to absorb it,
# and the segments either side stay disjoint - but it would happen EVERY round,
# which makes settle_beacons worthless as a signal: a genuinely missed stop
# would look identical to the tie. At 310s the last beacon lands 10s inside the
# phase and the next is never due, so settle_beacons should be 0 every time and
# any non-zero value is worth looking at.
ATTACK_SECONDS = 310.0

# The trigger is placed this far AFTER the baseline boundary. Without it the
# attack lands in the last baseline window (live_test_02 fired at t=709.1s with
# a 720s baseline - harmless there because the first beacon was still 30s away,
# but it is not a property to rely on twice). With it, the baseline is provably
# attack-free rather than incidentally so.
GUARD_SECONDS = 15.0

BEACON_PORT = 4444
POLL_SECONDS = 1.0

# A dry run proves hardware behaviour, not detection. Its phases are far too
# short for detect.MIN_BASELINE_WINDOWS, which is exactly why it writes no
# truth files: runs that cannot be scored should not look scoreable.
DRY_BASELINE = 120.0
DRY_ATTACK = 130.0     # not a multiple of 30s either - see ATTACK_SECONDS
DRY_SETTLE = 30.0


# --------------------------------------------------------------------------
# The beacon sink - listener.py's job, plus the counting this file needs
# --------------------------------------------------------------------------

class BeaconSink:
    """
    Answers beacons so they complete, and counts them so phases can be checked.

    src/listener.py is the standalone version of this and is the right tool
    when a human is watching a single run. A batch needs the count back as a
    value rather than as printed text, so it runs its own sink in-process
    instead of parsing another process's log. The socket behaviour is the
    same: accept, read to EOF, close.
    """

    def __init__(self, port: int = BEACON_PORT):
        self.port = port
        self.beacons: list = []
        self._lock = threading.Lock()
        self._server = None
        self._stop = threading.Event()

    def start(self) -> None:
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            server.bind(("0.0.0.0", self.port))
        except OSError as exc:
            raise SystemExit(
                "\n  cannot bind port %d - %s\n"
                "  Something else is already listening. If src/listener.py is\n"
                "  running, stop it: this file provides its own sink.\n"
                % (self.port, exc)
            )
        server.listen(8)
        server.settimeout(0.5)
        self._server = server
        threading.Thread(target=self._accept_loop, daemon=True).start()

    def _accept_loop(self) -> None:
        while not self._stop.is_set():
            try:
                conn, addr = self._server.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            threading.Thread(
                target=self._handle, args=(conn, addr), daemon=True
            ).start()

    def _handle(self, conn, addr) -> None:
        with self._lock:
            self.beacons.append((time.time(), addr[0]))
        try:
            while True:
                if not conn.recv(4096):
                    break
        except OSError:
            pass
        finally:
            conn.close()

    def count(self) -> int:
        with self._lock:
            return len(self.beacons)

    def stop(self) -> None:
        self._stop.set()
        if self._server is not None:
            self._server.close()


# --------------------------------------------------------------------------
# Talking to the boards
# --------------------------------------------------------------------------

def send_command(board: str, payload: str, host: str, port: int) -> None:
    """One control message, through scenario.py's publisher and no other."""
    scenario.publish_trigger(scenario.TRIGGER_TOPIC % board, payload,
                             host=host, port=port)


def reset_boards(boards, host: str, port: int) -> None:
    """
    Clear the latch on every board in play, not just the one about to be hit.

    Only the attacked board can be latched, so stopping all of them is
    redundant by construction. It is done anyway because the cost is one tiny
    publish per board, and the failure it prevents - a board left beaconing
    from an earlier round, quietly contaminating this round's baseline - is
    silent, survives into the results, and is indistinguishable from a
    detector bug when you go looking for it later.
    """
    for board in boards:
        send_command(board, "stop", host, port)


def wait(seconds: float, label: str, sink: BeaconSink) -> int:
    """
    Sleep out a phase, printing progress, and report beacons seen during it.

    Returns the beacon count for the phase so the caller can assert on it.
    """
    start = time.time()
    before = sink.count()
    end = start + seconds
    last_line = 0.0
    while True:
        now = time.time()
        if now >= end:
            break
        if now - last_line >= 15.0:
            seen = sink.count() - before
            print("      %-9s %4ds / %4ds   beacons this phase: %d"
                  % (label, int(now - start), int(seconds), seen), flush=True)
            last_line = now
        time.sleep(min(POLL_SECONDS, max(0.0, end - now)))
    return sink.count() - before


# --------------------------------------------------------------------------
# One round
# --------------------------------------------------------------------------

def run_round(index: int, total_rounds: int, origin: str, run_id: str,
              sink: BeaconSink, baseline_seconds: float, attack_seconds: float,
              settle_seconds: float, guard_seconds: float,
              boards, broker_host: str, broker_port: int,
              beacon_host: str, beacon_port: int,
              write_truth: bool) -> dict:
    """
    Reset, stay quiet, attack, let it beacon. Returns the round's timings.

    The returned dict is what --split later needs in order to cut this round
    out of the continuous capture, so it records absolute epochs rather than
    durations: durations would have to be re-added in the right order by
    whoever reads it, and getting that wrong would silently misalign a segment
    instead of failing.
    """
    print("\n  round %d/%d  -  %s  ->  %s"
          % (index, total_rounds, run_id, origin), flush=True)

    # ---- reset ----------------------------------------------------------
    print("    reset    stop -> %s" % ", ".join(boards), flush=True)
    reset_boards(boards, broker_host, broker_port)
    settle_beacons = wait(settle_seconds, "settle", sink)

    # ---- baseline -------------------------------------------------------
    quiet_for = baseline_seconds + guard_seconds
    print("    baseline %ds quiet (must stay beacon-free)" % int(quiet_for),
          flush=True)
    baseline_beacons = wait(quiet_for, "baseline", sink)

    # ---- attack ---------------------------------------------------------
    fired_at = datetime.now(timezone.utc)
    send_command(origin, scenario.TRIGGER_PAYLOAD, broker_host, broker_port)
    attack_epoch = fired_at.timestamp()
    print("    ATTACK   %r -> ctrl/%s  at %s"
          % (scenario.TRIGGER_PAYLOAD, origin,
             datetime.fromtimestamp(attack_epoch).strftime("%H:%M:%S.%f")[:-3]),
          flush=True)

    if write_truth:
        answer = scenario.build_answer(
            origin, run_id, fired_at,
            broker_host, broker_port, beacon_host, beacon_port,
        )
        path = scenario.write_answer(answer)
        print("    answer   %s" % path.name, flush=True)

    # ---- beacons --------------------------------------------------------
    attack_beacons = wait(attack_seconds, "beacons", sink)
    round_end = time.time()

    # Leave the board clean even if the batch is interrupted right here.
    reset_boards(boards, broker_host, broker_port)

    # No origin here, deliberately - see the note at the top of this file.
    record = {
        "round": index,
        "run_id": run_id,
        "attack_epoch": attack_epoch,
        "attack_local": datetime.fromtimestamp(attack_epoch).isoformat(
            timespec="milliseconds"),
        "slice_start_epoch": attack_epoch - baseline_seconds - guard_seconds,
        "slice_end_epoch": round_end,
        "baseline_seconds": baseline_seconds,
        "guard_seconds": guard_seconds,
        "settle_beacons": settle_beacons,
        "baseline_beacons": baseline_beacons,
        "attack_beacons": attack_beacons,
        "baseline_clean": baseline_beacons == 0,
        "attack_fired": attack_beacons > 0,
    }

    ok = record["baseline_clean"] and record["attack_fired"]
    print("    %s      baseline_beacons=%d (want 0)   attack_beacons=%d (want >0)"
          % ("OK " if ok else "BAD", baseline_beacons, attack_beacons), flush=True)
    if settle_beacons:
        print("             note: %d beacon(s) arrived during settle - the previous"
              " round's tail, which is what settle is for" % settle_beacons,
              flush=True)
    return record


# --------------------------------------------------------------------------
# The batch
# --------------------------------------------------------------------------

def alternating_origins(rounds: int, boards) -> list:
    """esp32-02, esp32-03, esp32-02, ... - equal counts when rounds is even."""
    return [boards[i % len(boards)] for i in range(rounds)]


def _hms(seconds: float) -> str:
    seconds = int(seconds)
    if seconds < 3600:
        return "%dm%02ds" % (seconds // 60, seconds % 60)
    return "%dh%02dm" % (seconds // 3600, (seconds % 3600) // 60)


def run_batch(rounds: int, boards, baseline_seconds: float,
              attack_seconds: float, settle_seconds: float,
              guard_seconds: float, run_prefix: str,
              broker_host: str, broker_port: int,
              beacon_host: str, beacon_port: int,
              write_truth: bool, manifest_path: Path) -> int:
    origins = alternating_origins(rounds, boards)
    per_round = settle_seconds + baseline_seconds + guard_seconds + attack_seconds
    total = per_round * rounds

    print("\n  BATCH  %d rounds, %s each, %s total"
          % (rounds, _hms(per_round), _hms(total)))
    print("  " + "-" * 70)
    print("  boards in play   %s" % ", ".join(boards))
    print("  origins          %s" % ", ".join(origins))
    print("  baseline         %ds (+%ds guard) = %d windows"
          % (baseline_seconds, guard_seconds,
             windows.baseline_window_count(baseline_seconds)))
    print("  attack           %ds" % attack_seconds)
    # Say which of the two the settle actually is. A dry run's settle is
    # deliberately shorter than IDLE_SECONDS, and a line that claimed
    # "IDLE_SECONDS + margin" while printing 30s would be quietly false.
    if settle_seconds >= capture.IDLE_SECONDS:
        settle_note = "capture.IDLE_SECONDS=%ds + margin" % capture.IDLE_SECONDS
    else:
        settle_note = ("BELOW capture.IDLE_SECONDS=%ds - fine for a dry run, "
                       "which converts nothing" % capture.IDLE_SECONDS)
    print("  settle           %ds (%s)" % (settle_seconds, settle_note))
    print("  answer files     %s"
          % ("written by scenario.py, one per round" if write_truth
             else "NOT written (dry run)"))
    print("  expected finish  %s"
          % datetime.fromtimestamp(time.time() + total).strftime("%H:%M:%S"))
    print()

    sink = BeaconSink(beacon_port)
    sink.start()
    print("  beacon sink listening on 0.0.0.0:%d" % beacon_port)

    records = []
    interrupted = False
    try:
        for i, origin in enumerate(origins, 1):
            records.append(run_round(
                i, rounds, origin, "%s_%02d" % (run_prefix, i), sink,
                baseline_seconds, attack_seconds, settle_seconds, guard_seconds,
                boards, broker_host, broker_port, beacon_host, beacon_port,
                write_truth,
            ))
    except KeyboardInterrupt:
        interrupted = True
        print("\n  interrupted - resetting boards before exit", flush=True)
        reset_boards(boards, broker_host, broker_port)
    finally:
        sink.stop()

    manifest = {
        "created": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "baseline_seconds": baseline_seconds,
        "guard_seconds": guard_seconds,
        "attack_seconds": attack_seconds,
        "settle_seconds": settle_seconds,
        "dry_run": not write_truth,
        "interrupted": interrupted,
        "rounds": records,
    }
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")

    clean = sum(1 for r in records if r["baseline_clean"])
    fired = sum(1 for r in records if r["attack_fired"])
    print("\n  " + "=" * 70)
    print("  %d rounds: %d with a clean baseline, %d that actually beaconed"
          % (len(records), clean, fired))
    print("  manifest -> %s" % manifest_path)
    if not records or clean != len(records) or fired != len(records):
        print("\n  NOT ALL ROUNDS ARE USABLE - see the table above.")
        return 1
    return 0


# --------------------------------------------------------------------------
# Cutting the one capture into per-round runs
# --------------------------------------------------------------------------

def find_editcap(explicit=None) -> str:
    """
    Locate editcap, the same way capture.py locates tshark.

    editcap reads and writes FILES. It never opens a network adapter, so the
    AdminOnly wall that stops dumpcap does not apply to it - which is the whole
    reason the split happens after the fact instead of during.
    """
    if explicit:
        if Path(explicit).exists():
            return explicit
        raise FileNotFoundError("no editcap at %s" % explicit)
    found = shutil.which("editcap")
    if found:
        return found
    for candidate in (r"C:\Program Files\Wireshark\editcap.exe",
                      r"C:\Program Files (x86)\Wireshark\editcap.exe",
                      "/usr/bin/editcap", "/usr/local/bin/editcap"):
        if Path(candidate).exists():
            return candidate
    raise FileNotFoundError(
        "editcap not found. It ships with Wireshark. Pass --editcap PATH."
    )


def _editcap_time(epoch: float) -> str:
    """editcap -A/-B take LOCAL wall-clock, to the second."""
    return datetime.fromtimestamp(epoch).strftime("%Y-%m-%d %H:%M:%S")


def split_capture(master_pcap: Path, manifest_path: Path, out_dir: Path,
                  editcap=None, tshark=None, force: bool = False) -> int:
    """
    Cut the continuous capture into one segment per round, then convert each.

    Each segment starts guard_seconds + baseline_seconds before that round's
    trigger, so converting it with --baseline <baseline_seconds> puts the
    trigger just PAST the baseline boundary, and the baseline windows contain
    no attack traffic at all.
    """
    master_pcap = Path(master_pcap)
    if not master_pcap.exists():
        raise FileNotFoundError("no capture at %s" % master_pcap)
    manifest_path = Path(manifest_path)
    if not manifest_path.exists():
        raise FileNotFoundError(
            "no manifest at %s - it is written by the batch run" % manifest_path)
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    rounds = manifest["rounds"]
    if manifest.get("dry_run"):
        print("\n  NOTE: this manifest is from a --dry-run batch. Those rounds\n"
              "  have no answer files and baselines far below\n"
              "  detect.MIN_BASELINE_WINDOWS, so they can be converted but not\n"
              "  meaningfully scored.")

    binary = find_editcap(editcap)
    out_dir.mkdir(parents=True, exist_ok=True)
    print("\n  splitting %s into %d segments" % (master_pcap.name, len(rounds)))
    print("  " + "-" * 70)

    failures = 0
    for rec in rounds:
        run_id = rec["run_id"]
        segment = out_dir / ("%s.pcapng" % run_id)
        command = [binary,
                   "-A", _editcap_time(rec["slice_start_epoch"]),
                   "-B", _editcap_time(rec["slice_end_epoch"]),
                   str(master_pcap), str(segment)]
        result = subprocess.run(command, capture_output=True, text=True)
        if result.returncode != 0:
            print("  %-16s editcap FAILED: %s" % (run_id, result.stderr.strip()))
            failures += 1
            continue
        try:
            _, _, _, meta, n_packets = capture.capture_to_run(
                segment, run_id=run_id, tshark=tshark,
                baseline_seconds=rec["baseline_seconds"], force=force,
            )
        except Exception as exc:
            print("  %-16s convert FAILED: %s" % (run_id, exc))
            failures += 1
            continue
        print("  %-16s %5d packets -> %4d flows, %4ds, baseline %2d windows"
              % (run_id, n_packets, meta["n_connections"],
                 meta["capture_seconds"], meta["baseline_windows"]))

    print("\n  %d/%d segments converted" % (len(rounds) - failures, len(rounds)))
    return 1 if failures else 0


# --------------------------------------------------------------------------
# Command line
# --------------------------------------------------------------------------

def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description="Drive a batch of real attacks into one continuous capture."
    )
    parser.add_argument("--rounds", type=int, default=12)
    parser.add_argument("--boards", default="esp32-02,esp32-03",
                        help="comma-separated, alternated in order")
    parser.add_argument("--prefix", default="live_batch", help="run id prefix")
    parser.add_argument("--baseline", type=float, default=BASELINE_SECONDS)
    parser.add_argument("--attack", type=float, default=ATTACK_SECONDS)
    parser.add_argument("--settle", type=float, default=SETTLE_SECONDS)
    parser.add_argument("--guard", type=float, default=GUARD_SECONDS)
    parser.add_argument("--broker-host", default=scenario.BROKER_HOST)
    parser.add_argument("--broker-port", type=int, default=scenario.BROKER_PORT)
    parser.add_argument("--beacon-host", default=scenario.BEACON_HOST)
    parser.add_argument("--beacon-port", type=int, default=scenario.BEACON_PORT)
    parser.add_argument("--manifest", default=None,
                        help="where to write/read the timing manifest")
    parser.add_argument("--dry-run", action="store_true",
                        help="short phases, no truth files - proves the hardware "
                             "resets and that each baseline is beacon-free")
    parser.add_argument("--split", default=None, metavar="PCAP",
                        help="cut this continuous capture using the manifest")
    parser.add_argument("--out-dir", default=str(ROOT / "pcap" / "segments"))
    parser.add_argument("--editcap", default=None)
    parser.add_argument("--tshark", default=None)
    parser.add_argument("--force", action="store_true",
                        help="overwrite existing runs when splitting")
    args = parser.parse_args(argv)

    boards = [b.strip() for b in args.boards.split(",") if b.strip()]
    if not boards:
        print("\n  no boards given\n", file=sys.stderr)
        return 1
    for board in boards:
        if board in scenario.NEVER_ATTACK:
            print("\n  %s is on the never-attack list - refusing.\n" % board,
                  file=sys.stderr)
            return 1
        if board not in scenario.ORIGINS:
            print("\n  %s is not a lab board (%s)\n"
                  % (board, ", ".join(scenario.ORIGINS)), file=sys.stderr)
            return 1

    prefix = args.prefix + ("_dry" if args.dry_run else "")
    manifest_path = (Path(args.manifest) if args.manifest
                     else MANIFEST_DIR / ("%s_manifest.json" % prefix))

    if args.split:
        return split_capture(Path(args.split), manifest_path,
                             Path(args.out_dir), editcap=args.editcap,
                             tshark=args.tshark, force=args.force)

    if args.dry_run:
        baseline, attack, settle = DRY_BASELINE, DRY_ATTACK, DRY_SETTLE
    else:
        baseline, attack, settle = args.baseline, args.attack, args.settle
        needed = windows.baseline_window_count(baseline)
        if needed < 8:
            print("\n  a baseline of %ds is only %d windows; "
                  "detect.MIN_BASELINE_WINDOWS is 8,\n"
                  "  so every device would be skipped and nothing scored.\n"
                  % (baseline, needed), file=sys.stderr)
            return 1

    return run_batch(
        args.rounds, boards, baseline, attack, settle, args.guard, prefix,
        args.broker_host, args.broker_port, args.beacon_host, args.beacon_port,
        write_truth=not args.dry_run, manifest_path=manifest_path,
    )


if __name__ == "__main__":
    sys.exit(main())
