"""
LIVE - running the unchanged pipeline WHILE the capture is still recording.

WHAT THIS FILE DOES
-------------------
Until now the pipeline only ran after a capture had stopped: record in
Wireshark, convert with src/capture.py, open the run in the dashboard. This
file makes it run during the capture. It watches a folder that dumpcap (or
Wireshark) fills with short capture files, and every time a minute of traffic
is complete it re-runs the whole analysis on everything recorded so far and
writes the answer to state.json, which the live dashboard page reads.

    dumpcap  ->  pcap/live/<session>/ring_00001_<time>.pcapng   (one file per 10 s)
                                 |
    this file: each FINISHED file -> capture.read_packets
               each CLOSED minute  -> build_flows -> build_features
                                      -> detect -> attribute -> template brief
               -> pcap/live/<session>/state.json   (written atomically)
                                 |
    dashboard live page reads state.json every few seconds

When the session stops it is saved as an ordinary run in data/, so the
existing replay dashboard and evaluate.py open and score it like any other.

WHY THERE IS NO SECOND COPY OF THE METHOD
-----------------------------------------
Nothing here detects or attributes anything by itself. Every cycle builds an
ordinary runs.Run in memory and hands it to the SAME functions the offline
path uses: capture.read_packets, capture.build_flows, detect.detect_run
(which calls features.build_features), attribute.attribute_run, and
report.build_evidence / report.template_brief. The live verdict therefore
equals the offline verdict on the same packets by construction, and the
acceptance tests check it on all twelve real attack captures anyway.

"Re-run everything every minute" sounds wasteful but is cheap: one cycle took
0.2-0.4 s on a 17-minute session. Clever incremental maths would be faster
and would also be a second implementation that could quietly disagree with
the first.

THREE RULES THAT KEEP THE LIVE ANSWER HONEST
--------------------------------------------
1. The NEWEST capture file is never read while the capture runs. dumpcap is
   still writing it, so reading it would see half a file. A file is read only
   once a newer one exists - or at STOP, when the last one is finished too.

2. Only CLOSED minutes are scored. A minute counts as closed once the capture
   has reached 5 seconds past its end (window end + GRACE_SECONDS, measured on
   the packets' own clock, not the laptop's). A half-finished minute has
   fewer connections than it will end up with, and scoring it could invent an
   onset or hide one. At STOP the final pass scores everything, exactly as the
   offline pipeline does on the merged capture.

3. The detector needs its baseline first. Until the baseline minutes are all
   closed the session is LEARNING and nothing is scored at all: judging a
   device against half a baseline is judging it against a different normal.

TIME
----
Inside the pipeline, time is seconds since the first packet, exactly as in
capture.py. capture_start_epoch (the first packet's wall-clock time) is kept
alongside so the page can show real clock times. "now" for the engine is the
newest packet it has read, not the laptop's clock, so a replay at 20x speed
makes exactly the same decisions at exactly the same capture times as a live
session does.

WHEN IS THE ALERT?
------------------
The detector calls a device's onset the first of three abnormal minutes in a
row (detect.CONSECUTIVE). So the alert cannot be raised before the THIRD of
those minutes closes. state.json records two times:
    first_alert_closed_epoch  the moment that third minute closed (+ grace) -
                              the earliest the method could possibly know;
    first_alert_epoch         the capture time at which the engine actually
                              raised it - up to one file (10 s) later,
                              because the newest file is read only once the
                              next one exists.
On the twelve real attacks the first is 229-230 s after the trigger: the
trigger lands about 15 s into a minute that does not yet look abnormal, and
then three abnormal minutes plus the 5 s grace follow (45 + 180 + 5).

FILES THAT GO WRONG
-------------------
A capture file that is empty, unreadable, has no packets with an Ethernet
layer, or goes backwards in time is REPORTED (in state.json "problems" and on
the console) and skipped. It never stops the session. Measured on this laptop
with tshark 4.6.9: a file cut short mid-packet is read without error and its
complete packets are kept, so truncation loses at most the last half packet.

WHAT THIS FILE DOES NOT DO
--------------------------
It never contacts a device, a router or the broker, and never blocks
anything: containment is recommended, never executed. It does not know which
device was really attacked - that is written by scenario.py and read only by
evaluate.py and, after STOP, by the dashboard's reveal tick. It does not start
the capture; that needs an Administrator terminal (Npcap here is AdminOnly),
which is why the engine only reads finished files and runs as a normal user.

USAGE
-----
    python -m src.live --session live_session_01                 # watch pcap/live/live_session_01/
    python -m src.live --session live_session_01 --baseline 600
    python -m src.live --session replay_05 --replay pcap/segments/live_batch_05.pcapng --speed 20

Stop a live session by pressing Ctrl+C here, or by creating a file called
STOP in the session folder. If no new capture file appears for 30 seconds the
session also stops by itself (the capture has evidently ended).
"""

from __future__ import annotations

import argparse
import json
import math
import os
import shutil
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

import numpy as np
import pandas as pd

from src import attribute, capture, detect, report, runs, windows

ROOT = capture.ROOT
LIVE_DIR = ROOT / "pcap" / "live"

STATE_FILE = "state.json"
STOP_FILE = "STOP"
REPLAY_SOURCE = "replay_source"     # where --replay keeps the cut-up capture

# A minute is "closed" this long after its end. Packets are timestamped when
# the adapter sees them, and the last few of a minute can land in the next
# capture file; five seconds is generous for that and costs five seconds of
# alert latency.
GRACE_SECONDS = 5.0

# No new capture file for this long means the capture has stopped.
QUIET_SECONDS = 30.0

# Length of each capture file, for dumpcap -b duration: and for --replay.
SEGMENT_SECONDS = 10

# The baseline used for every real-lab run so far (12 minutes).
DEFAULT_BASELINE = 720

# How often the live loop looks for new files.
POLL_SECONDS = 1.0

# A file whose packets start more than this far BEFORE the newest packet
# already read has come from somewhere else (an old file dropped in the
# folder, a clock jump). It is reported and skipped.
OUT_OF_ORDER_TOLERANCE = 1.0

CAPTURE_SUFFIXES = (".pcapng", ".pcap")

# The phases, in the order a session normally passes through them.
WAITING = "WAITING"           # no capture file yet
LEARNING = "LEARNING"         # baseline still being recorded
MONITORING = "MONITORING"     # baseline done, nothing abnormal
INCIDENT = "INCIDENT"         # a device has gone sustainedly abnormal
CONTAINED = "CONTAINED"       # reserved for Step 18 (the containment check)
STOPPED = "STOPPED"           # capture over, final verdict written
PHASES = [WAITING, LEARNING, MONITORING, INCIDENT, CONTAINED, STOPPED]


# --------------------------------------------------------------------------
# Small helpers
# --------------------------------------------------------------------------

def ring_files(folder: Path) -> list:
    """
    The capture files in the session folder, oldest first.

    dumpcap and Wireshark both name ring files  <prefix>_<NNNNN>_<YYYYMMDDhhmmss>,
    with a zero-padded counter, so sorting by name is sorting by age. Files
    with any other suffix (state.json, STOP, a half-copied ".part") are not
    capture files and are ignored; so are hidden files.
    """
    folder = Path(folder)
    if not folder.is_dir():
        return []
    return sorted(
        p for p in folder.iterdir()
        if p.is_file() and p.suffix.lower() in CAPTURE_SUFFIXES
        and not p.name.startswith(".")
    )


def closed_window_count(now_seconds: float, window_seconds: int = windows.WINDOW_SECONDS,
                        grace_seconds: float = GRACE_SECONDS) -> int:
    """
    How many whole minutes are finished, given the newest packet's time.

    Window w is closed when the capture has reached (w + 1) * width + grace.
    So with 60 s windows and a 5 s grace, window 0 closes at 65 s, window 1 at
    125 s, and so on. The answer is the number of closed windows, i.e. windows
    0 .. count-1 are safe to score.
    """
    if now_seconds is None or now_seconds < grace_seconds:
        return 0
    return int(math.floor((now_seconds - grace_seconds) / window_seconds))


def json_safe(value):
    """
    Turn anything the pipeline produces into something json.dumps accepts.

    numpy numbers become plain numbers, dictionary keys become text (window
    numbers are ints), and NaN or infinity become null. The last one matters:
    Python's json module writes NaN by default, which is NOT valid JSON, and a
    browser or a strict reader would refuse the whole file.
    """
    if isinstance(value, dict):
        return {str(k): json_safe(v) for k, v in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [json_safe(v) for v in value]
    if isinstance(value, (np.bool_, bool)):
        return bool(value)
    if isinstance(value, (np.integer,)):
        return int(value)
    if isinstance(value, (float, np.floating)):
        value = float(value)
        return value if math.isfinite(value) else None
    if isinstance(value, Path):
        return str(value)
    return value


def write_state(path: Path, state: dict, attempts: int = 20) -> None:
    """
    Write state.json so that a reader never sees half a file.

    The text goes to state.json.tmp first and is then swapped in with
    os.replace, which is atomic: the reader sees either the old file or the
    new one, never a mixture. On Windows the swap can be refused for a moment
    while the dashboard has the old file open, so it is retried briefly.
    allow_nan=False makes json.dumps fail loudly rather than write invalid
    JSON, and json_safe has already removed every NaN it could produce.
    """
    path = Path(path)
    text = json.dumps(json_safe(state), indent=1, allow_nan=False)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(text, encoding="utf-8")
    for attempt in range(attempts):
        try:
            os.replace(tmp, path)
            return
        except PermissionError:
            if attempt == attempts - 1:
                raise
            time.sleep(0.05)


def find_editcap(explicit: str | None = None) -> str | None:
    """editcap, if it can be found (it ships with Wireshark). None if not."""
    if explicit:
        return explicit if Path(explicit).exists() else None
    found = shutil.which("editcap")
    if found:
        return found
    for candidate in (r"C:\Program Files\Wireshark\editcap.exe",
                      r"C:\Program Files (x86)\Wireshark\editcap.exe",
                      "/usr/bin/editcap", "/usr/local/bin/editcap"):
        if Path(candidate).exists():
            return candidate
    return None


def _first_epoch(packets: list):
    """The first packet time build_flows will use as t = 0 (same rule)."""
    for packet in packets:
        try:
            return float(packet["frame.time_epoch"])
        except (TypeError, ValueError, KeyError):
            continue
    return None


def _epochs(packets: list) -> list:
    out = []
    for packet in packets:
        try:
            out.append(float(packet["frame.time_epoch"]))
        except (TypeError, ValueError, KeyError):
            continue
    return out


def _clock(epoch) -> str | None:
    """Local wall-clock time, for console lines."""
    if epoch is None:
        return None
    return datetime.fromtimestamp(epoch).strftime("%H:%M:%S")


# --------------------------------------------------------------------------
# The live session
# --------------------------------------------------------------------------

class LiveSession:
    """
    One live session: a folder of capture files, analysed as they arrive.

    Use it by calling update() repeatedly while the capture runs, then
    finish() once. Both return the state dictionary that is also written to
    <folder>/state.json.

    folder            where the capture files appear
    baseline_seconds  how long the "this is normal" period is (whole minutes,
                      at least detect.MIN_BASELINE_WINDOWS of them)
    devices           the asset inventory, name -> kind (default: the lab's)
    session           the run id it is saved as at STOP (default: folder name)
    reader            how to read one file into packets; by default
                      capture.read_packets with tshark. Tests pass their own.
    data_dir          where the finished run is saved
    """

    def __init__(self, folder, baseline_seconds: float = DEFAULT_BASELINE,
                 devices: dict | None = None, session: str | None = None,
                 tshark: str | None = None,
                 window_seconds: int = windows.WINDOW_SECONDS,
                 grace_seconds: float = GRACE_SECONDS,
                 data_dir: Path = runs.DATA_DIR,
                 reader=None):
        self.folder = Path(folder)
        self.session = session or self.folder.name
        self.window_seconds = int(window_seconds)
        self.grace_seconds = float(grace_seconds)
        self.data_dir = Path(data_dir)

        # The baseline must be whole minutes (windows.py refuses otherwise)
        # and long enough for the detector to judge anybody at all.
        self.baseline_windows = windows.baseline_window_count(baseline_seconds,
                                                              self.window_seconds)
        if self.baseline_windows < detect.MIN_BASELINE_WINDOWS:
            raise ValueError(
                "a baseline of %ss is %d windows; the detector needs at least %d "
                "(%d s) before it will judge a device"
                % (baseline_seconds, self.baseline_windows, detect.MIN_BASELINE_WINDOWS,
                   detect.MIN_BASELINE_WINDOWS * self.window_seconds))
        self.baseline_seconds = int(self.baseline_windows * self.window_seconds)

        self.devices = dict(devices if devices is not None else capture.DEVICE_KINDS)
        self.device_names = list(self.devices)

        if reader is None:
            binary = capture.find_tshark(tshark)
            reader = lambda path: capture.read_packets(path, binary)  # noqa: E731
        self._reader = reader

        # What has been read.
        self.packets: list = []
        self.files_read: list = []          # names, in the order read
        self._done: set = set()             # names read OR rejected
        self.problems: list = []            # {file, problem, seconds}
        self.capture_start_epoch = None
        self.last_epoch = None

        # What has been concluded.
        self._flows = None                  # cache, rebuilt when packets change
        self._flows_for = -1                # len(packets) the cache was built from
        self.closed_windows = 0
        self.analysed_windows = -1          # closed_windows at the last analysis
        self.run = None
        self.detection = None
        self.result = None
        self.brief = None
        self.analysis_seconds = None        # how long the last cycle took

        self.phase = WAITING
        self.stopped = False
        self.first_alert = None             # dict, set once and never cleared
        self.verdict_changes: list = []
        self.phase_log: list = []
        self.cycles: list = []              # (now_seconds, phase) per update, for tests
        self.saved = None                   # (parquet, meta) after finish()
        self._last_verdict_key = None
        self._log_phase(WAITING)

    # ---- reading files -------------------------------------------------

    @property
    def now_seconds(self):
        """How far into the capture the engine has read (newest packet)."""
        if self.capture_start_epoch is None or self.last_epoch is None:
            return None
        return self.last_epoch - self.capture_start_epoch

    def _problem(self, path: Path, text: str) -> None:
        entry = {"file": Path(path).name, "problem": text, "seconds": self.now_seconds}
        self.problems.append(entry)
        print("  [live] %s: %s - skipped" % (entry["file"], text), file=sys.stderr)

    def _read_one(self, path: Path) -> int:
        """Read one finished capture file. Returns how many packets it added."""
        self._done.add(path.name)
        try:
            size = path.stat().st_size
        except OSError as exc:
            self._problem(path, "cannot be opened (%s)" % exc)
            return 0
        if size == 0:
            self._problem(path, "empty file (0 bytes)")
            return 0
        try:
            packets = self._reader(path)
        except Exception as exc:            # any failure to read is reported, never fatal
            self._problem(path, "unreadable (%s)" % str(exc).strip().splitlines()[0][:200])
            return 0

        if not any((p.get("eth.src") or "").strip() for p in packets):
            self._problem(path, "no readable packets")
            return 0

        times = _epochs(packets)
        if self.last_epoch is not None and times and \
                min(times) < self.last_epoch - OUT_OF_ORDER_TOLERANCE:
            self._problem(path, "goes back in time by %.1f s (not part of this capture?)"
                          % (self.last_epoch - min(times)))
            return 0

        if self.capture_start_epoch is None:
            self.capture_start_epoch = _first_epoch(packets)
        self.packets.extend(packets)
        if times:
            newest = max(times)
            self.last_epoch = newest if self.last_epoch is None else max(self.last_epoch, newest)
        self.files_read.append(path.name)
        return len(packets)

    def ingest(self, final: bool = False) -> int:
        """
        Read every finished file not read yet. The newest file is left alone
        unless final=True, because the capture may still be writing it.
        """
        files = ring_files(self.folder)
        if not final:
            files = files[:-1]
        added = 0
        for path in files:
            if path.name not in self._done:
                added += self._read_one(path)
        return added

    # ---- the analysis --------------------------------------------------

    def flows(self) -> pd.DataFrame:
        """Every packet so far, as flows - capture.build_flows, unchanged."""
        if self._flows is None or self._flows_for != len(self.packets):
            self._flows = capture.build_flows(self.packets)
            self._flows_for = len(self.packets)
        return self._flows

    def _as_run(self, connections: pd.DataFrame, capture_seconds: float) -> runs.Run:
        """An ordinary in-memory run, exactly what runs.load_run would build."""
        return runs.Run(
            run_id=self.session,
            scenario="capture",
            connections=connections,
            device_names=list(self.device_names),
            devices=[{"name": n, "kind": k} for n, k in self.devices.items()],
            window_seconds=self.window_seconds,
            capture_seconds=int(round(capture_seconds)),
            baseline_seconds=self.baseline_seconds,
            baseline_windows=self.baseline_windows,
        )

    def _analyse(self, final: bool) -> None:
        """
        Run the unchanged pipeline on everything up to the last closed minute
        (or on everything, at STOP).
        """
        started = time.perf_counter()
        flows = self.flows()
        now = self.now_seconds or 0.0
        if final:
            used = flows
            capture_seconds = float(flows["t"].max()) if len(flows) else 0.0
        else:
            used = flows[flows["t"] < self.closed_windows * self.window_seconds]
            used = used.reset_index(drop=True)
            capture_seconds = self.closed_windows * self.window_seconds

        self.run = self._as_run(used, capture_seconds)
        self.detection = detect.detect_run(self.run)
        self.result = attribute.attribute_run(self.run, self.detection)

        # The brief is presentation, not the method: if it fails the verdict
        # still stands, so a failure here is recorded and the engine goes on.
        self.brief = None
        if self.result.ranking:
            try:
                evidence = report.build_evidence(self.run, self.detection, self.result)
                self.brief = {
                    "source": "template",
                    "brief": report.template_brief(evidence, self.run,
                                                   self.result).model_dump(),
                }
            except Exception as exc:
                self.brief = {"source": "failed", "error": str(exc)[:300]}

        if self.detection.onsets and self.first_alert is None:
            self._record_first_alert(now, final)
        self._record_verdict(now)
        self.analysis_seconds = time.perf_counter() - started

    def _record_first_alert(self, now: float, final: bool) -> None:
        """
        Remember the first alert, once. The earliest the method could know is
        when the third abnormal minute (third ROW, as detect.find_onset counts
        them) of the first device to trip had closed.
        """
        closed_at = None
        first_device = None
        for device, onset_w in self.detection.onset_windows.items():
            scored = sorted(w for w in self.detection.scores[device] if w >= onset_w)
            third = scored[min(detect.CONSECUTIVE, len(scored)) - 1]
            moment = (third + 1) * self.window_seconds + self.grace_seconds
            if closed_at is None or moment < closed_at or \
                    (moment == closed_at and device < first_device):
                closed_at, first_device = moment, device
        start = self.capture_start_epoch
        self.first_alert = {
            "device": first_device,
            "onset_seconds": self.detection.onsets[first_device],
            "closed_seconds": closed_at,
            "raised_seconds": now,
            "closed_epoch": start + closed_at,
            "raised_epoch": start + now,
            "found_at_stop": bool(final),
        }

    def _record_verdict(self, now: float) -> None:
        """Log the verdict whenever it changes, with the capture time it changed."""
        if not self.detection.onsets:
            return
        r = self.result
        key = (r.named, r.abstained, tuple(r.ranking), r.confidence_percent,
               tuple(sorted(self.detection.onsets.items())))
        if key == self._last_verdict_key:
            return
        self._last_verdict_key = key
        self.verdict_changes.append({
            "seconds": now,
            "epoch": self.capture_start_epoch + now,
            "named": r.named,
            "abstained": r.abstained,
            "confidence_percent": r.confidence_percent,
            "ranking": list(r.ranking),
            "onsets": dict(self.detection.onsets),
            "final": self.stopped,
        })

    def _log_phase(self, phase: str) -> None:
        if self.phase_log and self.phase_log[-1]["phase"] == phase:
            return
        now = self.now_seconds
        self.phase_log.append({
            "phase": phase,
            "seconds": now,
            "epoch": None if now is None else self.capture_start_epoch + now,
        })
        self.phase = phase

    def _decide_phase(self) -> str:
        if self.stopped:
            return STOPPED
        if not self.packets:
            return WAITING
        if self.closed_windows < self.baseline_windows:
            return LEARNING
        if self.first_alert is not None:
            return INCIDENT
        return MONITORING

    # ---- the two public calls -----------------------------------------

    def update(self) -> dict:
        """
        One cycle: read any newly finished files, re-analyse if a minute has
        closed since last time, write state.json. Safe to call as often as
        you like; it does real work only when something changed.
        """
        if self.stopped:
            return self.state()
        self.ingest(final=False)
        self.closed_windows = closed_window_count(self.now_seconds, self.window_seconds,
                                                  self.grace_seconds)
        if self.closed_windows >= self.baseline_windows and \
                self.closed_windows != self.analysed_windows:
            self._analyse(final=False)
            self.analysed_windows = self.closed_windows
        self._log_phase(self._decide_phase())
        self.cycles.append((self.now_seconds, self.phase))
        state = self.state()
        self.write()
        return state

    def finish(self, save: bool = True, force: bool = False) -> dict:
        """
        STOP: read every remaining file, including the newest, make the final
        pass over the whole capture (the offline analysis), save it as
        data/<session>.parquet + .meta.json, and write the final state.
        """
        if self.stopped:
            return self.state()
        self.ingest(final=True)
        self.stopped = True
        self.closed_windows = closed_window_count(self.now_seconds, self.window_seconds,
                                                  self.grace_seconds)
        if self.packets:
            self._analyse(final=True)
            self.analysed_windows = self.closed_windows
            if save:
                self.save(force=force)
        self._log_phase(STOPPED)
        self.cycles.append((self.now_seconds, self.phase))
        state = self.state()
        self.write()
        return state

    def save(self, force: bool = False):
        """
        Save the session as an ordinary captured run, so the replay dashboard
        and evaluate.py can open it. capture.save_run writes both files; the
        live-only facts (wall-clock start, files read, problems) are added to
        the meta afterwards rather than by changing save_run.
        """
        parquet_file, meta_file, meta = capture.save_run(
            self.flows(), self.session, pcap_path=self.folder,
            baseline_seconds=self.baseline_seconds,
            window_seconds=self.window_seconds,
            data_dir=self.data_dir, force=force,
        )
        meta["capture_start_epoch"] = self.capture_start_epoch
        meta["live"] = {
            "files_read": len(self.files_read),
            "packets": len(self.packets),
            "problems": self.problems,
            "first_alert": self.first_alert,
            "grace_seconds": self.grace_seconds,
        }
        meta_file.write_text(json.dumps(json_safe(meta), indent=2), encoding="utf-8")
        self.saved = (parquet_file, meta_file)
        return self.saved

    # ---- what the page reads -----------------------------------------

    def state(self) -> dict:
        """Everything the live page needs, as plain data (plan section 6)."""
        now = self.now_seconds
        start = self.capture_start_epoch
        flows = self.flows() if self.packets else None
        seen = sorted(set(flows["src"]) & set(self.device_names)) if flows is not None else []

        det, res = self.detection, self.result
        threshold = det.threshold if det is not None else detect.THRESHOLD
        devices = {}
        for name in self.device_names:
            scores = det.scores.get(name, {}) if det is not None else {}
            onset = det.onsets.get(name) if det is not None else None
            devices[name] = {
                "kind": self.devices[name],
                "seen": name in seen,
                "latest_score": scores[max(scores)] if scores else None,
                "strikes": self._strikes(name),
                "onset": onset,
                "onset_epoch": None if onset is None else start + onset,
                "scores_by_window": dict(sorted(scores.items())),
                "skipped": bool(det is not None and name in det.skipped),
            }

        baseline_remaining = None
        if now is not None:
            baseline_remaining = max(0.0, self.baseline_seconds + self.grace_seconds - now)

        alert = self.first_alert or {}
        return {
            "session": self.session,
            "phase": self.phase,
            "updated_epoch": time.time(),
            "capture_start_epoch": start,
            "now_seconds": now,
            "now_epoch": None if now is None else start + now,
            "baseline_seconds": self.baseline_seconds,
            "baseline_windows": self.baseline_windows,
            "baseline_remaining_seconds": baseline_remaining,
            "window_seconds": self.window_seconds,
            "grace_seconds": self.grace_seconds,
            "closed_windows": self.closed_windows,
            "consecutive": detect.CONSECUTIVE,
            "files_read": len(self.files_read),
            "packets": len(self.packets),
            "flows": 0 if flows is None else int(len(flows)),
            "devices_seen": seen,
            "devices": devices,
            "threshold": threshold,
            "onsets": dict(det.onsets) if det is not None else {},
            "ranking": list(res.ranking) if res is not None else [],
            "named": res.named if res is not None else None,
            "abstained": bool(res.abstained) if res is not None else False,
            "shortlist": list(res.shortlist) if res is not None else [],
            "confidence_percent": res.confidence_percent if res is not None else None,
            "path": list(res.path) if res is not None else [],
            "edges": res.edge_evidence() if res is not None else [],
            "report": self.brief or {},
            "first_alert": self.first_alert,
            "first_alert_epoch": alert.get("raised_epoch"),
            "first_alert_closed_epoch": alert.get("closed_epoch"),
            "contained_epoch": None,        # Step 18
            "verdict_changes": self.verdict_changes,
            "phase_log": self.phase_log,
            "problems": self.problems,
            "analysis_seconds": self.analysis_seconds,
            "saved_run": None if self.saved is None else self.session,
        }

    def _strikes(self, name: str) -> int:
        """
        The strike meter: how many abnormal minutes in a row this device has
        right now, counted the way detect.find_onset counts them (scored rows
        after the baseline), capped at CONSECUTIVE. A device with an onset
        shows the full count. This is a "watching" signal only: one or two
        strikes name nobody (see docs/LIVE_PLAN.md section 7 for why).
        """
        det = self.detection
        if det is None or name not in det.scores:
            return 0
        if name in det.onsets:
            return detect.CONSECUTIVE
        count = 0
        for w in sorted(det.scores[name], reverse=True):
            if w < self.baseline_windows or det.scores[name][w] <= det.threshold:
                break
            count += 1
        return min(count, detect.CONSECUTIVE)

    def write(self) -> Path:
        self.folder.mkdir(parents=True, exist_ok=True)
        path = self.folder / STATE_FILE
        write_state(path, self.state())
        return path


# --------------------------------------------------------------------------
# Cutting a recorded capture into ring-style files (for --replay)
# --------------------------------------------------------------------------

def split_capture(pcap_path, out_dir, seconds: int = SEGMENT_SECONDS,
                  editcap: str | None = None, tshark: str | None = None) -> list:
    """
    Cut one capture into consecutive files of `seconds` each, named like
    dumpcap's ring files, and return them oldest first.

    editcap -i does this in one pass. If editcap is missing, tshark is used
    instead, one display-filtered pass per slice - slower, same result.
    Measured on the real captures: reading the slices one by one gives exactly
    the same packets and flows as reading the original file.
    """
    pcap_path, out_dir = Path(pcap_path), Path(out_dir)
    if not pcap_path.exists():
        raise FileNotFoundError("no capture file at %s" % pcap_path)
    out_dir.mkdir(parents=True, exist_ok=True)
    for old in ring_files(out_dir):
        old.unlink()

    binary = find_editcap(editcap)
    if binary:
        result = subprocess.run(
            [binary, "-i", str(int(seconds)), str(pcap_path), str(out_dir / "ring.pcapng")],
            capture_output=True, text=True)
        if result.returncode != 0:
            raise RuntimeError("editcap failed: %s" % result.stderr.strip())
        return ring_files(out_dir)

    # No editcap: slice with tshark on frame.time_relative.
    tshark = capture.find_tshark(tshark)
    probe = subprocess.run([tshark, "-r", str(pcap_path), "-T", "fields",
                            "-e", "frame.time_relative"], capture_output=True, text=True)
    if probe.returncode != 0:
        raise RuntimeError("tshark failed reading %s: %s" % (pcap_path, probe.stderr.strip()))
    last = max((float(x) for x in probe.stdout.split() if x.strip()), default=0.0)
    for k in range(int(last // seconds) + 1):
        lo, hi = k * seconds, (k + 1) * seconds
        out = out_dir / ("ring_%05d.pcapng" % k)
        result = subprocess.run(
            [tshark, "-r", str(pcap_path), "-F", "pcapng", "-w", str(out),
             "-Y", "frame.time_relative >= %d && frame.time_relative < %d" % (lo, hi)],
            capture_output=True, text=True)
        if result.returncode != 0:
            raise RuntimeError("tshark failed slicing %s: %s" % (pcap_path, result.stderr.strip()))
    return ring_files(out_dir)


def _prepare_folder(folder: Path, force: bool) -> None:
    """A session folder must start empty of capture files and old state."""
    folder.mkdir(parents=True, exist_ok=True)
    leftovers = ring_files(folder) + [p for p in (folder / STATE_FILE, folder / STOP_FILE)
                                      if p.exists()]
    if leftovers and not force:
        raise FileExistsError(
            "%s already holds %d file(s) from an earlier session. Pick a new\n"
            "  --session name, or pass --force to clear it." % (folder, len(leftovers)))
    for p in leftovers:
        p.unlink()


def replay(pcap_path, session: str, folder=None, baseline_seconds: float = DEFAULT_BASELINE,
           speed: float = 20.0, data_dir: Path = runs.DATA_DIR, force: bool = False,
           save: bool = True, editcap: str | None = None, tshark: str | None = None,
           on_cycle=None, quiet: bool = False) -> LiveSession:
    """
    Play a recorded capture through the live path, as if it were happening now.

    The capture is cut into 10-second files in <folder>/replay_source/, then
    the files are dropped into the session folder one at a time - the same
    folder-watching code, the same newest-file rule, the same closed-window
    rule as a live session. speed=20 means one 10-second file every 0.5 s;
    speed=0 means as fast as the engine can go (used by the tests).

    on_cycle(session, state) is called after every update, for tests.
    """
    folder = Path(folder) if folder else LIVE_DIR / session
    _prepare_folder(folder, force)
    if not force and runs.data_path(session, data_dir).exists() and save:
        raise FileExistsError("data/%s.parquet already exists; pick a new --session "
                              "or pass --force" % session)

    sources = split_capture(pcap_path, folder / REPLAY_SOURCE, editcap=editcap, tshark=tshark)
    live = LiveSession(folder, baseline_seconds=baseline_seconds, session=session,
                       tshark=tshark, data_dir=data_dir)
    gap = SEGMENT_SECONDS / speed if speed and speed > 0 else 0.0
    last_print = None

    for source in sources:
        # Copy under a non-capture name, then rename: the file appears whole,
        # just as a finished dumpcap file would.
        part = folder / (source.name + ".part")
        shutil.copyfile(source, part)
        os.replace(part, folder / source.name)
        state = live.update()
        if on_cycle:
            on_cycle(live, state)
        if not quiet:
            last_print = _print_status(live, last_print)
        if gap:
            time.sleep(gap)

    (folder / STOP_FILE).write_text("stopped by --replay\n", encoding="utf-8")
    state = live.finish(save=save, force=force)
    if on_cycle:
        on_cycle(live, state)
    if not quiet:
        _print_status(live, None)
    return live


# --------------------------------------------------------------------------
# The live loop
# --------------------------------------------------------------------------

def run_live(session: str, folder=None, baseline_seconds: float = DEFAULT_BASELINE,
             data_dir: Path = runs.DATA_DIR, poll_seconds: float = POLL_SECONDS,
             quiet_seconds: float = QUIET_SECONDS, force: bool = False,
             tshark: str | None = None) -> LiveSession:
    """
    Watch the session folder until STOP, Ctrl+C, or 30 s with no new file.
    """
    folder = Path(folder) if folder else LIVE_DIR / session
    _prepare_folder(folder, force)
    if not force and runs.data_path(session, data_dir).exists():
        raise FileExistsError("data/%s.parquet already exists; pick a new --session "
                              "or pass --force" % session)

    live = LiveSession(folder, baseline_seconds=baseline_seconds, session=session,
                       tshark=tshark, data_dir=data_dir)
    live.write()
    print("\n  watching %s" % folder)
    print("  start the capture in an Administrator PowerShell:")
    print("    python -m src.live_capture --session %s   (Step 16b), or" % session)
    print("    dumpcap -i <wired adapter> -b duration:%d -w \"%s\"\n"
          % (SEGMENT_SECONDS, folder / "ring.pcapng"))
    print("  stop with Ctrl+C here, or create a file named STOP in that folder.\n")

    last_count, last_change = 0, time.monotonic()
    last_print = None
    reason = "stopped"
    try:
        while True:
            live.update()
            last_print = _print_status(live, last_print)
            count = len(ring_files(folder))
            if count != last_count:
                last_count, last_change = count, time.monotonic()
            if (folder / STOP_FILE).exists():
                reason = "STOP file found"
                break
            if count and time.monotonic() - last_change > quiet_seconds:
                reason = "no new capture file for %d s" % quiet_seconds
                break
            time.sleep(poll_seconds)
    except KeyboardInterrupt:
        reason = "Ctrl+C"

    print("\n  stopping (%s): reading the last file and making the final pass..." % reason)
    live.finish(force=force)
    _print_status(live, None)
    return live


def _print_status(live: LiveSession, last):
    """One console line whenever the phase or the number of closed minutes changes."""
    key = (live.phase, live.closed_windows, len(live.problems))
    if key == last:
        return last
    now = live.now_seconds
    where = "-" if now is None else "%s (+%ds)" % (_clock(live.capture_start_epoch + now), now)
    line = "  %-10s %s  minutes closed %d/%d baseline  packets %d" % (
        live.phase, where, live.closed_windows, live.baseline_windows, len(live.packets))
    if live.result is not None and live.detection is not None and live.detection.onsets:
        r = live.result
        line += "  | %s, confidence %d%%" % (
            "ABSTAIN %s" % r.shortlist if r.abstained else "origin %s" % r.named,
            r.confidence_percent)
    print(line)
    if live.phase == STOPPED and live.saved:
        print("  saved %s" % live.saved[0])
        print("        %s" % live.saved[1])
    return key


# --------------------------------------------------------------------------
# Command line
# --------------------------------------------------------------------------

def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description="Analyse a capture while it is still being recorded.")
    parser.add_argument("--session", required=True,
                        help="session name; also the run id it is saved as, e.g. live_session_01")
    parser.add_argument("--folder", default=None,
                        help="folder the capture files appear in (default pcap/live/<session>)")
    parser.add_argument("--baseline", type=float, default=DEFAULT_BASELINE,
                        help="baseline length in seconds, whole minutes (default %d)"
                             % DEFAULT_BASELINE)
    parser.add_argument("--replay", default=None,
                        help="play a recorded .pcapng through the live path instead")
    parser.add_argument("--speed", type=float, default=20.0,
                        help="replay speed; 20 = one 10-s file every 0.5 s, 0 = flat out")
    parser.add_argument("--poll", type=float, default=POLL_SECONDS,
                        help="seconds between looks at the folder (live mode)")
    parser.add_argument("--quiet-stop", type=float, default=QUIET_SECONDS,
                        help="stop when no new file has appeared for this long")
    parser.add_argument("--force", action="store_true",
                        help="clear an existing session folder / overwrite data/<session>")
    parser.add_argument("--tshark", default=None)
    parser.add_argument("--editcap", default=None)
    args = parser.parse_args(argv)

    try:
        if args.replay:
            live = replay(args.replay, args.session, folder=args.folder,
                          baseline_seconds=args.baseline, speed=args.speed,
                          force=args.force, editcap=args.editcap, tshark=args.tshark)
        else:
            live = run_live(args.session, folder=args.folder,
                            baseline_seconds=args.baseline, poll_seconds=args.poll,
                            quiet_seconds=args.quiet_stop, force=args.force,
                            tshark=args.tshark)
    except (FileNotFoundError, FileExistsError, ValueError, RuntimeError) as exc:
        print("\n  %s\n" % exc, file=sys.stderr)
        return 1

    if live.problems:
        print("\n  %d capture file(s) were skipped - see 'problems' in %s"
              % (len(live.problems), live.folder / STATE_FILE))
    print()
    return 0


if __name__ == "__main__":
    sys.exit(main())
