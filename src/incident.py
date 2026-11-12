"""
THE INCIDENT REPORT - everything about one incident, in one place, built from
the measurements alone (Step 19).

WHAT THIS FILE DOES
-------------------
The pipeline ends with a run, a detection and an attribution. report.py turns
those into a short brief, optionally worded by a language model. This file
turns the same three objects into the COMPLETE report an operator works from,
in eight sections:

    1. What happened         one sentence
    2. When                  first unusual connection, each abnormal minute,
                             the alert, and time-to-detect
    3. Where it started      the named device, confidence, the full ranking,
                             and the devices that stayed normal
    4. How                   the new behaviour, MEASURED: destination+port
                             pairs the device used 3 or more times after the
                             baseline and never during it, with count, first
                             time, typical gap and typical size
    5. Why we believe it     each minute's score against the line, which
                             measurements moved, the evidence connection ids
    6. Impact                the affected devices and what they talked to
    7. What to do            contain / preserve / eradicate / recover / verify
    8. What we are not sure about

plus the CONTAINED check (section 7's "verify"): once the named device has
made no connection to the section-4 destinations for 90 seconds, the incident
is confirmed contained, with the time.

WHY NO LANGUAGE MODEL IS NEEDED
-------------------------------
Every sentence here is assembled from numbers the pipeline already produced:
nothing is generated, so nothing can be invented and nothing can fail in a
demo. The report is complete with the model switched off. A model's wording
can be ADDED (wording_from_brief): only a brief that passed report.py's
validator is used, and if there is none the report simply says so.

WHY "SPREAD" IS NOT ALWAYS SAID
-------------------------------
The real-lab attack is one compromised board. The old template said "and
spread to other devices" every time - wrong in 10 of the 12 real runs, where
only the board was flagged. Here the word is used only when more than one
device was flagged (the same fix is made to report.template_brief).

WHAT THIS FILE DOES NOT DO
--------------------------
It decides nothing: no detection, no ranking - those come in. It never reads
the file that says which device was really attacked (that is evaluate.py's
job alone), so "time to detect" here is measured from the first unusual
CONNECTION seen in the traffic, not from the moment the attack was launched.
It never contacts or blocks anything: containment is recommended, the
operator does it, and this file only confirms it from the traffic.

USAGE
-----
    python -m src.incident rehearsal_02                   # print it, write reports/rehearsal_02.html
    python -m src.incident live_batch_05 --no-html
    python -m src.incident rehearsal_02 --pcap pcap/live/rehearsal_02.pcapng   # + IP addresses, SHA-256
    python -m src.incident rehearsal_02 --llm local       # add a validated model wording, if any
"""

from __future__ import annotations

import argparse
import hashlib
import html
import json
import sys
from datetime import datetime
from pathlib import Path

import numpy as np
import pandas as pd

from src import attribute, capture, detect, features, runs, windows

ROOT = capture.ROOT
REPORTS_DIR = ROOT / "reports"

# Section 4: a destination+port pair counts as the new behaviour if the device
# used it at least this many times after the baseline and never during it.
# Three, because one or two connections can be anything (a lookup, a retry);
# a beacon repeats.
PATTERN_MIN_COUNT = 3

# The CONTAINED check: this long without a single connection to the new
# destinations. The beacon ticks every 30 s, so 90 s is three missed beats -
# not a pause, a stop.
CONTAINED_QUIET_SECONDS = 90.0

# The live engine's grace for a closed minute (live.GRACE_SECONDS). Repeated
# rather than imported because live.py imports this file.
GRACE_SECONDS = 5.0

REPORT_VERSION = 1

# Plain words for the measurements, for "which measurements moved".
FEATURE_WORDS = {
    "bytes_out": "bytes sent per minute",
    "bytes_in": "bytes received per minute",
    "n_conn": "connections per minute",
    "n_dst": "different destinations per minute",
    "n_new_ext": "new outside addresses per minute",
    "n_peer": "connections to other lab devices per minute",
    "iat_reg": "timing regularity (higher = more machine-like)",
}
assert set(FEATURE_WORDS) == set(features.FEATURE_COLUMNS)

# Well-known ports, so "broker:1883" can be read as "MQTT" by a non-expert.
PORT_WORDS = {53: "DNS", 67: "DHCP", 68: "DHCP", 80: "HTTP", 123: "NTP", 443: "HTTPS",
              1883: "MQTT", 5353: "mDNS", 5355: "LLMNR", 1900: "SSDP"}


# --------------------------------------------------------------------------
# Time, written the same way everywhere
# --------------------------------------------------------------------------

def clock_text(seconds, start_epoch=None) -> str:
    """Wall-clock HH:MM:SS when the capture's start is known, else capture time."""
    if seconds is None:
        return "-"
    if start_epoch is not None:
        return datetime.fromtimestamp(float(start_epoch) + float(seconds)).strftime("%H:%M:%S")
    s = int(seconds)
    return "%02d:%02d:%02d" % (s // 3600, (s % 3600) // 60, s % 60)


def duration_text(seconds) -> str:
    """3 min 05 s."""
    if seconds is None:
        return "-"
    seconds = max(0, int(round(float(seconds))))
    if seconds < 60:
        return "%d s" % seconds
    return "%d min %02d s" % (seconds // 60, seconds % 60)


def _epoch(seconds, start_epoch):
    return None if seconds is None or start_epoch is None else float(start_epoch) + float(seconds)


def endpoint_label(dst, dport) -> str:
    """broker:4444; a flow with no port (ARP, ICMP) is just 'broker (no port)'."""
    return "%s:%d" % (dst, int(dport)) if int(dport) else "%s (no port)" % dst


# --------------------------------------------------------------------------
# The moment the method could first know
# --------------------------------------------------------------------------

def alert_moment(detection: detect.Detection, window_seconds: int,
                 grace_seconds: float = GRACE_SECONDS):
    """
    (device, seconds): the first device to trip and the capture time at which
    its third abnormal minute (third scored ROW from the onset, as
    detect.find_onset counts them) had closed, plus the grace. None if no
    device has an onset. The live engine records its alert with this, and an
    offline report uses it as "the earliest the alert could have been raised".
    """
    best = None
    for device, onset_w in sorted(detection.onset_windows.items()):
        scored = sorted(w for w in detection.scores.get(device, {}) if w >= onset_w)
        if not scored:
            continue
        third = scored[min(detection.consecutive, len(scored)) - 1]
        moment = (third + 1) * window_seconds + grace_seconds
        if best is None or moment < best[1]:
            best = (device, moment)
    return best


# --------------------------------------------------------------------------
# Section 4 - the new behaviour, measured
# --------------------------------------------------------------------------

def new_patterns(connections: pd.DataFrame, device: str, baseline_seconds: float,
                 min_count: int = PATTERN_MIN_COUNT, start_epoch=None) -> list:
    """
    The destination+port pairs `device` opened at least min_count times after
    the baseline and never during it, most-used first. Each with its count,
    first and last time, typical gap between connections (median), typical
    bytes sent and received (median, wire bytes) and the first connection ids.
    Only flows WITH a port count: ARP and ICMP (port 0) are how a device finds
    its way around the network, not a service it connects to, and a board that
    rejoins ARPs a lot - that must not be presented as the attack.
    """
    if connections is None or len(connections) == 0 or device is None:
        return []
    mine = connections[(connections["src"] == device) & (connections["dport"] != 0)]
    before = mine[mine["t"] < baseline_seconds]
    after = mine[mine["t"] >= baseline_seconds]
    known = set(zip(before["dst"], before["dport"].astype(int)))
    found = []
    for (dst, dport), group in after.groupby(["dst", "dport"], sort=True):
        if (dst, int(dport)) in known or len(group) < min_count:
            continue
        group = group.sort_values("t")
        times = group["t"].to_numpy(dtype=float)
        gap = float(np.median(np.diff(times))) if len(times) > 1 else None
        found.append({
            "dst": dst,
            "dport": int(dport),
            "label": endpoint_label(dst, dport),
            "count": int(len(group)),
            "first_seconds": float(times[0]),
            "first_epoch": _epoch(times[0], start_epoch),
            "first_id": str(group["conn_id"].iloc[0]),
            "last_seconds": float(times[-1]),
            "typical_gap_seconds": gap,
            "typical_bytes_out": int(round(float(group["bytes_out"].median()))),
            "typical_bytes_in": int(round(float(group["bytes_in"].median()))),
            "conn_ids": [str(c) for c in group["conn_id"].head(5)],
        })
    return sorted(found, key=lambda p: (-p["count"], p["first_seconds"], p["label"]))


def pattern_sentence(device: str, pattern: dict, start_epoch=None) -> str:
    gap = pattern["typical_gap_seconds"]
    return ("%s made %d connections to %s%s, ~%d bytes each, the first at %s - "
            "it never did this during the baseline."
            % (device, pattern["count"], pattern["label"],
               " every ~%d s" % round(gap) if gap is not None else "",
               pattern["typical_bytes_out"],
               clock_text(pattern["first_seconds"], start_epoch)))


# --------------------------------------------------------------------------
# Section 5 - which measurements moved
# --------------------------------------------------------------------------

def measurements_moved(feature_table: pd.DataFrame, detection: detect.Detection,
                       device: str, baseline_windows: int, minutes: list) -> list:
    """
    For the abnormal minutes of `device`: each measurement's normal value (the
    detector's own baseline median, rejoin minutes left out exactly as it left
    them out), its median during those minutes, and how far that is in the
    detector's weighted units. Those that moved by at least one unit, furthest
    first. The second opinion (IsolationForest) judges the seven together and
    cannot be split per measurement; when it is the louder witness the list
    can be short or empty, and the report says so.
    """
    if feature_table is None or not minutes:
        return []
    group = feature_table[feature_table["dev"] == device].sort_values("w")
    left_out = sorted(detection.rejoins.get(device, {}))
    baseline = group[(group["w"] < baseline_windows) & ~group["w"].isin(left_out)]
    during = group[group["w"].isin(minutes)]
    if baseline.empty or during.empty:
        return []
    middle, spread = detect.baseline_reference(baseline)
    out = []
    for column in features.FEATURE_COLUMNS:
        now = float(during[column].median())
        units = abs(now - float(middle[column])) / float(spread[column]) \
            * detect.DIAG[column] / detect.WEIGHT_SCALE
        if units >= 1.0:
            out.append({"feature": column, "words": FEATURE_WORDS[column],
                        "normal": round(float(middle[column]), 2), "during": round(now, 2),
                        "units": round(float(units), 1)})
    return sorted(out, key=lambda m: -m["units"])


# --------------------------------------------------------------------------
# The CONTAINED check
# --------------------------------------------------------------------------

def containment_status(connections: pd.DataFrame, device, patterns: list,
                       now_seconds, start_epoch=None, alert_seconds=None,
                       quiet_needed: float = CONTAINED_QUIET_SECONDS) -> dict:
    """
    Has the named device stopped? Watches only the section-4 destinations
    (what the attack does), in ALL the traffic read so far - not just the
    closed minutes - because this is about the newest packets. Contained once
    there has been no such connection for quiet_needed seconds AND the alert
    has been raised (an incident has to exist before it can be contained).
    """
    labels = [p["label"] for p in patterns]
    status = {"available": bool(device and patterns), "device": device, "watching": labels,
              "quiet_needed_seconds": quiet_needed, "last_seen_seconds": None,
              "last_seen_epoch": None, "last_seen_id": None, "quiet_seconds": None,
              "contained": False, "contained_seconds": None, "contained_epoch": None}
    if not status["available"] or now_seconds is None or connections is None:
        return status
    pairs = {(p["dst"], p["dport"]) for p in patterns}
    mine = connections[connections["src"] == device]
    hits = mine[[(d, int(p)) in pairs for d, p in zip(mine["dst"], mine["dport"])]]
    if hits.empty:
        return status
    last = hits.sort_values("t").iloc[-1]
    last_t = float(last["t"])
    quiet = float(now_seconds) - last_t
    status.update(last_seen_seconds=last_t, last_seen_epoch=_epoch(last_t, start_epoch),
                  last_seen_id=str(last["conn_id"]), quiet_seconds=quiet)
    if quiet >= quiet_needed and alert_seconds is not None:
        moment = max(last_t + quiet_needed, float(alert_seconds))
        status.update(contained=True, contained_seconds=moment,
                      contained_epoch=_epoch(moment, start_epoch))
    return status


def containment_line(c: dict, start_epoch=None) -> str:
    if not c or not c.get("available"):
        return ("The containment check needs the new connections of section 4; "
                "none have been identified yet.")
    watching = ", ".join(c["watching"])
    needed = int(c["quiet_needed_seconds"])
    if c.get("contained"):
        return ("CONTAINED at %s: %s has made no connection to %s since %s (%s)."
                % (clock_text(c["contained_seconds"], start_epoch), c["device"], watching,
                   clock_text(c["last_seen_seconds"], start_epoch),
                   c.get("last_seen_id") or "-"))
    if c.get("last_seen_seconds") is None:
        return "Watching %s for connections to %s." % (c["device"], watching)
    return ("NOT YET CONTAINED: the last connection from %s to %s was at %s, %s ago. "
            "Contained is confirmed after %d s with none."
            % (c["device"], watching, clock_text(c["last_seen_seconds"], start_epoch),
               duration_text(c["quiet_seconds"]), needed))


# --------------------------------------------------------------------------
# Preserving the evidence
# --------------------------------------------------------------------------

def sha256_of(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def write_checksums(folder: Path, names: list, out_name: str = "SHA256SUMS.txt") -> dict:
    """
    SHA-256 of each named file in folder, written as <folder>/SHA256SUMS.txt
    (the format `sha256sum -c` reads). Returns {file, files, sha256} where
    sha256 is the digest of that list itself - one fingerprint for the lot.
    """
    folder = Path(folder)
    lines = ["%s  %s" % (sha256_of(folder / n), n) for n in names if (folder / n).is_file()]
    out = folder / out_name
    text = "\n".join(lines) + ("\n" if lines else "")
    out.write_text(text, encoding="utf-8", newline="\n")
    return {"file": str(out), "files": len(lines),
            "sha256": hashlib.sha256(text.encode("utf-8")).hexdigest()}


# --------------------------------------------------------------------------
# The report
# --------------------------------------------------------------------------

def _confidence_words(result: attribute.Attribution) -> tuple:
    if result.abstained:
        return "cannot determine", ("the analysis could not separate the top candidates "
                                    "(gap %d%%)" % result.confidence_percent)
    c = result.confidence
    if c >= 0.50:
        return "high", "no other device came close"
    if c >= 0.25:
        return "medium", "another device is a plausible alternative"
    return "low", "the runner-up is nearly as likely"


def build_incident(run: runs.Run, detection: detect.Detection,
                   result: attribute.Attribution, *,
                   capture_start_epoch=None, now_seconds=None, first_alert=None,
                   addresses=None, evidence=None, containment=None,
                   feature_table=None, session_folder=None) -> dict:
    """
    The whole report, as plain data (JSON-safe). run/detection/result are the
    pipeline's own objects, unchanged. The keyword arguments are what only the
    caller can know:

      capture_start_epoch  wall-clock time of the first packet (times are then
                           shown as clock times)
      now_seconds          how far the capture has got (default: the run's end)
      first_alert          the live engine's alert record; without it the
                           earliest possible alert moment is used
      addresses            device -> last IP address seen (from the packets)
      evidence             {folder, files, sha256, ...} about the capture files
      containment          a containment_status() dict, if already worked out
      feature_table        features.features_for_run(run), if already built
      session_folder       where the session's capture files are (for section 7)

    With no device flagged the report says so and has no incident sections.
    """
    start = capture_start_epoch
    when = lambda s: clock_text(s, start)  # noqa: E731
    connections = run.connections
    if now_seconds is None:
        now_seconds = float(connections["t"].max()) if len(connections) else 0.0
    flagged = detection.devices_by_onset()
    seen = sorted(set(connections["src"]) & set(run.device_names)) if len(connections) else []

    report = {
        "version": REPORT_VERSION,
        "session": run.run_id,
        "capture_start_epoch": start,
        "now_seconds": float(now_seconds),
        "now_epoch": _epoch(now_seconds, start),
        "baseline_seconds": run.baseline_seconds,
        "threshold": detection.threshold,
        "consecutive": detection.consecutive,
        "status": "no incident",
        "flagged": flagged,
        "wording": {"source": "deterministic",
                    "note": "built from the measurements; no language model was used"},
    }
    if not flagged or not result.ranking:
        report["what_happened"] = {
            "sentence": "No incident: no device was abnormal for %d minutes in a row."
                        % detection.consecutive, "spread": False}
        return report

    named = None if result.abstained else result.named
    focus = named or result.ranking[0]
    spread = len(flagged) > 1
    label, label_why = _confidence_words(result)

    # ---- 4. how (first: everything else refers to it) ----------------------
    patterns = new_patterns(connections, focus, run.baseline_seconds, start_epoch=start)
    how = {"device": focus, "patterns": patterns,
           "sentences": [pattern_sentence(focus, p, start) for p in patterns]}
    if not patterns:
        how["sentences"] = ["No destination+port was used %d or more times by %s after the "
                            "baseline that it had not also used before; its change is in "
                            "how much and how regularly it talked (section 5)."
                            % (PATTERN_MIN_COUNT, focus)]

    # ---- 1. what happened ------------------------------------------------
    others = [d for d in flagged if d != focus]
    if result.abstained:
        sentence = ("An attack was detected, but the starting device could not be told apart "
                    "between %s." % ", ".join(result.shortlist))
    else:
        behaviour = ("opened a new, repeating connection to %s" % patterns[0]["label"]
                     if patterns else "started behaving differently from its normal pattern")
        sentence = "%s was compromised: from %s it %s." % (
            named, when(patterns[0]["first_seconds"] if patterns
                        else detection.onsets[named]), behaviour)
        sentence += (" The attack appears to have spread to %s." % ", ".join(others) if spread
                     else " No other device behaved abnormally.")
    report["what_happened"] = {"sentence": sentence, "spread": spread}

    # ---- 2. when ---------------------------------------------------------
    scores = detection.scores.get(focus, {})
    onset_w = detection.onset_windows.get(focus)
    abnormal = sorted(w for w, s in scores.items()
                      if onset_w is not None and w >= onset_w and s > detection.threshold)
    w_sec = run.window_seconds
    minute_rows = [{"window": int(w), "start_seconds": w * w_sec,
                    "start_epoch": _epoch(w * w_sec, start),
                    "text": "%s-%s" % (when(w * w_sec), when((w + 1) * w_sec)),
                    "score": round(float(scores[w]), 1)} for w in abnormal]
    if first_alert:
        alert_s = float(first_alert.get("raised_seconds"))
        closed_s = float(first_alert.get("closed_seconds"))
        alert_kind = "raised by the live engine"
    else:
        moment = alert_moment(detection, w_sec)
        alert_s = closed_s = moment[1] if moment else None
        alert_kind = "earliest possible (third abnormal minute closed)"
    first_unusual = patterns[0]["first_seconds"] if patterns else detection.onsets[focus]
    first_id = patterns[0]["first_id"] if patterns else None
    ttd = None if alert_s is None else alert_s - first_unusual
    report["when"] = {
        "first_unusual_seconds": first_unusual, "first_unusual_epoch": _epoch(first_unusual, start),
        "first_unusual_id": first_id,
        "onset_seconds": detection.onsets[focus], "onset_epoch": _epoch(detection.onsets[focus], start),
        "abnormal_minutes": minute_rows,
        "third_minute_closed_seconds": closed_s, "third_minute_closed_epoch": _epoch(closed_s, start),
        "alert_seconds": alert_s, "alert_epoch": _epoch(alert_s, start), "alert_kind": alert_kind,
        "time_to_detect_seconds": ttd,
        "sentence": ("First unusual connection at %s%s; first abnormal minute from %s; "
                     "alert at %s (%s) - %s after the first unusual connection."
                     % (when(first_unusual), " (%s)" % first_id if first_id else "",
                        when(detection.onsets[focus]), when(alert_s), alert_kind,
                        duration_text(ttd))),
    }

    # ---- 3. where it started ---------------------------------------------
    ranking = [{"position": i + 1, "device": d,
                "onset_seconds": detection.onsets.get(d),
                "onset_text": when(detection.onsets[d]) if d in detection.onsets else "-",
                "explanation": result.explain_rank(d)} for i, d in enumerate(result.ranking)]
    cleared = [d for d in run.device_names if d in detection.scores and d not in detection.onsets]
    not_judged = [d for d in run.device_names if d in detection.skipped and d in seen]
    unseen = [d for d in run.device_names if d not in seen]
    report["where"] = {
        "named": named, "abstained": bool(result.abstained), "shortlist": list(result.shortlist),
        "confidence_percent": result.confidence_percent, "confidence_label": label,
        "confidence_words": label_why, "ranking": ranking,
        "cleared": cleared, "not_judged": not_judged, "unseen": unseen,
        "sentence": (("%s, confidence %d%% (%s: %s)." % (named, result.confidence_percent,
                                                          label, label_why))
                     if named else "Not certain: %s." % label_why),
    }
    report["how"] = how

    # ---- 5. why we believe it ---------------------------------------------
    if feature_table is None:
        feature_table = features.features_for_run(run)
    after_onset = sorted(w for w in scores if onset_w is not None and w >= onset_w)
    moved = measurements_moved(feature_table, detection, focus, run.baseline_windows, abnormal)
    evidence_ids = []
    for p in patterns[:2]:
        evidence_ids += p["conn_ids"][:3]
    for e in result.edge_evidence():
        evidence_ids += [i for i in e["evidence_ids"][:2] if i not in evidence_ids]
    report["why"] = {
        "device": focus, "threshold": detection.threshold,
        "minutes": [{"window": int(w), "text": "%s-%s" % (when(w * w_sec), when((w + 1) * w_sec)),
                     "score": round(float(scores[w]), 1), "over": bool(scores[w] > detection.threshold)}
                    for w in after_onset],
        "moved": moved,
        "evidence_ids": evidence_ids[:8],
        "rejoins": {d: sorted(int(w) for w in ws) for d, ws in detection.rejoins.items()},
        "sentence": ("%s scored over the line (%.1f) in %d minutes in a row from %s; "
                     "a device is only flagged after %d." % (
                         focus, detection.threshold, _run_length(scores, onset_w, detection.threshold),
                         when(detection.onsets[focus]), detection.consecutive)),
    }

    # ---- 6. impact ---------------------------------------------------------
    reach = {}
    for dev in flagged:
        mine = connections[connections["src"] == dev]
        before = set(zip(mine[mine["t"] < run.baseline_seconds]["dst"],
                         mine[mine["t"] < run.baseline_seconds]["dport"].astype(int)))
        after = mine[mine["t"] >= detection.onsets[dev]]
        rows = []
        for (dst, dport), g in after.groupby(["dst", "dport"], sort=True):
            rows.append({"label": endpoint_label(dst, dport), "count": int(len(g)),
                         "new": (dst, int(dport)) not in before,
                         "what": PORT_WORDS.get(int(dport), "")})
        reach[dev] = sorted(rows, key=lambda r: (not r["new"], -r["count"], r["label"]))
    report["impact"] = {
        "affected": flagged, "reach": reach,
        "sentence": ("Affected: %s. %s" % (", ".join(flagged),
                     "Only one device behaved abnormally." if not spread else
                     "%d devices behaved abnormally." % len(flagged))),
    }

    # ---- 7. what to do -----------------------------------------------------
    report["containment"] = containment or containment_status(
        connections, named, patterns if named else [], now_seconds, start, alert_s)
    report["playbook"] = _playbook(run, named, result, patterns, addresses or {},
                                   evidence or {}, session_folder, report["containment"], start)
    report["status"] = "contained" if report["containment"].get("contained") else "incident"

    # ---- 8. what we are not sure about ---------------------------------------
    report["unsure"] = _unsure(result, label, label_why, spread, not_judged, unseen,
                               detection, report["containment"])
    return report


def _run_length(scores: dict, onset_w, threshold) -> int:
    if onset_w is None:
        return 0
    n = 0
    for w in sorted(w for w in scores if w >= onset_w):
        if scores[w] <= threshold:
            break
        n += 1
    return n


def _mac_of(device) -> str | None:
    for mac, name in capture.MAC_TO_NAME.items():
        if name == device:
            return mac
    return None


def _playbook(run, named, result, patterns, addresses, evidence, session_folder,
              containment, start) -> list:
    targets = [named] if named else list(result.shortlist)
    who = []
    for dev in targets:
        mac = _mac_of(dev) or "unknown MAC"
        ip = addresses.get(dev)
        who.append("%s (MAC %s%s)" % (dev, mac, ", last seen at %s" % ip if ip else
                                      ", IP not recorded - find it by MAC in the router's "
                                      "client list"))
    ports = ", ".join(p["label"] for p in patterns) if patterns else None
    steps = [{
        "step": "contain", "urgency": "now",
        "title": "Contain it now" if named else "Contain all three suspects now",
        "do": ["Isolate %s: pull its power, or block its MAC address on the router."
               % " and ".join(who)]
              + (["Its connections to %s should then stop." % ports] if ports else [])
              + ["Nothing is blocked automatically - the operator does this by hand."],
    }]
    folder = session_folder or evidence.get("folder")
    preserve = ["Do not delete or overwrite the capture: it is the evidence."]
    if folder:
        count = evidence.get("files")
        preserve.append("The capture is in %s%s." % (
            folder, " (%d file%s)" % (count, "" if count == 1 else "s") if count else ""))
    if evidence.get("sha256"):
        preserve.append("Fingerprint (SHA-256) of the file list %s: %s"
                        % (evidence.get("file", ""), evidence["sha256"]))
    elif session_folder:
        preserve.append("Their SHA-256 list is written to SHA256SUMS.txt in that folder "
                        "when the capture stops.")
    if session_folder:
        preserve.append("To make one file of them: mergecap -w %s.pcapng %s\\ring_*.pcapng"
                        % (session_folder, session_folder))
    steps.append({"step": "preserve", "urgency": "now", "title": "Preserve the evidence",
                  "do": preserve})
    steps.append({"step": "eradicate", "urgency": "today", "title": "Remove the attacker",
                  "do": ["Re-flash %s from the known-good firmware "
                         "(firmware/sensor/sensor.ino)." % " and ".join(targets),
                         "Change the Wi-Fi password and the broker credentials it holds; "
                         "assume anything stored on it is known."]})
    steps.append({"step": "recover", "urgency": "today", "title": "Reconnect safely",
                  "do": ["Reconnect it only after a fresh session has learned a clean "
                         "baseline (%d minutes) with it shown as normal."
                         % (run.baseline_seconds // 60)]})
    steps.append({"step": "verify", "urgency": "now", "title": "Confirm it stopped",
                  "do": ["The engine confirms containment by itself: CONTAINED once %s has "
                         "made no connection to %s for %d s."
                         % (named or "the device", ports or "the new destinations",
                            int(CONTAINED_QUIET_SECONDS)),
                         containment_line(containment, start)]})
    return steps


def _unsure(result, label, label_why, spread, not_judged, unseen, detection, containment) -> list:
    lines = ["Confidence in the starting device: %d%% - %s (%s)."
             % (result.confidence_percent, label, label_why)]
    if not spread:
        lines.append("Only one device was flagged. A device that only RECEIVES traffic, or "
                     "talks to another board directly, can look normal here.")
    lines.append("The capture point (the master laptop) sees only traffic to and from itself "
                 "plus broadcasts; traffic between two boards over Wi-Fi is invisible.")
    lines.append("The alert needs %d abnormal minutes in a row, so it comes 3-4 minutes after "
                 "an attack starts - by design, so one noisy minute never names a device."
                 % detection.consecutive)
    if not_judged:
        lines.append("Not judged (too little traffic during the baseline): %s."
                     % ", ".join(not_judged))
    if unseen:
        lines.append("Not seen in this capture at all: %s." % ", ".join(unseen))
    if containment.get("contained"):
        lines.append("A contained device that is unplugged stays marked abnormal: it is "
                     "offline / contained, not still attacking.")
    lines.append("The method can be confidently wrong; this report is a faithful account of "
                 "what it measured, not a guarantee.")
    return lines


def with_containment(report: dict, containment: dict) -> dict:
    """The report with a fresh containment check (status and section 7 follow it)."""
    if not report or report.get("status") == "no incident":
        return report
    report = dict(report)
    report["containment"] = containment
    report["status"] = "contained" if containment.get("contained") else "incident"
    start = report.get("capture_start_epoch")
    playbook = []
    for step in report.get("playbook", []):
        if step.get("step") == "verify":
            step = dict(step, do=list(step["do"][:-1]) + [containment_line(containment, start)])
        playbook.append(step)
    report["playbook"] = playbook
    return report


def wording_from_brief(report: dict, outcome) -> dict:
    """
    Add a language model's headline to section 1 - only if its brief passed
    report.py's validator (source "llm"). Otherwise the report keeps its
    deterministic wording and records that the model's text was not used.
    """
    report = dict(report)
    if outcome is not None and getattr(outcome, "source", None) == "llm":
        report["wording"] = {"source": "llm", "headline": outcome.brief.headline,
                             "note": "a language model's headline, checked against the "
                                     "evidence by report.validate_brief"}
    else:
        report["wording"] = {"source": "deterministic",
                             "note": "built from the measurements; the model's text was not "
                                     "used (%s)" % ("not validated" if outcome else "not asked")}
    return report


# --------------------------------------------------------------------------
# Rendering: text for the console, HTML for the file and the download
# --------------------------------------------------------------------------

def render_text(report: dict) -> str:
    start = report.get("capture_start_epoch")
    when = lambda s: clock_text(s, start)  # noqa: E731
    out = ["INCIDENT REPORT - %s   [%s]" % (report.get("session"), report.get("status", "").upper()),
           ""]
    out += ["1. WHAT HAPPENED", "   " + report["what_happened"]["sentence"]]
    if report.get("wording", {}).get("source") == "llm":
        out.append("   In other words: " + report["wording"]["headline"])
    if report.get("status") == "no incident":
        return "\n".join(out)
    w = report["when"]
    out += ["", "2. WHEN", "   " + w["sentence"]]
    for m in w["abnormal_minutes"]:
        out.append("   abnormal minute %s  score %.1f" % (m["text"], m["score"]))
    where = report["where"]
    out += ["", "3. WHERE IT STARTED", "   " + where["sentence"]]
    for r in where["ranking"]:
        out.append("   %d. %-10s abnormal from %s   %s"
                   % (r["position"], r["device"], r["onset_text"], r["explanation"]))
    if where["cleared"]:
        out.append("   stayed normal: %s" % ", ".join(where["cleared"]))
    out += ["", "4. HOW"] + ["   " + s for s in report["how"]["sentences"]]
    why = report["why"]
    out += ["", "5. WHY WE BELIEVE IT", "   " + why["sentence"]]
    out.append("   minutes: " + ", ".join("%s %.1f%s" % (m["text"].split("-")[0], m["score"],
                                                          "*" if m["over"] else "")
                                          for m in why["minutes"]) + "   (* = over the line)")
    for m in why["moved"]:
        out.append("   %s: normally %s, during the attack %s" % (m["words"], m["normal"], m["during"]))
    out.append("   evidence: %s" % ", ".join(why["evidence_ids"]))
    imp = report["impact"]
    out += ["", "6. IMPACT", "   " + imp["sentence"]]
    for dev, rows in imp["reach"].items():
        out.append("   %s talked to: %s" % (dev, ", ".join(
            "%s%s x%d" % (r["label"], " (NEW)" if r["new"] else "", r["count"]) for r in rows)))
    out += ["", "7. WHAT TO DO (recommended - the operator acts)"]
    for i, step in enumerate(report["playbook"], 1):
        out.append("   %d. [%s] %s" % (i, step["urgency"].upper(), step["title"]))
        out += ["      - " + d for d in step["do"]]
    out += ["", "8. WHAT WE ARE NOT SURE ABOUT"] + ["   - " + u for u in report["unsure"]]
    out += ["", "   (%s)" % report.get("wording", {}).get("note", ""),
            "   generated %s, capture time %s" % (datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                                                  when(report.get("now_seconds")))]
    return "\n".join(out)


_CSS = """
body{font-family:Segoe UI,Arial,sans-serif;max-width:900px;margin:24px auto;color:#222;line-height:1.45}
h1{font-size:22px;margin-bottom:4px} h2{font-size:17px;margin:22px 0 6px;border-bottom:1px solid #ddd}
.status{display:inline-block;padding:4px 10px;border-radius:4px;font-weight:bold;color:#fff}
.incident{background:#c0392b}.contained{background:#27ae60}.none{background:#7f8c8d}
table{border-collapse:collapse;margin:6px 0} td,th{border:1px solid #ccc;padding:3px 8px;font-size:14px}
th{background:#f4f4f4;text-align:left} .muted{color:#777;font-size:13px} code{background:#f4f4f4;padding:0 3px}
.over{color:#c0392b;font-weight:bold} li{margin:2px 0}
@media print{body{margin:0}}
"""


def render_html(report: dict) -> str:
    """One self-contained page (inline CSS, no scripts): open it, or print it to PDF."""
    e = html.escape
    start = report.get("capture_start_epoch")
    status = report.get("status", "no incident")
    css_class = {"incident": "incident", "contained": "contained"}.get(status, "none")
    p = []
    p.append("<h1>Incident report - %s</h1>" % e(str(report.get("session"))))
    p.append("<p><span class='status %s'>%s</span> <span class='muted'>capture time %s</span></p>"
             % (css_class, e(status.upper()), e(clock_text(report.get("now_seconds"), start))))
    p.append("<h2>1. What happened</h2><p>%s</p>" % e(report["what_happened"]["sentence"]))
    if report.get("wording", {}).get("source") == "llm":
        p.append("<p><i>In other words:</i> %s</p>" % e(report["wording"]["headline"]))
    if status != "no incident":
        c = report.get("containment") or {}
        if c.get("available"):
            p.append("<p><b>%s</b></p>" % e(containment_line(c, start)))
        w = report["when"]
        p.append("<h2>2. When</h2><p>%s</p>" % e(w["sentence"]))
        if w["abnormal_minutes"]:
            p.append("<table><tr><th>abnormal minute</th><th>score</th></tr>%s</table>" % "".join(
                "<tr><td>%s</td><td>%.1f</td></tr>" % (e(m["text"]), m["score"])
                for m in w["abnormal_minutes"]))
        where = report["where"]
        p.append("<h2>3. Where it started</h2><p>%s</p>" % e(where["sentence"]))
        p.append("<table><tr><th>#</th><th>device</th><th>abnormal from</th><th>how it ranked</th>"
                 "</tr>%s</table>" % "".join(
                     "<tr><td>%d</td><td><code>%s</code></td><td>%s</td><td>%s</td></tr>"
                     % (r["position"], e(r["device"]), e(r["onset_text"]), e(r["explanation"]))
                     for r in where["ranking"]))
        for key, words in (("cleared", "Stayed normal"), ("not_judged", "Not judged"),
                           ("unseen", "Not seen")):
            if where.get(key):
                p.append("<p>%s: %s</p>" % (words, e(", ".join(where[key]))))
        p.append("<h2>4. How</h2>")
        pats = report["how"]["patterns"]
        p.append("<ul>%s</ul>" % "".join("<li>%s</li>" % e(s) for s in report["how"]["sentences"]))
        if pats:
            p.append("<table><tr><th>destination</th><th>connections</th><th>first</th>"
                     "<th>typical gap</th><th>bytes sent / back</th><th>ids</th></tr>%s</table>"
                     % "".join("<tr><td><code>%s</code></td><td>%d</td><td>%s</td><td>%s</td>"
                               "<td>%d / %d</td><td>%s</td></tr>"
                               % (e(x["label"]), x["count"], e(clock_text(x["first_seconds"], start)),
                                  e("~%d s" % round(x["typical_gap_seconds"])
                                    if x["typical_gap_seconds"] is not None else "-"),
                                  x["typical_bytes_out"], x["typical_bytes_in"],
                                  e(", ".join(x["conn_ids"]))) for x in pats))
        why = report["why"]
        p.append("<h2>5. Why we believe it</h2><p>%s</p>" % e(why["sentence"]))
        p.append("<p>Score per minute (the line is %.1f): %s</p>" % (why["threshold"], " &middot; ".join(
            "<span class='%s'>%s %.1f</span>" % ("over" if m["over"] else "", e(m["text"]), m["score"])
            for m in why["minutes"])))
        if why["moved"]:
            p.append("<table><tr><th>measurement</th><th>normally</th><th>during the attack</th>"
                     "</tr>%s</table>" % "".join(
                         "<tr><td>%s</td><td>%s</td><td>%s</td></tr>"
                         % (e(m["words"]), m["normal"], m["during"]) for m in why["moved"]))
        else:
            p.append("<p class='muted'>No single measurement moved far on its own; the second "
                     "opinion (IsolationForest, all seven together) carried the score.</p>")
        p.append("<p>Evidence connections: <code>%s</code></p>" % e(", ".join(why["evidence_ids"])))
        imp = report["impact"]
        p.append("<h2>6. Impact</h2><p>%s</p><ul>%s</ul>" % (e(imp["sentence"]), "".join(
            "<li><code>%s</code> talked to: %s</li>" % (e(dev), e(", ".join(
                "%s%s x%d" % (r["label"], " (NEW)" if r["new"] else "", r["count"]) for r in rows)))
            for dev, rows in imp["reach"].items())))
        p.append("<h2>7. What to do</h2><p class='muted'>Recommended - the operator acts; "
                 "nothing is done automatically.</p><ol>")
        for step in report["playbook"]:
            p.append("<li><b>[%s] %s</b><ul>%s</ul></li>" % (
                e(step["urgency"].upper()), e(step["title"]),
                "".join("<li>%s</li>" % e(d) for d in step["do"])))
        p.append("</ol>")
        p.append("<h2>8. What we are not sure about</h2><ul>%s</ul>"
                 % "".join("<li>%s</li>" % e(u) for u in report["unsure"]))
    p.append("<p class='muted'>%s. Generated %s.</p>" % (
        e(report.get("wording", {}).get("note", "")), e(datetime.now().strftime("%Y-%m-%d %H:%M:%S"))))
    return ("<!DOCTYPE html><html lang='en'><head><meta charset='utf-8'><title>Incident report - %s"
            "</title><style>%s</style></head><body>%s</body></html>"
            % (e(str(report.get("session"))), _CSS, "\n".join(p)))


def write_html(report: dict, reports_dir: Path = REPORTS_DIR) -> Path:
    reports_dir = Path(reports_dir)
    reports_dir.mkdir(parents=True, exist_ok=True)
    path = reports_dir / ("%s.html" % report.get("session", "report"))
    tmp = path.with_suffix(".html.tmp")
    tmp.write_text(render_html(report), encoding="utf-8")
    tmp.replace(path)
    return path


# --------------------------------------------------------------------------
# Command line: a report for a saved run
# --------------------------------------------------------------------------

def report_for_run(run_id: str, pcap=None, llm: str | None = None) -> dict:
    """The report for a saved run, as the offline pipeline sees it."""
    run = runs.load_run(run_id)
    meta = json.loads(runs.meta_path(run_id).read_text(encoding="utf-8"))
    start = meta.get("capture_start_epoch")
    addresses, evidence = {}, {}
    if pcap:
        pcap = Path(pcap)
        packets = capture.read_packets(pcap, capture.find_tshark())
        addresses = capture.addresses_from_packets(packets)
        if start is None and packets:
            start = float(packets[0]["frame.time_epoch"])
        evidence = {"folder": str(pcap), "file": str(pcap), "sha256": sha256_of(pcap), "files": 1}
    detection = detect.detect_run(run)
    result = attribute.attribute_run(run, detection)
    first_alert = (meta.get("live") or {}).get("first_alert")
    report = build_incident(run, detection, result, capture_start_epoch=start,
                            first_alert=first_alert, addresses=addresses, evidence=evidence)
    if llm and report["status"] != "no incident":
        from src import report as brief_module
        ev = brief_module.build_evidence(run, detection, result)
        facts = brief_module.allowed_facts_from(ev, run)
        outcome = brief_module.generate_brief(ev, facts, run, result, provider=llm)
        report = wording_from_brief(report, outcome)
    return report


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="The complete incident report for a saved run.")
    parser.add_argument("run_id", help="e.g. rehearsal_02 or live_batch_05")
    parser.add_argument("--pcap", default=None,
                        help="the run's capture file: adds IP addresses and its SHA-256")
    parser.add_argument("--llm", choices=["local", "cloud"], default=None,
                        help="also ask a language model for a headline (validated; optional)")
    parser.add_argument("--no-html", action="store_true", help="do not write reports/<run>.html")
    args = parser.parse_args(argv)
    try:
        report = report_for_run(args.run_id, pcap=args.pcap, llm=args.llm)
    except FileNotFoundError as exc:
        print("\n  %s\n" % exc, file=sys.stderr)
        return 1
    print()
    print(render_text(report))
    if not args.no_html:
        print("\n  wrote %s" % write_html(report))
    print()
    return 0


if __name__ == "__main__":
    sys.exit(main())
