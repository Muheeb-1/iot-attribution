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
    python -m src.incident live_session_07 --pdf          # + reports/live_session_07.pdf (Edge)

THE DESIGNED REPORT (Step P3)
-----------------------------
render_html draws docs/design/report_mockup.html: one light A4 page, two
pages at most, on screen and as the PDF (html_to_pdf prints it with the Edge
Windows 11 already has). It adds three rule-based fields - incident_id,
severity (rule in SEVERITY_RULE) and the MITRE ATT&CK techniques the
measured behaviour is consistent with - and shows every destination as an
address (192.168.0.200:4444), never as capture.py's name ("broker:4444").
The eight sections above are unchanged in the dict and in render_text.
"""

from __future__ import annotations

import argparse
import hashlib
import html
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
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
        gaps = np.diff(times)
        gap = float(np.median(gaps)) if len(times) > 1 else None
        # How regular the gaps are: spread / mean (0 = a metronome). Used
        # only for the ATT&CK "Scheduled Transfer" line (Step P3).
        gap_cv = (float(np.std(gaps) / np.mean(gaps))
                  if len(gaps) > 0 and float(np.mean(gaps)) > 0 else None)
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
            "gap_cv": gap_cv,
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


def containment_line(c: dict, start_epoch=None, addresses=None) -> str:
    """
    The CONTAINED check in one sentence, in sentence case (Step P3). The
    destinations are written as addresses ("192.168.0.200:4444", not
    "broker:4444") - see address_label; the check itself is unchanged.
    """
    if not c or not c.get("available"):
        return ("The containment check needs the new connections of section 4; "
                "none have been identified yet.")
    watching = ", ".join(address_label(w, addresses) for w in c["watching"])
    needed = int(c["quiet_needed_seconds"])
    if c.get("contained"):
        return ("Contained at %s: %s has made no connection to %s since %s (%s)."
                % (clock_text(c["contained_seconds"], start_epoch), c["device"], watching,
                   clock_text(c["last_seen_seconds"], start_epoch),
                   c.get("last_seen_id") or "-"))
    if c.get("last_seen_seconds") is None:
        return "Watching %s for connections to %s." % (c["device"], watching)
    return ("Not contained yet. Last connection to %s at %s, %s ago. "
            "Containment is confirmed after %d s with none."
            % (watching, clock_text(c["last_seen_seconds"], start_epoch),
               duration_text(c["quiet_seconds"]), needed))


# --------------------------------------------------------------------------
# Addresses for display (Step P3)
# --------------------------------------------------------------------------
#
# capture.py names the master laptop "broker" (it runs the MQTT broker), and
# the report's labels say "broker:4444". On screen and on paper the operator
# needs the address they would actually block or look up, so every label is
# DISPLAYED as "192.168.0.200:4444". This is display only: capture.py's
# names, the report's "label" fields and everything that matches on them are
# unchanged. The address comes from the packets (addresses_from_packets) and,
# failing that, from capture.IP_TO_NAME - the fixed addresses of the lab's
# infrastructure - so "broker" is never shown even without the packets.

def address_of(name, addresses=None):
    """The IP address to show for a name, or None."""
    if not name:
        return None
    found = (addresses or {}).get(name)
    if found:
        return found
    for ip, known in capture.IP_TO_NAME.items():
        if known == name:
            return ip
    return None


def address_label(label, addresses=None) -> str:
    """'broker:4444' -> '192.168.0.200:4444'; 'broker (no port)' likewise; else unchanged."""
    label = str(label)
    for suffix_start in (label.rfind(":"), label.rfind(" (no port)")):
        if suffix_start > 0:
            name, suffix = label[:suffix_start], label[suffix_start:]
            if suffix == " (no port)" or suffix[1:].isdigit():
                ip = address_of(name, addresses)
                return ip + suffix if ip else label
    return label


def display_text(text, report: dict | None = None, addresses=None) -> str:
    """
    A report sentence with every destination label it mentions written as an
    address. Only the labels the report itself lists (section 4, section 6,
    the CONTAINED check) are replaced, so nothing else in a sentence changes.
    """
    text = str(text)
    addresses = dict((report or {}).get("addresses") or {}, **(addresses or {}))
    labels = set()
    for p in ((report or {}).get("how") or {}).get("patterns") or []:
        labels.add(p.get("label", ""))
    for rows in (((report or {}).get("impact") or {}).get("reach") or {}).values():
        labels.update(r.get("label", "") for r in rows)
    labels.update(((report or {}).get("containment") or {}).get("watching") or [])
    for label in sorted((l for l in labels if l), key=len, reverse=True):
        shown = address_label(label, addresses)
        if shown != label:
            text = re.sub(r"(?<![\w.-])%s(?!\d)" % re.escape(label), shown, text)
    return text


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
    # Count over the SAME window as section 4 (everything after the baseline),
    # not from the onset. The onset is only when we NOTICED; the attack began a
    # few windows earlier, at the trigger. Counting from the onset dropped the
    # first beacon or two, so section 4 ("8 connections to broker:4444") and
    # section 6 ("x7") disagreed about the same endpoint. One count, the final
    # post-baseline total at STOP, shared by both.
    reach = {}
    for dev in flagged:
        mine = connections[connections["src"] == dev]
        before = set(zip(mine[mine["t"] < run.baseline_seconds]["dst"],
                         mine[mine["t"] < run.baseline_seconds]["dport"].astype(int)))
        after = mine[mine["t"] >= run.baseline_seconds]
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

    # ---- Step P3: new fields for the designed report (nothing above changes) --
    # Every scored minute of the focus device, baseline included, for the
    # report's small bar chart (section 5 lists only the minutes from the onset).
    report["why"]["series"] = [{"window": int(w), "score": round(float(s), 2),
                                "baseline": bool(w < run.baseline_windows),
                                "over": bool(s > detection.threshold)}
                               for w, s in sorted(scores.items())]
    report["addresses"] = {k: str(v) for k, v in (addresses or {}).items()}
    report["evidence"] = {k: evidence[k] for k in ("folder", "files", "sha256", "file")
                          if k in (evidence or {})}
    report["session_folder"] = session_folder
    report.update(designed_fields(report))
    return report


# --------------------------------------------------------------------------
# Step P3: incident id, severity and ATT&CK techniques - rules, not a model
# --------------------------------------------------------------------------

SEVERITY_RULE = ("Critical: more than one device flagged. High: one device with a new "
                 "repeating destination. Medium: one device flagged, no new repeating "
                 "destination.")

# The ports this lab has a name for (PORT_WORDS) are the "known services"; a
# new destination on any other port is a non-standard port.
KNOWN_SERVICE_PORTS = frozenset(PORT_WORDS)

# Names checked on attack.mitre.org on 15 Nov 2026.
TECHNIQUES = {
    "T1571": {"name": "Non-Standard Port", "tactic": "Command and Control",
              "url": "https://attack.mitre.org/techniques/T1571/"},
    "T1029": {"name": "Scheduled Transfer", "tactic": "Exfiltration",
              "url": "https://attack.mitre.org/techniques/T1029/"},
    "T1041": {"name": "Exfiltration Over C2 Channel", "tactic": "Exfiltration",
              "url": "https://attack.mitre.org/techniques/T1041/"},
}
SCHEDULED_MIN_COUNT = 4         # connections needed before a rhythm is claimed
SCHEDULED_MAX_CV = 0.2          # spread of the gaps / their mean


def incident_id(report: dict) -> str:
    """
    INC-<capture date YYYYMMDD>-<trailing digits of the session name>, or the
    alert's HHMM when the name has no digits. live_session_07 on 13 Nov 2026 ->
    INC-20261113-07. A run with no clock time (simulated) has no date: INC-<HHMM>.
    """
    session = str(report.get("session") or "")
    start = report.get("capture_start_epoch")
    digits = re.search(r"(\d+)$", session)
    if digits:
        tail = digits.group(1)
    else:
        alert = (report.get("when") or {}).get("alert_epoch")
        if alert is not None:
            tail = datetime.fromtimestamp(float(alert)).strftime("%H%M")
        else:
            seconds = int((report.get("when") or {}).get("alert_seconds") or 0)
            tail = "%02d%02d" % (seconds // 3600, (seconds % 3600) // 60)
    if start is None:
        return "INC-%s" % tail
    return "INC-%s-%s" % (datetime.fromtimestamp(float(start)).strftime("%Y%m%d"), tail)


def severity_of(report: dict) -> str:
    """critical / high / medium, by SEVERITY_RULE, from the report's own facts."""
    if len(report.get("flagged") or []) > 1:
        return "critical"
    if (report.get("how") or {}).get("patterns"):
        return "high"
    return "medium"


def techniques_for(report: dict, addresses=None) -> list:
    """
    The MITRE ATT&CK techniques the measured behaviour is CONSISTENT WITH,
    each with the measurement that supports it. Only section 4's new
    repeating destinations are looked at; no packet contents are needed.
      T1571  a new destination on a port outside the known-service list
      T1029  4+ connections at a regular gap (spread / mean < 0.2)
      T1041  more bytes out than back on that destination
    """
    found = {}
    addresses = dict(report.get("addresses") or {}, **(addresses or {}))
    for p in (report.get("how") or {}).get("patterns") or []:
        where = address_label(p.get("label", ""), addresses)
        if "T1571" not in found and int(p.get("dport") or 0) not in KNOWN_SERVICE_PORTS:
            found["T1571"] = "Port %d was never used in the baseline and is not a known service " \
                             "here (%s)." % (int(p["dport"]), where)
        gap, cv = p.get("typical_gap_seconds"), p.get("gap_cv")
        if "T1029" not in found and int(p.get("count") or 0) >= SCHEDULED_MIN_COUNT \
                and gap is not None and cv is not None and cv < SCHEDULED_MAX_CV:
            found["T1029"] = "One connection every %d seconds to %s, machine-regular " \
                             "(%d connections)." % (round(gap), where, int(p["count"]))
        out, back = p.get("typical_bytes_out"), p.get("typical_bytes_in")
        if "T1041" not in found and out is not None and back is not None and out > back:
            found["T1041"] = "%d bytes out for %d back, each time, to %s." % (out, back, where)
    return [dict(TECHNIQUES[t], id=t, evidence=found[t]) for t in ("T1571", "T1029", "T1041")
            if t in found]


def designed_fields(report: dict) -> dict:
    """
    The P3 fields, worked out from the report dict alone - so a report saved
    before P3 (an old state.json) can be drawn the new way too.
    """
    if not report or report.get("status") in (None, "failed", "no incident"):
        return {}
    return {"incident_id": incident_id(report), "severity": severity_of(report),
            "severity_rule": SEVERITY_RULE, "techniques": techniques_for(report)}


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
                         containment_line(containment, start, addresses)]})
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


# --------------------------------------------------------------------------
# The operator's acknowledgement (Step P2)
# --------------------------------------------------------------------------
#
# The live page has an Acknowledge button. Pressing it writes
# pcap/live/<session>/ack.json with the operator's clock time. That is an
# operator action, like unplugging the board: the engine reads the file only
# to put the time in state.json and in this report. It changes no verdict,
# score, phase or containment decision.
#
# WHICH CLOCK. In a live session the packets are stamped by the same laptop
# clock the operator's click is, so the click time IS the capture time. In a
# replay the page shows the recording's clock (13 Nov, 20 times fast) while
# the operator clicks on today's clock. There the acknowledgement is placed
# on the recording's clock at the alert plus the operator's REAL reaction
# time (click minus the real moment the engine raised the alert), so "to
# acknowledge" is the human's actual reaction in both cases.

def acknowledgement(clicked_epoch, first_alert, alert_wall_epoch=None, replaying=False,
                    start_epoch=None) -> dict | None:
    """
    The acknowledgement as report facts, or None (no click, or no alert yet).

    clicked_epoch     the operator's clock when Acknowledge was pressed
    first_alert       the engine's first alert (raised_epoch is used)
    alert_wall_epoch  the operator's clock when the engine raised that alert
                      (needed only for a replay)
    """
    if clicked_epoch is None or not first_alert or first_alert.get("raised_epoch") is None:
        return None
    raised = float(first_alert["raised_epoch"])
    clicked = float(clicked_epoch)
    if replaying and alert_wall_epoch is not None:
        epoch = raised + max(0.0, clicked - float(alert_wall_epoch))
        clock = "replay: the operator's real reaction time, placed on the recording's clock"
    else:
        epoch = max(raised, clicked)       # a click cannot come before the alert it answers
        clock = "the capture clock (the laptop's own clock)"
    return {
        "acknowledged_epoch": epoch,
        "acknowledged_seconds": None if start_epoch is None else epoch - float(start_epoch),
        "after_alert_seconds": epoch - raised,
        "clicked_epoch": clicked,
        "clock": clock,
    }


def acknowledged_line(ack: dict | None) -> str:
    """One sentence for the report."""
    if not ack:
        return "Not acknowledged by the operator."
    return ("Acknowledged by the operator at %s, %s after the alert."
            % (datetime.fromtimestamp(float(ack["acknowledged_epoch"])).strftime("%H:%M:%S"),
               duration_text(ack["after_alert_seconds"])))


def with_acknowledgement(report: dict, ack: dict | None) -> dict:
    """The report with the operator's acknowledgement added (a new field only)."""
    if not report or not ack or report.get("status") in (None, "failed", "no incident"):
        return report
    report = dict(report)
    report["acknowledged"] = ack
    return report


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
            step = dict(step, do=list(step["do"][:-1])
                        + [containment_line(containment, start, report.get("addresses"))])
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
    if report.get("acknowledged"):
        out.append("   " + acknowledged_line(report["acknowledged"]))
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


# --------------------------------------------------------------------------
# The designed report (Step P3): docs/design/report_mockup.html
# --------------------------------------------------------------------------
#
# One light A4 page design, used on screen and printed to PDF, two pages at
# most. It shows the SHORT version - key facts, what happened, timeline, how
# it was found, why we believe it, techniques, what to do, evidence and
# limits. The eight sections stay in the report dict and in render_text; the
# dashboards show them under "Full technical detail".
#
# design_facts() collects what is shown, as plain data, from the report dict
# alone; render_html() draws it light for paper and dashboard/theme.py draws
# the same facts dark for the live page, so the two never disagree.

def _when_epoch(report: dict, seconds):
    return _epoch(seconds, report.get("capture_start_epoch"))


def _hms(epoch) -> str:
    return "-" if epoch is None else datetime.fromtimestamp(float(epoch)).strftime("%H:%M:%S")


def template_summary(report: dict, addresses=None) -> str:
    """
    'What happened' in two to four plain sentences, built from the measurements
    (the template wording; Step P4's AI analyst may word it instead). Names only
    facts that do not change minute to minute.
    """
    addresses = dict(report.get("addresses") or {}, **(addresses or {}))
    where = report.get("where") or {}
    named = where.get("named")
    flagged = report.get("flagged") or []
    if not named:
        return display_text(report.get("what_happened", {}).get("sentence", ""), report, addresses)
    patterns = (report.get("how") or {}).get("patterns") or []
    first = _hms((report.get("when") or {}).get("first_unusual_epoch")) \
        if report.get("capture_start_epoch") is not None \
        else clock_text((report.get("when") or {}).get("first_unusual_seconds"))
    parts = []
    if patterns:
        p = patterns[0]
        gap = p.get("typical_gap_seconds")
        parts.append("%s was compromised at %s." % (named, first))
        parts.append("It began opening a connection to %s%s, sending %d bytes each time."
                     % (address_label(p["label"], addresses),
                        " every %d seconds" % round(gap) if gap is not None else " repeatedly",
                        p["typical_bytes_out"]))
        parts.append("It never used that destination while its normal behaviour was "
                     "being learned.")
    else:
        parts.append("%s started behaving differently from its normal pattern at %s." % (named, first))
    others = [d for d in flagged if d != named]
    if others:
        parts.append("%s also behaved abnormally afterwards, so the attack appears to have "
                     "spread." % ", ".join(others))
    else:
        parts.append("No other device changed its behaviour, so the attack started here and "
                     "did not spread.")
    return " ".join(parts)


def summary_and_source(report: dict, addresses=None) -> tuple:
    """
    (summary text, source line, written_by_ai). The AI analyst's summary is
    used only if it is in the report AND passed the validator (Step P4);
    otherwise the template wording, and the source line says which.
    """
    analyst = report.get("analyst") or {}
    if analyst.get("status") == "ok" and analyst.get("summary"):
        return (analyst["summary"],
                "Written by the AI analyst (%s). Every fact checked against the evidence."
                % analyst.get("model", "cloud model"), True)
    if analyst.get("status") in ("failed", "rejected", "unreachable", "no key"):
        source = "Template wording - the AI analyst was not reachable."
    elif analyst.get("status") == "asking":
        source = "Template wording - the AI analyst is being asked."
    else:
        source = "Template wording, built from the measurements."
    return template_summary(report, addresses), source, False


def design_facts(report: dict, addresses=None) -> dict:
    """Everything the designed report shows, as plain data (tested directly)."""
    addresses = dict(report.get("addresses") or {}, **(addresses or {}))
    report = dict(report, **{k: v for k, v in designed_fields(report).items()
                              if k not in report})
    start = report.get("capture_start_epoch")
    status = report.get("status", "no incident")
    session = str(report.get("session") or "")
    facts = {"session": session, "status": status, "incident_id": report.get("incident_id"),
             "date": (datetime.fromtimestamp(float(start)).strftime("%d %b %Y").lstrip("0")
                      if start is not None else None)}
    if status in ("no incident", "failed", None):
        facts["headline"] = "No incident"
        facts["summary"] = report.get("what_happened", {}).get("sentence", "")
        return facts

    where = report.get("where") or {}
    when = report.get("when") or {}
    named = where.get("named")
    c = report.get("containment") or {}
    ack = report.get("acknowledged") or {}
    contained = bool(c.get("contained"))
    alert_epoch = when.get("alert_epoch")
    hms = (lambda epoch, seconds: _hms(epoch)) if start is not None else \
        (lambda epoch, seconds: clock_text(seconds))

    facts["headline"] = ("Attack started on" if named else "Attack detected, origin not certain")
    facts["device"] = named
    facts["severity"] = report.get("severity")
    facts["severity_rule"] = report.get("severity_rule", SEVERITY_RULE)
    facts["contained"] = contained
    facts["confidence"] = where.get("confidence_percent")
    facts["tags"] = ([("sev", "Severity %s" % report.get("severity"))]
                     + [("ok", "Contained") if contained else ("sev", "Not contained yet")]
                     + ([("plain", "Confidence %s%%" % where.get("confidence_percent"))]
                        if named else [("plain", "Too close to call")]))

    to_contain = None
    if contained and c.get("contained_epoch") is not None and alert_epoch is not None:
        to_contain = max(0.0, float(c["contained_epoch"]) - float(alert_epoch))
    elif contained and c.get("contained_seconds") is not None and when.get("alert_seconds") is not None:
        to_contain = max(0.0, float(c["contained_seconds"]) - float(when["alert_seconds"]))
    origin_ip = address_of(named, addresses) if named else None
    facts["keys"] = [
        (named or ", ".join(where.get("shortlist") or []) or "-",
         "origin device" + (", %s" % origin_ip if origin_ip else "") if named else "suspects"),
        (duration_text(when.get("time_to_detect_seconds")) if when.get("time_to_detect_seconds")
         is not None else "--", "to detect"),
        (duration_text(ack.get("after_alert_seconds")) if ack else "--", "to acknowledge"),
        (duration_text(to_contain) if to_contain is not None else "--", "to contain"),
    ]
    facts["summary"], facts["source"], facts["by_ai"] = summary_and_source(report, addresses)

    # Timeline: the same five moments as the live page's timeline.
    baseline = report.get("baseline_seconds")
    tl = []
    if baseline is not None:
        tl.append((hms(_when_epoch(report, float(baseline) + GRACE_SECONDS),
                       float(baseline) + GRACE_SECONDS), "Baseline established", ""))
    if when.get("first_unusual_seconds") is not None:
        tl.append((hms(when.get("first_unusual_epoch"), when["first_unusual_seconds"]),
                   "First unusual connection", "hot"))
    if when.get("alert_seconds") is not None:
        tl.append((hms(alert_epoch, when["alert_seconds"]), "Alert raised", "hot"))
    if ack:
        tl.append((_hms(ack.get("acknowledged_epoch")), "Acknowledged by operator", ""))
    if contained:
        tl.append((hms(c.get("contained_epoch"), c.get("contained_seconds")),
                   "Contained, %d s of silence" % int(c.get("quiet_needed_seconds") or 90), "good"))
    facts["timeline"] = tl

    patterns = (report.get("how") or {}).get("patterns") or []
    facts["found"] = [{"destination": address_label(p["label"], addresses),
                       "count": p["count"],
                       "gap": ("~%d s" % round(p["typical_gap_seconds"])
                               if p.get("typical_gap_seconds") is not None else "-"),
                       "bytes_out": p["typical_bytes_out"], "bytes_in": p["typical_bytes_in"]}
                      for p in patterns[:3]]
    why = report.get("why") or {}
    baseline_minutes = int(round(float(baseline or 0) / 60))
    facts["found_note"] = ("Never used in the %d-minute baseline. " % baseline_minutes
                           if patterns else
                           "No new repeating destination: flagged on how its traffic changed. ")
    facts["evidence_ids"] = list(why.get("evidence_ids") or [])[:3]

    threshold = float(why.get("threshold") or report.get("threshold") or 4.0)
    series = why.get("series")
    if not series:      # a report from before P3: only the minutes from the onset
        series = [{"window": m.get("window"), "score": m["score"], "baseline": False,
                   "over": m["over"]} for m in why.get("minutes") or []]
    facts["bars"] = [{"height": max(0.0, min(1.0, float(s["score"]) / BAR_SCALE)),
                      # a baseline minute is learning, never an alert: drawn grey
                      "score": float(s["score"]),
                      "over": bool(s.get("over")) and not bool(s.get("baseline")),
                      "baseline": bool(s.get("baseline")), "capped": float(s["score"]) > BAR_SCALE}
                     for s in series[-MAX_BARS:]]
    facts["threshold"] = threshold
    facts["line_height"] = threshold / BAR_SCALE
    run = [m for m in why.get("minutes") or []]
    over_run = []
    for m in run:
        if not m.get("over"):
            break
        over_run.append(m)
    moved = (why.get("moved") or [])[:1]
    caption = "%d minutes in a row over the alert line (%.1f)" % (len(over_run), threshold)
    if over_run:
        caption += ": scores %s." % ", ".join("%.1f" % m["score"] for m in over_run)
    else:
        caption += "."
    if moved:
        words = re.sub(r"\s*\(.*\)$", "", moved[0]["words"])
        caption += " %s went from %s to %s." % (words[0].upper() + words[1:],
                                                _num(moved[0]["normal"]), _num(moved[0]["during"]))
    facts["why_caption"] = caption

    facts["techniques"] = report.get("techniques") or techniques_for(report, addresses)

    # What to do, short - from the playbook's facts.
    targets = [named] if named else list(where.get("shortlist") or [])
    macs = [(t, _mac_of(t)) for t in targets]
    isolate = "Isolate %s." % " and ".join(targets)
    block = "Pull its power, or block MAC %s on the router." % " / ".join(
        m for _, m in macs if m) if any(m for _, m in macs) else \
        "Pull its power, or block it on the router."
    done = (" Done: confirmed contained at %s." % hms(c.get("contained_epoch"),
                                                       c.get("contained_seconds"))
            if contained else "")
    evidence = report.get("evidence") or {}
    folder = evidence.get("folder") or report.get("session_folder")
    keep = "Keep the capture as evidence."
    keep_detail = ""
    if folder:
        files = evidence.get("files")
        keep_detail = ("%d files in %s." % (files, folder) if files else "The capture is in %s." % folder)
    facts["steps"] = [
        {"when": "Now", "later": False, "done": contained, "title": isolate,
         "text": block + done, "mono": [m for _, m in macs if m]},
        {"when": "Now", "later": False, "done": False, "title": keep, "text": keep_detail,
         "mono": [folder] if folder else []},
        {"when": "Today", "later": True, "done": False,
         "title": "Re-flash the board" if len(targets) == 1 else "Re-flash the boards",
         "text": "from known-good firmware and change the Wi-Fi and broker credentials it held.",
         "mono": []},
        {"when": "Today", "later": True, "done": False,
         "title": "Reconnect it only after a clean baseline", "text": "shows it as normal.",
         "mono": []},
    ]
    facts["sha256"] = evidence.get("sha256")
    limits = ["The capture point sees traffic to and from the master laptop, plus broadcasts. "
              "Board-to-board traffic is not visible.",
              "The alert needs %d abnormal minutes in a row, so it comes 3 to 4 minutes after "
              "an attack starts." % int(report.get("consecutive") or 3)]
    if where.get("not_judged"):
        limits.append("Not judged (too little traffic during the baseline): %s."
                      % ", ".join(where["not_judged"]))
    limits.append("This report states what was measured. The method can be wrong; check the "
                  "evidence connections before acting on anything irreversible.")
    facts["limits"] = limits
    facts["footer"] = ("Verdict and numbers: detection and attribution engine (V5). Wording: %s."
                       % ("AI analyst, validated" if facts["by_ai"] else "template, from the measurements"))
    return facts


BAR_SCALE = 10.0        # the same scale as the live page's lanes: the line (4.0) at 40%
MAX_BARS = 40


def _num(value) -> str:
    value = float(value)
    return "%d" % value if value == int(value) else "%.1f" % value


_CSS = """
@page { size: A4; margin: 14mm 14mm 16mm; }
:root { --ink: #101A2E; --soft: #44536F; --muted: #6D7B95; --rule: #D5DCE8; --wash: #F2F5FA;
        --navy: #0E1524; --alert: #C9283B; --ok: #0F7D62; --amber: #8A5A00;
        --display: "Bahnschrift", "DIN Alternate", "Barlow Semi Condensed", "Segoe UI", sans-serif;
        --body: "Segoe UI Variable Text", "Segoe UI", system-ui, sans-serif;
        --mono: "Cascadia Mono", Consolas, monospace; }
* { box-sizing: border-box; -webkit-print-color-adjust: exact; print-color-adjust: exact; }
body { margin: 0 auto; max-width: 182mm; color: var(--ink); font: 10.5pt/1.5 var(--body); background: #fff; }
@media screen { body { padding: 28px 12px 60px; } }
h1, h2, p, ul { margin: 0; }
.mono { font-family: var(--mono); font-size: 0.93em; }
.head { background: var(--navy); color: #fff; border-radius: 8px; padding: 18px 22px; display: grid; grid-template-columns: 1fr auto; gap: 16px; align-items: end; }
.head .org { font: 500 9.5pt var(--body); color: #B4C2DB; }
.head h1 { font: 600 22pt/1.1 var(--display); margin-top: 3px; }
.head h1 .dev { font-family: var(--mono); font-size: 0.86em; white-space: nowrap; }
.head .id { text-align: right; font: 600 12pt var(--mono); }
.head .id small { display: block; font: 400 9pt var(--body); color: #B4C2DB; }
.tags { display: flex; gap: 8px; margin-top: 12px; flex-wrap: wrap; }
.tag { font: 600 9pt var(--body); padding: 3px 10px; border-radius: 999px; }
.tag.sev { background: #FF5D6C; color: #2A0A10; }  .tag.ok { background: #35C7A0; color: #06261E; }
.tag.plain { background: #1E2B44; color: #E8EEF9; }
.keys { display: grid; grid-template-columns: repeat(4, 1fr); margin: 14px 0 4px; border: 1px solid var(--rule); border-radius: 8px; }
.keys > div { padding: 11px 14px; border-left: 1px solid var(--rule); }  .keys > div:first-child { border-left: 0; }
.keys .v { white-space: nowrap; font: 600 15pt/1.1 var(--display); font-variant-numeric: tabular-nums; }
.keys .k { color: var(--muted); font-size: 8.5pt; margin-top: 3px; }
h2 { font: 600 12.5pt var(--display); margin: 18px 0 7px; padding-bottom: 4px; border-bottom: 2px solid var(--ink); }
section { break-inside: avoid; }
.summary { font-size: 11.5pt; line-height: 1.55; }
.source { color: var(--ok); font-size: 8.5pt; margin-top: 6px; font-weight: 600; }
.source.tpl { color: var(--muted); }
.tl { display: grid; grid-auto-columns: 1fr; grid-auto-flow: column; margin-top: 4px; }
.tl div { border-top: 2px solid var(--rule); padding: 9px 8px 0 0; position: relative; }
.tl div::before { content: ""; position: absolute; top: -6px; left: 0; width: 10px; height: 10px; border-radius: 50%; background: var(--muted); }
.tl .hot::before { background: var(--alert); }  .tl .good::before { background: var(--ok); }
.tl b { display: block; font: 600 12pt var(--display); font-variant-numeric: tabular-nums; }
.tl span { color: var(--soft); font-size: 8.5pt; }
table { border-collapse: collapse; width: 100%; font-size: 9.5pt; }
th { text-align: left; color: var(--muted); font-weight: 600; font-size: 8.5pt; padding: 5px 10px 5px 0; border-bottom: 1px solid var(--rule); }
td { padding: 6px 10px 6px 0; border-bottom: 1px solid var(--rule); vertical-align: top; }
td.n { font-variant-numeric: tabular-nums; white-space: nowrap; }
.two { display: grid; grid-template-columns: 1.15fr 1fr; gap: 20px; }
.bars { display: flex; align-items: flex-end; gap: 3px; height: 44px; position: relative; margin-top: 4px; }
.bars i { flex: 1; background: #B9C4D8; border-radius: 2px 2px 0 0; min-height: 2px; }
.bars i.over { background: var(--alert); }  .bars i.base { background: #DDE3EE; }
.bars i.capped { box-shadow: inset 0 2px 0 var(--ink); }
.bars .line { position: absolute; left: 0; right: 0; border-top: 1px dashed var(--soft); }
.cap { color: var(--muted); font-size: 8.5pt; margin-top: 4px; }
.tech { display: grid; grid-template-columns: auto 1fr; gap: 5px 12px; align-items: baseline; }
.tech > b { font: 600 9.5pt var(--mono); background: var(--wash); border: 1px solid var(--rule); border-radius: 4px; padding: 1px 7px; }
.steps { list-style: none; padding: 0; }
.steps li { display: grid; grid-template-columns: 16px 62px 1fr; gap: 9px; padding: 6px 0; border-bottom: 1px solid var(--rule); }
.steps .box { width: 13px; height: 13px; border: 1.5px solid var(--soft); border-radius: 3px; margin-top: 3px; }
.steps .done .box { background: var(--ok); border-color: var(--ok); }
.steps .when { font-weight: 600; font-size: 8.5pt; color: var(--alert); padding-top: 2px; }
.steps .when.later { color: var(--amber); }
.note { background: var(--wash); border-radius: 6px; padding: 9px 12px; font-size: 9.5pt; color: var(--soft); }
.note li { margin-left: 16px; }
.muted { color: var(--muted); }
.foot { margin-top: 16px; color: var(--muted); font-size: 8pt; display: flex; justify-content: space-between; gap: 12px; border-top: 1px solid var(--rule); padding-top: 6px; }
"""


def _mono_in(text: str, monos) -> str:
    """Escape text, then wrap each listed literal (a MAC, a folder) in the mono style."""
    out = html.escape(text)
    for m in sorted({x for x in monos if x}, key=len, reverse=True):
        out = out.replace(html.escape(m), "<span class='mono'>%s</span>" % html.escape(m))
    return out


def render_html(report: dict, addresses=None) -> str:
    """
    The designed report: one self-contained light page (inline CSS, no
    scripts, no web fonts, no links that load anything) to open in a browser
    or print to PDF. Every piece of data is escaped.
    """
    e = html.escape
    f = design_facts(report, addresses)
    title = f.get("incident_id") or f["session"]
    p = []
    sub = ", ".join(x for x in (f.get("date"), "session %s" % f["session"]) if x)
    if f["status"] in ("no incident", "failed", None):
        p.append("<header class='head'><div><div class='org'>IoT Incident Attribution, incident "
                 "report</div><h1>No incident</h1></div><div class='id'>%s<small>%s</small></div>"
                 "</header>" % (e(f["session"]), e(sub)))
        p.append("<section><h2>What happened</h2><p class='summary'>%s</p></section>"
                 % e(f["summary"]))
    else:
        head = ("%s <span class='dev'>%s</span>" % (e(f["headline"]), e(f["device"]))
                if f["device"] else e(f["headline"]))
        p.append("<header class='head'><div><div class='org'>IoT Incident Attribution, incident "
                 "report</div><h1>%s</h1><div class='tags'>%s</div></div>"
                 "<div class='id'>%s<small>%s</small></div></header>"
                 % (head, "".join("<span class='tag %s'>%s</span>" % (c, e(t)) for c, t in f["tags"]),
                    e(f.get("incident_id") or ""), e(sub)))
        p.append("<div class='keys'>%s</div>" % "".join(
            "<div><div class='v'>%s</div><div class='k'>%s</div></div>" % (e(v), e(k))
            for v, k in f["keys"]))
        p.append("<section><h2>What happened</h2><p class='summary'>%s</p>"
                 "<p class='source%s'>%s%s</p></section>"
                 % (e(f["summary"]), "" if f["by_ai"] else " tpl",
                    "&#10003; " if f["by_ai"] else "", e(f["source"])))
        if f["timeline"]:
            p.append("<section><h2>Timeline</h2><div class='tl'>%s</div></section>" % "".join(
                "<div class='%s'><b>%s</b><span>%s</span></div>" % (c, e(t), e(w))
                for t, w, c in f["timeline"]))
        rows = "".join("<tr><td class='mono'>%s</td><td class='n'><b>%d</b></td>"
                       "<td class='n'><b>%s</b></td><td class='n'><b>%d</b> / %d</td></tr>"
                       % (e(r["destination"]), r["count"], e(r["gap"]), r["bytes_out"], r["bytes_in"])
                       for r in f["found"])
        found = ("<table><tr><th>New destination</th><th>Connections</th><th>Gap</th>"
                 "<th>Bytes out / back</th></tr>%s</table>" % rows) if rows else ""
        ids = (" Evidence connections: <span class='mono'>%s</span>." % e(", ".join(f["evidence_ids"]))
               if f["evidence_ids"] else "")
        bars = "".join("<i class='%s' style='height:%.0f%%'></i>"
                       % (" ".join(c for c in ("over" if b["over"] else "",
                                               "base" if b["baseline"] else "",
                                               "capped" if b["capped"] else "") if c),
                          100 * b["height"]) for b in f["bars"])
        p.append("<section class='two'><div><h2>How it was found</h2>%s<p class='cap'>%s%s</p></div>"
                 "<div><h2>Why we believe it</h2><div class='bars' role='img' aria-label='%s score "
                 "per minute, alert line %.1f'>%s<span class='line' style='bottom:%.0f%%'></span>"
                 "</div><p class='cap'>%s</p></div></section>"
                 % (found, e(f["found_note"]), ids, e(f["device"] or "suspect"), f["threshold"],
                    bars, 100 * f["line_height"], e(f["why_caption"])))
        if f["techniques"]:
            p.append("<section><h2>Attack techniques seen (MITRE ATT&amp;CK)</h2>"
                     "<p class='cap' style='margin:0 0 6px'>Consistent with these techniques, "
                     "judged from the traffic's shape only.</p><div class='tech'>%s</div></section>"
                     % "".join("<b>%s</b><span><b>%s.</b> %s</span>"
                               % (e(t["id"]), e(t["name"]), e(t["evidence"]))
                               for t in f["techniques"]))
        p.append("<section><h2>What to do</h2><p class='cap' style='margin:0 0 4px'>Recommended - "
                 "the operator acts; nothing is done automatically.</p><ul class='steps'>%s</ul>"
                 "</section>" % "".join(
                     "<li class='%s'><span class='box'></span><span class='when%s'>%s</span>"
                     "<span><b>%s</b> %s</span></li>"
                     % ("done" if s["done"] else "", " later" if s["later"] else "", e(s["when"]),
                        e(s["title"]), _mono_in(s["text"], s["mono"])) for s in f["steps"]))
        sha = ("<p class='cap' style='margin:0 0 8px'>SHA-256 of the capture file list: "
               "<span class='mono'>%s</span></p>" % e(f["sha256"])) if f.get("sha256") else ""
        p.append("<section><h2>Evidence and limits</h2>%s<div class='note'><ul>%s</ul></div>"
                 "<p class='cap'>%s</p></section>"
                 % (sha, "".join("<li>%s</li>" % e(x) for x in f["limits"]),
                    e("Severity rule: " + f["severity_rule"])))
        p.append("<div class='foot'><span>%s</span><span>%s</span></div>"
                 % (e(f["footer"]), e(f.get("incident_id") or "")))
    p.append("<p class='cap muted'>Generated %s.</p>" % e(datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
    return ("<!DOCTYPE html><html lang='en'><head><meta charset='utf-8'><title>Incident report - %s"
            "</title><style>%s</style></head><body>%s</body></html>"
            % (e(title), _CSS, "\n".join(p)))


def write_html(report: dict, reports_dir: Path = REPORTS_DIR) -> Path:
    reports_dir = Path(reports_dir)
    reports_dir.mkdir(parents=True, exist_ok=True)
    path = reports_dir / ("%s.html" % report.get("session", "report"))
    tmp = path.with_suffix(".html.tmp")
    tmp.write_text(render_html(report), encoding="utf-8")
    tmp.replace(path)
    return path


# --------------------------------------------------------------------------
# The PDF (Step P3): the browser Windows 11 already has prints the page
# --------------------------------------------------------------------------
#
# No PDF library: Microsoft Edge (installed with Windows 11) prints the same
# HTML to PDF from the command line, colours included. Chrome is the second
# choice. Tried on this laptop on 15 Nov 2026: reports\live_session_07.html
# -> PDF in about 3 s.
#
# THE FRESH --user-data-dir MATTERS: if Edge is already open, a plain
# `msedge --headless ...` is handed to the running Edge, which ignores it and
# no file appears. A new empty profile folder makes it a separate browser.
# Arguments go as a list (the repo path has a space in it).

PDF_TIMEOUT_SECONDS = 45


def find_browser() -> str | None:
    """msedge.exe in either Program Files folder (or the user's), else Chrome; else None."""
    roots = [os.environ.get(v) for v in ("PROGRAMFILES(X86)", "PROGRAMFILES", "LOCALAPPDATA")]
    roots += [r"C:\Program Files (x86)", r"C:\Program Files"]
    for relative in (r"Microsoft\Edge\Application\msedge.exe",
                     r"Google\Chrome\Application\chrome.exe"):
        for root in roots:
            if root and Path(root, relative).is_file():
                return str(Path(root, relative))
    for name in ("msedge", "chrome", "chromium", "chromium-browser", "google-chrome"):
        found = shutil.which(name)
        if found:
            return found
    return None


def html_to_pdf(html_path, pdf_path=None, browser: str | None = None,
                timeout: float = PDF_TIMEOUT_SECONDS) -> Path | None:
    """
    Print an HTML file to PDF with headless Edge (or Chrome). Returns the PDF's
    path, or None on ANY failure (no browser, timeout, no file) - the HTML is
    always there as the fallback, so a missing PDF never stops anything.
    """
    try:
        html_path = Path(html_path).resolve()
        if not html_path.is_file():
            return None
        pdf_path = Path(pdf_path) if pdf_path else html_path.with_suffix(".pdf")
        pdf_path = pdf_path.resolve()
        browser = browser or find_browser()
        if not browser:
            return None
        if pdf_path.exists():
            pdf_path.unlink()
        profile = tempfile.mkdtemp(prefix="iot_pdf_")
        try:
            subprocess.run([browser, "--headless", "--disable-gpu", "--no-pdf-header-footer",
                            "--no-first-run", "--user-data-dir=%s" % profile,
                            "--print-to-pdf=%s" % pdf_path, html_path.as_uri()],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                           timeout=timeout, check=False)
        finally:
            shutil.rmtree(profile, ignore_errors=True)
        if pdf_path.is_file() and pdf_path.stat().st_size > 0:
            with open(pdf_path, "rb") as handle:
                if handle.read(5) == b"%PDF-":
                    return pdf_path
        return None
    except Exception:                 # noqa: BLE001 - None means "no PDF", whatever the cause
        return None


def write_pdf(report: dict, reports_dir: Path = REPORTS_DIR) -> Path | None:
    """reports/<session>.html (written fresh) printed to reports/<session>.pdf, or None."""
    return html_to_pdf(write_html(report, reports_dir))


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
    parser.add_argument("--pdf", action="store_true",
                        help="also print it to reports/<run>.pdf with Edge (Step P3)")
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
    if args.pdf:
        pdf = write_pdf(report)
        print("  wrote %s" % pdf if pdf else
              "  no PDF (Edge/Chrome not found or it failed) - open the HTML and print it "
              "to PDF from the browser")
    print()
    return 0


if __name__ == "__main__":
    sys.exit(main())
