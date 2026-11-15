"""
THE AI ANALYST - a cloud model writes the "Analyst summary", and nothing else
(Step P4 of docs/POLISH_PLAN.md).

WHAT IT DOES
------------
When the live engine raises its first alert (and once more at STOP), this file
sends the cloud model a handful of facts about the incident and asks for a
2-3 sentence summary a non-expert can read. The answer is shown on the page and
in the report ONLY if it passes the same evidence check every model text in this
project passes (report.validate_brief); otherwise the report keeps its template
wording and says so.

WHY CLOUD
---------
The local model (llama3.2:3b via Ollama) took 45+ minutes per answer on this
laptop - useless while an alert is ringing. The cloud model answered the first
real test in 8.0 s (15 Nov 2026, gemini-3.6-flash). Internet is assumed for the
demo, but the page is complete without it: the template wording is always there.

WHAT IT MAY SAY - ONLY WHAT DOES NOT CHANGE MINUTE TO MINUTE
------------------------------------------------------------
The summary sits beside cards that update every 3 seconds. If it said "7
connections so far" it would disagree with them a minute later. So the model is
given only facts that are fixed once the alert is raised: the device, the time
of its first unusual connection, the destination address and port, the interval
between connections, and the bytes sent and received each time. No running
counts, no scores, no confidence, nothing about other devices. A summary that
mentions a running count or another lab device is rejected.

WHAT IT CAN NEVER DO
--------------------
The verdict, the numbers and the playbook never come from the model. It cannot
change a phase, a score or the CONTAINED check: it runs in a background thread,
its answer is one more field in the report ("analyst"), and the engine's tick
never waits for it. The answer is checked by report.validate_brief, with the
allowed facts being exactly the facts the model was given.

WHAT LEAVES THE LAPTOP
----------------------
Device names, MAC and IP addresses, ports, clock times and byte counts - the
facts below. No packet contents, no Wi-Fi password. The key is read from
API_KEY.env at call time (report._gemini_key) and is never printed, logged or
written to analyst.json.

THE LIMITS
----------
25 s per attempt, one retry (with the validator's objections, so the model can
fix them). At STOP the whole ask has one 25 s budget, so a hanging network can
delay the final report by 25 s at most. The answer is cached as
pcap/live/<session>/analyst.json.
"""

from __future__ import annotations

import json
import os
import re
import threading
import time
from datetime import datetime
from pathlib import Path

from src import incident, report

ANALYST_FILE = "analyst.json"
MODEL = report.CLOUD_MODEL
LIMIT_SECONDS = 25.0          # per attempt
ATTEMPTS = 2                  # one try, one retry
STOP_BUDGET_SECONDS = 25.0    # the whole ask at STOP
MAX_SENTENCES = 3
MAX_CHARACTERS = 600

# statuses of an analyst record
ASKING = "asking"
OK = "ok"
REJECTED = "rejected"          # answered, but failed the evidence check twice
UNREACHABLE = "unreachable"    # no answer: offline, timeout, HTTP error
NO_KEY = "no key"              # API_KEY.env missing or has no key line


SYSTEM_PROMPT = """You are the analyst on a network security console. Write the \
"Analyst summary" of one incident for a person who is not a security expert.

RULES:
- 2 or 3 short, plain sentences.
- Use ONLY the facts given. Invent nothing.
- Say which device, when its first unusual connection was, the destination \
address and port, how often it connected and how many bytes it sent each time \
(and received, if given).
- Write the time, address and numbers exactly as given.
- Do NOT give counts of connections, packets or minutes, scores, confidence \
levels, or anything about other devices. Do NOT recommend actions."""


# --------------------------------------------------------------------------
# The facts the model is given
# --------------------------------------------------------------------------

def analyst_facts(report_dict: dict, addresses=None) -> dict | None:
    """
    The fixed facts of an incident, from the engine's report, or None when
    there is nothing for the analyst to describe (no named device, or no new
    repeating destination - then the template wording is used).
    """
    if not report_dict or report_dict.get("status") in (None, "failed", "no incident"):
        return None
    where = report_dict.get("where") or {}
    named = where.get("named")
    patterns = (report_dict.get("how") or {}).get("patterns") or []
    if not named or not patterns:
        return None
    addresses = dict(report_dict.get("addresses") or {}, **(addresses or {}))
    p = patterns[0]
    when = report_dict.get("when") or {}
    if when.get("first_unusual_epoch") is not None:
        first = datetime.fromtimestamp(float(when["first_unusual_epoch"])).strftime("%H:%M:%S")
    else:
        first = incident.clock_text(when.get("first_unusual_seconds"))
    facts = {
        "device": named,
        "device_address": incident.address_of(named, addresses),
        "first_unusual_connection": first,
        "first_connection_id": p.get("first_id") or when.get("first_unusual_id"),
        "destination": incident.address_label(p["label"], addresses),
        "port": int(p["dport"]),
        "interval_seconds": (int(round(p["typical_gap_seconds"]))
                             if p.get("typical_gap_seconds") is not None else None),
        "bytes_sent_each_time": int(p["typical_bytes_out"]),
        "bytes_received_each_time": int(p["typical_bytes_in"]),
        "new_destination": "never used while its normal behaviour was learned",
    }
    return {k: v for k, v in facts.items() if v is not None}


# --------------------------------------------------------------------------
# The check: the existing validator, plus the two P4 rules
# --------------------------------------------------------------------------

RUNNING_COUNT = re.compile(r"\b\d[\d,]*\s+(?:[a-z-]+\s+)?(?:connections?|packets?|beacons?|"
                           r"times|attempts?|minutes?|messages?)\b", re.I)
SENTENCE_END = re.compile(r"[.!?](?:\s|$)")


def check_summary(summary: str, facts: dict, device_names) -> list:
    """
    Problems with a summary; an empty list means it may be shown. The text is
    put through report.validate_brief (wrapped as a brief whose allowed facts
    are exactly `facts`), then the P4 rules: short, no running counts, no other
    device, and it names the device.
    """
    problems = []
    text = (summary or "").strip()
    if not text:
        return ["the summary is empty"]
    if len(text) > MAX_CHARACTERS or len(SENTENCE_END.findall(text + " ")) > MAX_SENTENCES:
        problems.append("longer than %d sentences" % MAX_SENTENCES)
    for match in RUNNING_COUNT.findall(text):
        problems.append("states a running count (%r), which changes minute to minute" % match)
    lowered = text.lower()
    if facts["device"].lower() not in lowered:
        problems.append("does not name the device %s" % facts["device"])
    for other in device_names:
        if other != facts["device"] and re.search(r"(?<![\w-])%s(?![\w-])" % re.escape(other.lower()),
                                                  lowered):
            problems.append("mentions another device, %s" % other)

    ids = {facts["first_connection_id"]} if facts.get("first_connection_id") else {"C000000"}
    first_id = next(iter(ids))
    byte_values = {facts["bytes_sent_each_time"], facts["bytes_received_each_time"]}
    numbers = set(byte_values) | {facts["port"]} | set(range(0, report.BARE_NUMBER_LIMIT))
    if facts.get("interval_seconds") is not None:
        numbers.add(facts["interval_seconds"])
    allowed = report.AllowedFacts(
        evidence_ids=ids, devices=set(device_names) | {facts["device"]}, hosts=set(),
        ports={facts["port"]}, clocks={facts["first_unusual_connection"]},
        byte_values=byte_values, numbers=numbers)
    brief = report.IncidentBrief(
        headline=text,
        origin=report.OriginFinding(device=facts["device"], confidence=100, label="high"),
        timeline=[report.TimelineEntry(time=facts["first_unusual_connection"],
                                       device=facts["device"], what_happened=text,
                                       evidence_ids=[first_id])],
        affected_devices=[facts["device"]],
        actions=[report.RecommendedAction(order=1, action="Follow the playbook.",
                                          why="The steps come from the measurements.",
                                          urgency="now")],
        uncertainty="")
    evidence = {"verdict": "named", "named_device": facts["device"], "shortlist": [facts["device"]],
                "confidence_percent": 100}
    problems += report.validate_brief(brief, allowed, evidence)
    return problems


# --------------------------------------------------------------------------
# Talking to the model
# --------------------------------------------------------------------------

def key_available() -> bool:
    """
    Is there a key? Checked without ever returning or printing it.
    IOT_NO_CLOUD=1 (set by the tests) means no: no test reaches the real cloud.
    """
    if os.environ.get("IOT_NO_CLOUD"):
        return False
    try:
        report._gemini_key()
        return True
    except Exception:            # noqa: BLE001 - any failure means "no key"
        return False


def cloud_transport(model: str, system: str, user: str, timeout: float) -> str:
    """One request to the cloud model; returns the summary text. Raises on any failure."""
    import requests
    response = requests.post(
        report.GEMINI_ENDPOINT % model,
        headers={"x-goog-api-key": report._gemini_key(), "Content-Type": "application/json"},
        json={"systemInstruction": {"parts": [{"text": system}]},
              "contents": [{"role": "user", "parts": [{"text": user}]}],
              "generationConfig": {
                  "temperature": report.TEMPERATURE,
                  "responseMimeType": "application/json",
                  "responseSchema": {"type": "object",
                                     "properties": {"summary": {"type": "string"}},
                                     "required": ["summary"]},
                  "thinkingConfig": {"thinkingLevel": "low"}}},
        timeout=timeout)
    if response.status_code != 200:
        raise RuntimeError("HTTP %d" % response.status_code)   # the body is not kept
    candidates = response.json().get("candidates") or []
    if not candidates:
        raise RuntimeError("no answer")
    parts = candidates[0].get("content", {}).get("parts") or []
    raw = "".join(part.get("text", "") for part in parts if not part.get("thought"))
    return str(json.loads(raw)["summary"])


def _user_prompt(facts: dict, problems=None) -> str:
    text = "The incident's facts:\n" + json.dumps(facts, indent=2) + "\n\nWrite the summary."
    if problems:
        text += ("\n\nYOUR PREVIOUS SUMMARY WAS REJECTED:\n"
                 + "\n".join("  - %s" % p for p in problems[:6])
                 + "\nFix these. Use only the facts above.")
    return text


def ask(facts: dict, device_names, transport=None, model: str = MODEL,
        attempts: int = ATTEMPTS, limit: float = LIMIT_SECONDS,
        budget: float | None = None, clock=time.monotonic) -> dict:
    """
    Ask once (plus one retry). Returns the analyst record:
      status   ok / rejected / unreachable / no key
      summary  the checked text (only when ok)
      model, facts, seconds, attempts, problems (short reasons, never the key)
    """
    started = clock()
    record = {"status": UNREACHABLE, "model": model, "facts": facts, "summary": None,
              "attempts": 0, "problems": [], "asked_epoch": time.time()}
    if transport is None:
        if not key_available():
            record.update(status=NO_KEY, problems=["%s not found or has no key" % report.API_KEY_FILE],
                          seconds=0.0)
            return record
        transport = cloud_transport
    problems = None
    answered = False
    for attempt in range(1, attempts + 1):
        timeout = limit
        if budget is not None:
            timeout = min(limit, budget - (clock() - started))
            if timeout <= 0.5:
                break
        record["attempts"] = attempt
        try:
            summary = transport(model, SYSTEM_PROMPT, _user_prompt(facts, problems), timeout)
        except Exception as exc:          # noqa: BLE001 - offline, timeout, HTTP error, bad JSON
            record["problems"].append("attempt %d: no answer (%s)" % (attempt, type(exc).__name__))
            continue
        answered = True
        problems = check_summary(summary, facts, device_names)
        if not problems:
            record.update(status=OK, summary=summary.strip())
            break
        record["problems"].append("attempt %d rejected: %s" % (attempt, "; ".join(problems[:3])))
    if record["status"] != OK:
        record["status"] = REJECTED if answered else UNREACHABLE
    record["seconds"] = round(clock() - started, 2)
    return record


# --------------------------------------------------------------------------
# The engine's helper: one background ask at a time, cached on disk
# --------------------------------------------------------------------------

class Analyst:
    """
    Owned by the live engine when it runs with --llm cloud. ask_in_background
    starts a thread and returns at once; current() is what the engine copies
    into the report each cycle. Thread-safe; the engine never waits for it,
    except finish(), which asks once more within STOP_BUDGET_SECONDS.
    """

    def __init__(self, folder, device_names, transport=None, model: str = MODEL):
        self.folder = Path(folder)
        self.device_names = list(device_names)
        self.transport = transport
        self.model = model
        self._lock = threading.Lock()
        self._record = None
        self._thread = None
        self.changes = 0              # bumped whenever the record changes
        self.calls = []               # (stage, status, seconds) of every finished ask

    def current(self) -> dict | None:
        with self._lock:
            return None if self._record is None else dict(self._record)

    def _set(self, record: dict) -> None:
        with self._lock:
            self._record = record
            self.changes += 1
            if record.get("status") != ASKING and "seconds" in record                     and "stop_attempt" not in record:
                self.calls.append({"stage": record.get("stage"), "status": record["status"],
                                   "seconds": record["seconds"]})
        try:
            path = self.folder / ANALYST_FILE
            part = path.with_name(path.name + ".part")
            part.write_text(json.dumps(record, indent=2), encoding="utf-8")
            part.replace(path)
        except OSError:
            pass                       # the cache is a convenience; the record is in memory

    def busy(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def ask_in_background(self, facts: dict, stage: str = "alert") -> bool:
        """Start one ask, unless one is running. Returns True if it started."""
        if facts is None or self.busy():
            return False
        self._set({"status": ASKING, "model": self.model, "facts": facts, "summary": None,
                   "stage": stage, "asked_epoch": time.time()})

        def work():
            record = ask(facts, self.device_names, transport=self.transport, model=self.model)
            record["stage"] = stage
            self._set(record)

        self._thread = threading.Thread(target=work, name="analyst", daemon=True)
        self._thread.start()
        return True

    def ask_at_stop(self, facts: dict, budget: float = STOP_BUDGET_SECONDS) -> dict | None:
        """
        The final report's ask, within one budget. A thread still running from
        the alert is waited for first (inside the same budget). If this ask
        fails but the alert's answer passed for the SAME facts, that answer is
        kept - it describes the final report exactly as well.
        """
        if facts is None:
            return self.current()
        started = time.monotonic()
        if self.busy():
            self._thread.join(timeout=budget)
        remaining = budget - (time.monotonic() - started)
        earlier = self.current()
        if remaining <= 0.5:
            return earlier
        record = ask(facts, self.device_names, transport=self.transport, model=self.model,
                     budget=remaining)
        record["stage"] = "stop"
        if record["status"] != OK and earlier and earlier.get("status") == OK                 and earlier.get("facts") == facts:
            with self._lock:
                self.calls.append({"stage": "stop", "status": record["status"],
                                   "seconds": record["seconds"]})
        if record["status"] != OK and earlier and earlier.get("status") == OK \
                and earlier.get("facts") == facts:
            earlier = dict(earlier, stop_attempt=record["status"])
            self._set(earlier)
            return earlier
        self._set(record)
        return record

    def join(self, timeout: float | None = None) -> None:
        if self._thread is not None:
            self._thread.join(timeout)
