"""
THE INCIDENT BRIEF - turning the findings into something a human can act on.

WHY A LANGUAGE MODEL AT ALL
---------------------------
Everything before this file produces a ranking, a graph and a set of numbers.
That is the right answer, but it is not yet useful to the person who has to
DO something about it - a site manager, a duty technician, somebody who does
not read network graphs. They need: what happened, which machine started it,
what to unplug first, and how sure we are.

A language model is good at that translation and bad at arithmetic and facts.
So the design here gives it exactly the job it is good at and removes every
opportunity to do the job it is bad at.

THE TWO GUARDS
--------------
1. THE SHAPE IS FORCED. The brief is described as a pydantic model, and that
   model's JSON schema is handed to Ollama as `format=`. The model is then
   physically unable to return prose, a missing field, or a different
   structure. This is not a request in the prompt that it might ignore - it
   is enforced during generation.

2. THE FACTS ARE CHECKED. Forcing the shape does nothing about invented
   CONTENT: a well-formed brief can still name a device that does not exist,
   cite an evidence id that was never issued, or quote a byte figure it made
   up. So before anything is shown, every brief is validated against the
   evidence that was passed in:

       - every evidence id it cites must exist
       - every device it names must be a real device
       - every address, port, timestamp and byte figure in its text must
         appear in the evidence

   Anything invented is rejected. We regenerate once. If the second attempt
   also fails, we abandon the model entirely and fall back to a plain
   template, and the brief is marked LLM_FALLBACK so nobody mistakes it for
   generated text.

WHY BOTHER, WHEN THE TEMPLATE ALWAYS WORKS
------------------------------------------
Because a template cannot phrase things for the reader, and because the
honest answer to "can you trust an LLM here?" is "only if you check it".
Building the checker is the interesting part of this step - the fallback
rate is a measured property of the system, reported by --batch, not a hope.

A NOTE ON WHAT "INVENTED" MEANS
-------------------------------
The validator is deliberately strict about identifiers and numbers, and
deliberately relaxed about English. "The camera sent an unusual amount of
data" is fine. "The camera sent 4.2 MB" is only fine if 4.2 MB is in the
evidence. Ordinary counting numbers ("three devices") are allowed; anything
carrying a unit, or any large bare number, must be traceable.
"""

from __future__ import annotations

import argparse
import difflib
import json
import re
import sys
from dataclasses import dataclass, field
from typing import Literal

import pandas as pd
from pydantic import BaseModel, Field

from src import attribute, detect, runs

# THE LOCAL MODEL, AND WHY IT IS NOT THE OBVIOUS ONE
# --------------------------------------------------
# qwen3:4b was the original choice and it was the wrong one twice over: it is
# a reasoning model, so every brief paid for a long hidden thinking passage
# that was then discarded, and its 256K context window did not fit in memory
# and spilled to disk. Twenty briefs took three hours.
#
# gemma3:4b fixes the first half - it is not a reasoning model - but on this
# machine it does not fit. It loads at 3.5 GB against roughly 2.9 GB of free
# VRAM (4 GB card, ~1.2 GB already in use), so Ollama pushes 54% of it onto
# the CPU. Measured: 219 seconds for a single brief, and the JSON came back
# truncated mid-string because the reply outgrew what was left of the window.
#
# llama3.2:3b loads at 80% on the GPU and produced the same brief in 37
# seconds. Both are non-reasoning models; this one actually fits.
LOCAL_MODEL = "llama3.2:3b"
MODEL = LOCAL_MODEL        # what --provider local uses, unless --model says otherwise

# The context window. The evidence prompt measures ~2,100 tokens and a brief
# runs to ~250, so 4096 holds both with room for the retry's extra text. This
# is the number that stops the 256K spill-to-disk.
NUM_CTX = 4096

TEMPERATURE = 0.1          # we want faithful, not creative
MAX_ATTEMPTS = 2           # generate, then one regeneration, then template
EVIDENCE_CONNECTIONS = 40  # how many raw connections to show the model

# Numbers below this are treated as ordinary English counting ("three
# devices", "rank 2") and are not required to appear in the evidence.
BARE_NUMBER_LIMIT = 1000

# How close a rounded figure (e.g. "4.2 MB") must be to a real one to pass.
UNIT_TOLERANCE = 0.02


# --------------------------------------------------------------------------
# The shape of a brief - this becomes the JSON schema handed to Ollama
# --------------------------------------------------------------------------

class OriginFinding(BaseModel):
    device: str = Field(description="the device the attack started from")
    confidence: int = Field(description="confidence percentage, 0-100")
    label: str = Field(description="one of: high, medium, low, cannot determine")


class TimelineEntry(BaseModel):
    time: str = Field(description="clock time as HH:MM:SS")
    device: str = Field(description="which device this step involves")
    what_happened: str = Field(description="one plain sentence, no jargon")
    evidence_ids: list[str] = Field(description="connection ids supporting this")


class RecommendedAction(BaseModel):
    order: int = Field(description="1 = do this first")
    action: str = Field(description="a concrete instruction")
    why: str = Field(description="one sentence on why it matters")
    urgency: Literal["now", "today", "this week"]


class IncidentBrief(BaseModel):
    headline: str = Field(description="one sentence a non-expert understands")
    origin: OriginFinding
    timeline: list[TimelineEntry]
    affected_devices: list[str]
    actions: list[RecommendedAction]
    uncertainty: str = Field(description="what we are NOT sure about, plainly")


@dataclass
class BriefResult:
    """A brief plus the story of how it was produced."""

    brief: IncidentBrief
    source: str                       # "llm" or "LLM_FALLBACK"
    attempts: int = 0
    rejections: list = field(default_factory=list)   # why each attempt failed
    error: str | None = None          # if the model could not be reached

    @property
    def is_fallback(self) -> bool:
        return self.source == "LLM_FALLBACK"


@dataclass
class BatchStats:
    """How the report layer behaved over many runs."""

    total: int = 0
    first_time: int = 0        # passed validation on attempt 1
    second_time: int = 0       # needed the one regeneration
    fallback: int = 0          # failed twice, fell back to the template
    unreachable: int = 0       # Ollama was not available at all
    reasons: list = field(default_factory=list)

    def report(self) -> str:
        if not self.total:
            return "no briefs generated"
        lines = [
            "  briefs generated:        %d" % self.total,
            "  passed first time:       %d  (%.0f%%)" % (
                self.first_time, 100 * self.first_time / self.total),
            "  passed after one retry:  %d  (%.0f%%)" % (
                self.second_time, 100 * self.second_time / self.total),
            "  fell back to template:   %d  (%.0f%%)" % (
                self.fallback, 100 * self.fallback / self.total),
        ]
        if self.unreachable:
            lines.append("  model unreachable:       %d" % self.unreachable)
        return "\n".join(lines)


# --------------------------------------------------------------------------
# The evidence pack - everything the model is allowed to know
# --------------------------------------------------------------------------

def clock(seconds: float) -> str:
    seconds = int(seconds)
    return "%02d:%02d:%02d" % (seconds // 3600, (seconds % 3600) // 60, seconds % 60)


def build_evidence(run: runs.Run, detection: detect.Detection,
                   result: attribute.Attribution) -> dict:
    """
    Assemble the facts the model may use - and nothing else.

    This doubles as the definition of truth for the validator: if a name, a
    number or an id is not in here, the brief may not contain it.
    """
    connections = run.connections

    verdict = "abstain" if result.abstained else "named"
    # Clamped for display - see Attribution.confidence_percent.
    confidence_pct = result.confidence_percent

    devices = []
    for name in run.device_names:
        onset = detection.onsets.get(name)
        devices.append({
            "device": name,
            "flagged": onset is not None,
            "onset": clock(onset) if onset is not None else None,
            "rank": result.ranking.index(name) + 1 if name in result.ranking else None,
        })

    # A sample of the actual connections that matter: for every device in the
    # ranking, its most notable traffic after it went abnormal.
    samples = []
    for device in result.ranking[:4]:
        onset = detection.onsets[device]
        after = connections[
            (connections["src"] == device) & (connections["t"] >= onset)
        ]
        if after.empty:
            continue
        notable = after.sort_values("bytes_out", ascending=False).head(3)
        earliest = after.sort_values("t").head(2)
        for _, row in pd.concat([earliest, notable]).drop_duplicates("conn_id").iterrows():
            samples.append({
                "id": row["conn_id"],
                "time": clock(row["t"]),
                "from": row["src"],
                "to": row["dst"],
                "port": int(row["dport"]),
                "bytes_sent": int(row["bytes_out"]),
            })
    samples = samples[:EVIDENCE_CONNECTIONS]

    links = []
    for edge in result.edge_evidence():
        links.append({
            "from": edge["from"], "to": edge["to"],
            "kind": edge["kind"], "detail": edge["detail"],
            "evidence_ids": edge["evidence_ids"],
        })

    return {
        "run_id": run.run_id,
        "verdict": verdict,
        "named_device": result.named,
        "shortlist": result.shortlist,
        "confidence_percent": confidence_pct,
        "confidence_label": _confidence_label(result),
        "attack_path": result.path,
        "ranking": [
            {"position": i + 1, "device": d}
            for i, d in enumerate(result.ranking)
        ],
        "devices": devices,
        "links_between_devices": links,
        "connections": samples,
        "capture_length": clock(run.capture_seconds),
        "baseline_ends": clock(run.baseline_seconds),
    }


def _confidence_label(result: attribute.Attribution) -> str:
    if result.abstained:
        return "cannot determine"
    if result.confidence >= 0.50:
        return "high"
    if result.confidence >= 0.25:
        return "medium"
    return "low"


# --------------------------------------------------------------------------
# The validator - the part that actually matters
# --------------------------------------------------------------------------

ID_PATTERN = re.compile(r"\bC\d{6}\b")
# Something that looks like a machine identifier: has a digit, hyphen or
# underscore in it. Ordinary English words are ignored.
IDENTIFIER_PATTERN = re.compile(r"\b[A-Za-z][A-Za-z0-9]*(?:[-_][A-Za-z0-9]+)*\b")
PORT_PATTERN = re.compile(r"\bport\s+(\d+)\b", re.I)
CLOCK_PATTERN = re.compile(r"\b(\d{1,2}:\d{2}(?::\d{2})?)\b")
UNIT_PATTERN = re.compile(r"\b(\d[\d,]*(?:\.\d+)?)\s*(bytes|byte|B|KB|MB|GB)\b")
NUMBER_PATTERN = re.compile(r"\b(\d[\d,]*(?:\.\d+)?)\b")

UNIT_MULTIPLIER = {"byte": 1, "bytes": 1, "b": 1, "kb": 1000, "mb": 1000000, "gb": 1000000000}

# Ordinary security vocabulary. These are generic terms, not claims that a
# device or address exists, so they are not treated as identifiers.
GENERIC_VOCABULARY = {
    "c2", "iot", "wifi", "wi-fi", "mqtt", "dns", "http", "https", "ip", "mac",
    "vpn", "usb", "ssh", "tcp", "udp", "tls", "ssl", "url", "llm_fallback",
}

# How similar an invented name has to be to a real one to count as a
# near-miss ("laptop-x" for "laptop-c").
NEAR_MISS_RATIO = 0.8


@dataclass
class AllowedFacts:
    """Everything a brief is permitted to say, derived from the evidence."""

    evidence_ids: set
    devices: set
    hosts: set
    ports: set
    clocks: set
    byte_values: set
    numbers: set

    @property
    def names(self) -> set:
        return self.devices | self.hosts


def allowed_facts_from(evidence: dict, run: runs.Run) -> AllowedFacts:
    """Read the evidence pack and work out what may legitimately be said."""
    ids = {c["id"] for c in evidence["connections"]}
    for link in evidence["links_between_devices"]:
        ids.update(link["evidence_ids"])

    devices = set(run.device_names)

    hosts = {c["to"] for c in evidence["connections"]}
    hosts |= {c["from"] for c in evidence["connections"]}
    hosts -= devices
    # Words that are part of the vocabulary rather than facts.
    hosts |= {"LLM_FALLBACK"}

    ports = {int(c["port"]) for c in evidence["connections"]}

    clocks = {c["time"] for c in evidence["connections"]}
    clocks |= {d["onset"] for d in evidence["devices"] if d["onset"]}
    clocks |= {evidence["capture_length"], evidence["baseline_ends"]}

    byte_values = {int(c["bytes_sent"]) for c in evidence["connections"]}

    numbers = set(byte_values) | set(ports)
    numbers.add(int(evidence["confidence_percent"]))
    numbers.update(range(0, BARE_NUMBER_LIMIT))    # ordinary counting language

    return AllowedFacts(
        evidence_ids=ids, devices=devices, hosts=hosts, ports=ports,
        clocks=clocks, byte_values=byte_values, numbers=numbers,
    )


def _all_text(brief: IncidentBrief) -> str:
    """Every piece of free text in the brief, joined for scanning."""
    parts = [brief.headline, brief.uncertainty, brief.origin.device,
             brief.origin.label]
    parts += list(brief.affected_devices)
    for entry in brief.timeline:
        parts += [entry.time, entry.device, entry.what_happened]
        parts += list(entry.evidence_ids)
    for action in brief.actions:
        parts += [action.action, action.why]
    return "\n".join(str(p) for p in parts)


def invented_names(text: str, facts: AllowedFacts) -> list:
    """
    Find names in the prose that claim a device or address exists when it does
    not. Two judgements are being made here, and both took a measurement to
    get right.

    WHAT COUNTS AS A NAME AT ALL. A token is treated as a machine name if it
    contains a digit or an underscore, or if it is suspiciously close to a
    real device name. Simply containing a hyphen is NOT enough: that rejected
    ordinary English like "highest-ranked" and "well-known", which inflated
    the fallback rate without catching a single real invention.

    The near-miss rule is the interesting half. "laptop-x" contains no digit
    and no underscore, so nothing about its shape marks it out - but it is one
    character from the real "laptop-c", which is exactly what a plausible
    fabrication looks like. Anything within 80% similarity of a real name must
    BE that name.

    CASE DOES NOT MATTER. "Cam2" at the start of a sentence is the device
    cam2. Rejecting it was the single largest source of fallbacks, and it was
    the validator being wrong rather than the model inventing anything.
    Structured fields are still matched exactly, because the dashboard looks
    devices up by name; only prose is read case-insensitively.
    """
    real_names = {name.lower() for name in facts.names}
    known = real_names | GENERIC_VOCABULARY
    found = []

    for token in sorted(set(IDENTIFIER_PATTERN.findall(text))):
        lowered = token.lower()
        if lowered in known:
            continue
        if ID_PATTERN.fullmatch(token) or CLOCK_PATTERN.fullmatch(token):
            continue

        has_digit = any(ch.isdigit() for ch in token)
        has_underscore = "_" in token
        has_hyphen = "-" in token

        # Nothing without a digit, underscore or hyphen is a machine name in
        # this lab, and ordinary words must never be examined further. (The
        # word "it" is an 80% match for "iot"; comparing every English word
        # against the vocabulary produced exactly that false positive.)
        if not (has_digit or has_underscore or has_hyphen):
            continue

        if (has_digit or has_underscore) and len(token) >= 3:
            found.append(token)
            continue

        # Hyphenated and otherwise unremarkable: only suspicious if it is a
        # near-miss of a REAL device name. Compared against device and host
        # names only - never the generic vocabulary, which is short and
        # collides with common words.
        if difflib.get_close_matches(lowered, real_names, n=1, cutoff=NEAR_MISS_RATIO):
            found.append(token)

    return found


def validate_brief(brief: IncidentBrief, facts: AllowedFacts,
                   evidence: dict) -> list:
    """
    Check a brief against the evidence. Returns a list of problems; an empty
    list means the brief is safe to show.
    """
    problems = []
    text = _all_text(brief)

    # --- 1. every evidence id it cites must exist -------------------------
    for entry in brief.timeline:
        if not entry.evidence_ids:
            problems.append(
                "timeline entry for %s cites no evidence at all" % entry.device
            )
        for cited in entry.evidence_ids:
            if cited not in facts.evidence_ids:
                problems.append("invented evidence id %r" % cited)
    for cited in set(ID_PATTERN.findall(text)):
        if cited not in facts.evidence_ids:
            problems.append("invented evidence id %r in the text" % cited)

    # --- 2. every device it names must be real ---------------------------
    if brief.origin.device not in facts.devices:
        problems.append("origin names a device that does not exist: %r"
                        % brief.origin.device)
    for name in brief.affected_devices:
        if name not in facts.devices:
            problems.append("affected_devices lists a device that does not "
                            "exist: %r" % name)
    for entry in brief.timeline:
        if entry.device not in facts.devices:
            problems.append("timeline names a device that does not exist: %r"
                            % entry.device)

    # ...and no invented machine-looking name anywhere in the prose.
    for token in invented_names(text, facts):
        problems.append("mentions %r, which is not a real device or address" % token)

    # --- 3. the verdict must match what we actually concluded ------------
    if evidence["verdict"] == "named":
        if brief.origin.device != evidence["named_device"]:
            problems.append(
                "brief blames %r but the analysis named %r"
                % (brief.origin.device, evidence["named_device"])
            )
    else:
        if brief.origin.device not in evidence["shortlist"]:
            problems.append(
                "the analysis abstained, but the brief blames %r which is not "
                "even on the shortlist" % brief.origin.device
            )
    if abs(brief.origin.confidence - evidence["confidence_percent"]) > 1:
        problems.append(
            "brief states %d%% confidence but the analysis computed %d%%"
            % (brief.origin.confidence, evidence["confidence_percent"])
        )

    # --- 4. ports, timestamps and byte figures must be traceable ---------
    for port in set(PORT_PATTERN.findall(text)):
        if int(port) not in facts.ports:
            problems.append("quotes port %s, which is not in the evidence" % port)

    for stamp in set(CLOCK_PATTERN.findall(text)):
        if stamp in facts.clocks:
            continue
        if any(known.startswith(stamp) for known in facts.clocks):
            continue          # HH:MM is fine when HH:MM:SS is in evidence
        problems.append("quotes time %s, which is not in the evidence" % stamp)

    for raw, unit in UNIT_PATTERN.findall(text):
        value = float(raw.replace(",", "")) * UNIT_MULTIPLIER[unit.lower()]
        if not _close_to_any(value, facts.byte_values):
            problems.append("quotes a figure of %s %s, which is not in the "
                            "evidence" % (raw, unit))

    # Large bare numbers - an invented byte count written without a unit.
    for raw in set(NUMBER_PATTERN.findall(text)):
        if ":" in raw or "." in raw:
            continue
        value = int(raw.replace(",", ""))
        if value < BARE_NUMBER_LIMIT:
            continue
        if value in facts.numbers or _close_to_any(float(value), facts.byte_values):
            continue
        problems.append("quotes the figure %s, which is not in the evidence" % raw)

    # --- 5. basic completeness -------------------------------------------
    if not brief.timeline:
        problems.append("the brief has no timeline")
    if not brief.actions:
        problems.append("the brief recommends no actions")

    return problems


def _close_to_any(value: float, known: set) -> bool:
    for candidate in known:
        if candidate == 0:
            if value == 0:
                return True
            continue
        if abs(value - candidate) / abs(candidate) <= UNIT_TOLERANCE:
            return True
    return False


# --------------------------------------------------------------------------
# Talking to the model
# --------------------------------------------------------------------------

SYSTEM_PROMPT = """You write short incident briefs for people who are not \
security experts - a site manager or a duty technician.

ABSOLUTE RULES:
- Use ONLY facts from the evidence you are given. Invent nothing.
- Never mention a device, address, port, time or byte figure that is not in \
the evidence.
- Every timeline entry must cite at least one real connection id from the \
evidence (they look like C012345).
- The origin device, the confidence percentage and the confidence label must \
match the analysis exactly. Do not adjust them.
- Write plainly. No jargon, no hedging, no marketing language.
- If the analysis abstained, say clearly that the origin could not be \
determined and name the shortlist."""


def _build_user_prompt(evidence: dict, previous_problems=None) -> str:
    parts = [
        "Here is the completed analysis of one network incident.",
        "",
        json.dumps(evidence, indent=2),
        "",
        "Write the incident brief.",
    ]
    if previous_problems:
        parts += [
            "",
            "YOUR PREVIOUS ATTEMPT WAS REJECTED because it contained things "
            "that are not in the evidence:",
        ]
        parts += ["  - %s" % p for p in previous_problems[:8]]
        parts += ["", "Fix these. Use only what is in the evidence above."]
    return "\n".join(parts)


def generate_brief(evidence: dict, facts: AllowedFacts, run: runs.Run,
                   result: attribute.Attribution,
                   model: str = MODEL, max_attempts: int = MAX_ATTEMPTS,
                   offline: bool = False) -> BriefResult:
    """
    Ask the model for a brief, check it, and retry once if it invents things.
    Falls back to the template if it fails twice, or if the model is not
    reachable at all.
    """
    if offline:
        return BriefResult(brief=template_brief(evidence, run, result),
                           source="LLM_FALLBACK", attempts=0,
                           rejections=["offline mode - template used by request"])

    try:
        import ollama
    except ImportError:
        return BriefResult(brief=template_brief(evidence, run, result),
                           source="LLM_FALLBACK", attempts=0,
                           error="the ollama package is not installed")

    rejections = []
    problems = None

    for attempt in range(1, max_attempts + 1):
        try:
            response = ollama.chat(
                model=model,
                messages=[
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user", "content": _build_user_prompt(evidence, problems)},
                ],
                # THIS is what forces the structure: the pydantic model's own
                # JSON schema is handed to Ollama, which constrains generation.
                format=IncidentBrief.model_json_schema(),
                options={"temperature": TEMPERATURE, "num_ctx": NUM_CTX},
                # Neither local model reasons, so this changes nothing for
                # them - it is here so that pointing --model at a reasoning
                # model cannot quietly reintroduce the three-hour problem.
                think=False,
            )
            raw = response["message"]["content"]
            brief = IncidentBrief.model_validate_json(raw)
        except Exception as exc:      # unreachable, timeout, malformed JSON
            rejections.append("attempt %d failed: %s" % (attempt, exc))
            problems = ["the previous reply could not be parsed at all"]
            continue

        problems = validate_brief(brief, facts, evidence)
        if not problems:
            return BriefResult(brief=brief, source="llm", attempts=attempt,
                               rejections=rejections)
        rejections.append("attempt %d rejected: %s" % (attempt, "; ".join(problems[:4])))

    return BriefResult(brief=template_brief(evidence, run, result),
                       source="LLM_FALLBACK", attempts=max_attempts,
                       rejections=rejections)


# --------------------------------------------------------------------------
# The fallback template - plain, dull, and always correct
# --------------------------------------------------------------------------

def template_brief(evidence: dict, run: runs.Run,
                   result: attribute.Attribution) -> IncidentBrief:
    """
    Build the brief mechanically from the evidence.

    It reads less well than a generated one, but it cannot be wrong: every
    value is copied straight from the analysis. This is what gets shown when
    the model invents things twice, and it is why the system can never
    present an unverified claim.
    """
    named = evidence["named_device"]
    abstained = evidence["verdict"] == "abstain"

    if abstained:
        headline = (
            "A network intrusion was detected, but the starting device could "
            "not be identified with confidence. The three most likely are %s."
            % ", ".join(evidence["shortlist"])
        )
        origin_device = evidence["shortlist"][0] if evidence["shortlist"] else run.device_names[0]
    else:
        headline = (
            "A network intrusion was detected. It appears to have started on "
            "%s and spread to other devices." % named
        )
        origin_device = named

    timeline = []
    by_time = sorted(
        [d for d in evidence["devices"] if d["flagged"]],
        key=lambda d: d["onset"],
    )
    for device in by_time:
        ids = [c["id"] for c in evidence["connections"] if c["from"] == device["device"]][:2]
        if not ids:
            ids = [c["id"] for c in evidence["connections"]][:1]
        timeline.append(TimelineEntry(
            time=device["onset"],
            device=device["device"],
            what_happened="%s began behaving differently from its normal pattern."
                          % device["device"],
            evidence_ids=ids,
        ))

    actions = [
        RecommendedAction(
            order=1,
            action="Disconnect %s from the network." % origin_device,
            why="It is the most likely starting point, so isolating it first "
                "stops the spread.",
            urgency="now",
        ),
        RecommendedAction(
            order=2,
            action="Check the other devices listed as affected.",
            why="They may already be compromised and acting on instructions.",
            urgency="today",
        ),
        RecommendedAction(
            order=3,
            action="Change the passwords and keys used by these devices.",
            why="Any credentials on a compromised device should be assumed known.",
            urgency="this week",
        ),
    ]

    if abstained:
        uncertainty = (
            "The analysis could not separate the top candidates: the gap "
            "between them was only %d%%. Treat all three on the shortlist as "
            "suspects rather than acting against one."
            % evidence["confidence_percent"]
        )
    else:
        uncertainty = (
            "Confidence in the starting device is %d%% (%s). Devices that "
            "only received traffic may not appear here, because this analysis "
            "sees devices by what they send."
            % (evidence["confidence_percent"], evidence["confidence_label"])
        )

    return IncidentBrief(
        headline=headline,
        origin=OriginFinding(
            device=origin_device,
            confidence=evidence["confidence_percent"],
            label=evidence["confidence_label"],
        ),
        timeline=timeline,
        affected_devices=[d["device"] for d in evidence["devices"] if d["flagged"]],
        actions=actions,
        uncertainty=uncertainty,
    )


# --------------------------------------------------------------------------
# Putting it together
# --------------------------------------------------------------------------

def brief_for_run(run_id: str, offline: bool = False, model: str = MODEL) -> tuple:
    """Load a run, analyse it, and produce a validated brief."""
    run = runs.load_run(run_id)
    detection = detect.detect_run(run)
    result = attribute.attribute_run(run, detection)

    evidence = build_evidence(run, detection, result)
    facts = allowed_facts_from(evidence, run)
    outcome = generate_brief(evidence, facts, run, result,
                             model=model, offline=offline)
    return outcome, evidence, result


def render(brief: IncidentBrief, source: str) -> str:
    """Print the brief the way a person should read it."""
    lines = []
    if source == "LLM_FALLBACK":
        lines.append("  [ LLM_FALLBACK - generated text was rejected, this is "
                     "the plain template ]")
        lines.append("")
    lines.append("  " + brief.headline)
    lines.append("")
    lines.append("  ORIGIN:  %s   (confidence %d%%, %s)"
                 % (brief.origin.device, brief.origin.confidence, brief.origin.label))
    lines.append("")
    lines.append("  WHAT HAPPENED")
    for entry in brief.timeline:
        lines.append("    %s  %-11s %s" % (entry.time, entry.device, entry.what_happened))
        lines.append("    %s  %-11s evidence: %s"
                     % (" " * 8, "", ", ".join(entry.evidence_ids)))
    lines.append("")
    lines.append("  AFFECTED DEVICES")
    lines.append("    %s" % ", ".join(brief.affected_devices))
    lines.append("")
    lines.append("  WHAT TO DO")
    for action in sorted(brief.actions, key=lambda a: a.order):
        lines.append("    %d. [%s] %s" % (action.order, action.urgency.upper(), action.action))
        lines.append("       why: %s" % action.why)
    lines.append("")
    lines.append("  WHAT WE ARE NOT SURE ABOUT")
    lines.append("    %s" % brief.uncertainty)
    return "\n".join(lines)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Write an incident brief.")
    parser.add_argument("run_id", nargs="?", help="e.g. run_000")
    parser.add_argument("--offline", action="store_true",
                        help="skip the model and use the plain template")
    parser.add_argument("--model", default=MODEL)
    parser.add_argument("--batch", type=int, default=None,
                        help="generate this many briefs and report the fallback rate")
    parser.add_argument("--show-evidence", action="store_true")
    args = parser.parse_args(argv)

    if args.batch:
        stats = BatchStats()
        run_ids = runs.list_runs(prefix="run")[:args.batch]
        for i, run_id in enumerate(run_ids, 1):
            outcome, _, _ = brief_for_run(run_id, offline=args.offline, model=args.model)
            stats.total += 1
            if outcome.is_fallback:
                stats.fallback += 1
                stats.reasons.append((run_id, outcome.rejections))
            elif outcome.attempts == 1:
                stats.first_time += 1
            else:
                stats.second_time += 1
            print("    %2d/%-3d %-10s %-14s %s"
                  % (i, len(run_ids), run_id, outcome.source,
                     "attempt %d" % outcome.attempts if not outcome.is_fallback else
                     "rejected twice"))
        print("\n" + stats.report())
        if stats.reasons:
            print("\n  why the fallbacks happened:")
            for run_id, why in stats.reasons[:5]:
                for line in why:
                    print("    %-10s %s" % (run_id, line[:150]))
        print()
        return 0

    if not args.run_id:
        parser.error("give a run_id, or use --batch N")

    outcome, evidence, _ = brief_for_run(args.run_id, offline=args.offline,
                                         model=args.model)
    if args.show_evidence:
        print(json.dumps(evidence, indent=2))

    print("\n  === INCIDENT BRIEF: %s ===\n" % args.run_id)
    print(render(outcome.brief, outcome.source))
    print("\n  ---")
    print("  source: %s   attempts: %d" % (outcome.source, outcome.attempts))
    for line in outcome.rejections:
        print("  %s" % line[:200])
    print()
    return 0


if __name__ == "__main__":
    sys.exit(main())
