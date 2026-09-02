"""
Tests for src/report.py - the incident brief and, mostly, its validator.

WHY THE VALIDATOR GETS THE MOST ATTENTION
-----------------------------------------
The language model is the least trustworthy component in the project, and it
is the one whose output a non-expert is meant to act on. Forcing the JSON
schema guarantees the SHAPE is right; it guarantees nothing about the
CONTENT. A perfectly well-formed brief can name a device that does not exist,
cite an evidence id that was never issued, or quote a byte figure it invented.

So the validator is the thing standing between a plausible fabrication and a
person unplugging the wrong machine. These tests plant one invention at a
time and demand it is caught. If the validator ever stops catching one of
these, the whole "verified before shown" claim collapses - quietly, because
nothing would crash.

None of these tests need Ollama. They build briefs directly, which is the
point: the checking logic must be testable without the unpredictable part.
The tests that DO need a model are marked and skipped when it is absent.
"""

import pytest

from src import attribute, detect, report, runs

pytestmark = pytest.mark.filterwarnings("ignore")


@pytest.fixture(scope="module")
def analysed():
    """One real run, analysed - the evidence every test works against."""
    run = runs.load_run("run_001")
    detection = detect.detect_run(run)
    result = attribute.attribute_run(run, detection)
    evidence = report.build_evidence(run, detection, result)
    facts = report.allowed_facts_from(evidence, run)
    return run, detection, result, evidence, facts


@pytest.fixture
def honest(analysed):
    """A brief that is true by construction - the control for every test."""
    run, _, result, evidence, _ = analysed
    return report.template_brief(evidence, run, result)


def problems_with(brief, analysed):
    _, _, _, evidence, facts = analysed
    return report.validate_brief(brief, facts, evidence)


# --------------------------------------------------------------------------
# The control: an honest brief must pass
# --------------------------------------------------------------------------

def test_the_template_brief_is_accepted(honest, analysed):
    """
    If this fails, every rejection test below is meaningless - they would be
    detecting a broken validator rather than a dishonest brief.
    """
    assert problems_with(honest, analysed) == []


def test_the_template_brief_is_complete(honest):
    assert honest.headline
    assert honest.origin.device
    assert honest.timeline
    assert honest.actions
    assert honest.uncertainty
    for entry in honest.timeline:
        assert entry.evidence_ids, "a timeline entry with no evidence"


# --------------------------------------------------------------------------
# Invented devices
# --------------------------------------------------------------------------

def test_a_device_that_does_not_exist_is_rejected(honest, analysed):
    """The headline case: the brief blames a machine that is not on the network."""
    brief = honest.model_copy(deep=True)
    brief.origin.device = "esp32-99"

    problems = problems_with(brief, analysed)
    assert problems
    assert any("esp32-99" in p for p in problems)


def test_an_invented_device_in_the_affected_list_is_rejected(honest, analysed):
    brief = honest.model_copy(deep=True)
    brief.affected_devices = list(brief.affected_devices) + ["laptop-x"]

    assert any("laptop-x" in p for p in problems_with(brief, analysed))


def test_an_invented_device_in_the_timeline_is_rejected(honest, analysed):
    brief = honest.model_copy(deep=True)
    brief.timeline[0].device = "thermostat-2"

    assert any("thermostat-2" in p for p in problems_with(brief, analysed))


def test_an_invented_device_buried_in_prose_is_rejected(honest, analysed):
    """
    The subtle one. Every structured field is legitimate; the fabrication is
    in a sentence. Checking only the structured fields would miss it entirely.
    """
    brief = honest.model_copy(deep=True)
    brief.headline = "esp32-01 attacked printer-07 over the network"

    assert any("printer-07" in p for p in problems_with(brief, analysed))


def test_real_device_names_in_prose_are_not_flagged(honest, analysed):
    """The mirror test: the validator must not cry wolf about real devices."""
    brief = honest.model_copy(deep=True)
    brief.headline = "The incident started on esp32-01 and reached laptop-c."

    assert problems_with(brief, analysed) == []


def test_ordinary_english_is_not_mistaken_for_an_identifier(honest, analysed):
    brief = honest.model_copy(deep=True)
    brief.uncertainty = (
        "We cannot be certain which device was first. Three devices look "
        "similar, and the evidence is circumstantial rather than conclusive."
    )
    assert problems_with(brief, analysed) == []


# --------------------------------------------------------------------------
# Invented evidence ids
# --------------------------------------------------------------------------

def test_an_evidence_id_that_was_never_issued_is_rejected(honest, analysed):
    brief = honest.model_copy(deep=True)
    brief.timeline[0].evidence_ids = ["C999999"]

    assert any("C999999" in p for p in problems_with(brief, analysed))


def test_a_timeline_entry_citing_no_evidence_is_rejected(honest, analysed):
    """A claim with no evidence behind it is exactly what we are guarding against."""
    brief = honest.model_copy(deep=True)
    brief.timeline[0].evidence_ids = []

    assert any("cites no evidence" in p for p in problems_with(brief, analysed))


# --------------------------------------------------------------------------
# Invented numbers
# --------------------------------------------------------------------------

def test_a_port_not_in_the_evidence_is_rejected(honest, analysed):
    brief = honest.model_copy(deep=True)
    brief.headline = "The device contacted a server on port 31337"

    assert any("31337" in p for p in problems_with(brief, analysed))


def test_a_real_port_is_accepted(honest, analysed):
    _, _, _, evidence, _ = analysed
    real_port = evidence["connections"][0]["port"]

    brief = honest.model_copy(deep=True)
    brief.headline = "Traffic was seen on port %d." % real_port

    assert problems_with(brief, analysed) == []


def test_an_invented_byte_figure_is_rejected(honest, analysed):
    brief = honest.model_copy(deep=True)
    brief.uncertainty = "It sent 8675309 bytes to the outside"

    assert any("8675309" in p for p in problems_with(brief, analysed))


def test_a_real_byte_figure_is_accepted(honest, analysed):
    _, _, _, evidence, _ = analysed
    real_bytes = max(c["bytes_sent"] for c in evidence["connections"])

    brief = honest.model_copy(deep=True)
    brief.uncertainty = "One connection carried %d bytes." % real_bytes

    assert problems_with(brief, analysed) == []


def test_a_timestamp_not_in_the_evidence_is_rejected(honest, analysed):
    brief = honest.model_copy(deep=True)
    brief.timeline[0].what_happened = "This began at 23:59:59"

    assert any("23:59:59" in p for p in problems_with(brief, analysed))


def test_counting_numbers_are_allowed(honest, analysed):
    """'Three devices were affected' must not be treated as a byte figure."""
    brief = honest.model_copy(deep=True)
    brief.uncertainty = "4 devices were affected, and 2 of them sent data outside."

    assert problems_with(brief, analysed) == []


# --------------------------------------------------------------------------
# Contradicting the analysis
# --------------------------------------------------------------------------

def test_a_confidence_figure_that_contradicts_the_analysis_is_rejected(honest, analysed):
    """
    The model must not talk itself into more certainty than we have. This is
    the invention that would matter most in practice: a brief that reads as
    definitive when the analysis was not.
    """
    brief = honest.model_copy(deep=True)
    brief.origin.confidence = 99

    assert any("99%" in p for p in problems_with(brief, analysed))


def test_blaming_a_different_device_than_the_analysis_named_is_rejected(honest, analysed):
    _, _, result, evidence, _ = analysed
    if evidence["verdict"] != "named":
        pytest.skip("this run abstained; covered by the abstain test instead")

    other = next(d for d in result.ranking if d != evidence["named_device"])
    brief = honest.model_copy(deep=True)
    brief.origin.device = other

    assert any("but the analysis named" in p for p in problems_with(brief, analysed))


def test_when_the_analysis_abstains_the_brief_may_not_name_an_outsider():
    """
    An abstention is a finding, not a gap to be filled in. The brief may pick
    from the shortlist, but must not reach past it.
    """
    run_id = None
    for candidate in runs.list_runs(prefix="run")[:12]:
        run = runs.load_run(candidate)
        detection = detect.detect_run(run)
        result = attribute.attribute_run(run, detection)
        if result.abstained and len(result.ranking) > 3:
            run_id = candidate
            break
    if run_id is None:
        pytest.skip("no abstaining run in the sample")

    evidence = report.build_evidence(run, detection, result)
    facts = report.allowed_facts_from(evidence, run)
    brief = report.template_brief(evidence, run, result)
    assert report.validate_brief(brief, facts, evidence) == []

    outsider = next(d for d in result.ranking if d not in result.shortlist)
    brief.origin.device = outsider
    problems = report.validate_brief(brief, facts, evidence)
    assert any("shortlist" in p for p in problems)


# --------------------------------------------------------------------------
# Structure is forced by the schema, not requested in the prompt
# --------------------------------------------------------------------------

def test_the_schema_has_every_field_the_specification_asks_for():
    schema = report.IncidentBrief.model_json_schema()
    assert set(schema["properties"]) == {
        "headline", "origin", "timeline", "affected_devices", "actions", "uncertainty"
    }

    origin = report.OriginFinding.model_json_schema()["properties"]
    assert set(origin) == {"device", "confidence", "label"}

    entry = report.TimelineEntry.model_json_schema()["properties"]
    assert set(entry) == {"time", "device", "what_happened", "evidence_ids"}

    action = report.RecommendedAction.model_json_schema()["properties"]
    assert set(action) == {"order", "action", "why", "urgency"}


def test_urgency_is_restricted_to_three_values():
    """A free-text urgency would be unsortable and unactionable."""
    action = report.RecommendedAction.model_json_schema()["properties"]["urgency"]
    assert set(action["enum"]) == {"now", "today", "this week"}


# --------------------------------------------------------------------------
# Falling back
# --------------------------------------------------------------------------

def test_offline_mode_never_calls_the_model_and_always_produces_a_brief(analysed):
    """
    This is what makes the dashboard's replay mode safe: with nothing
    connected, a brief still appears, plainly marked as the template.
    """
    run, _, result, evidence, facts = analysed
    outcome = report.generate_brief(evidence, facts, run, result, offline=True)

    assert outcome.source == "LLM_FALLBACK"
    assert outcome.is_fallback
    assert outcome.brief.headline


def test_an_unreachable_model_falls_back_rather_than_crashing(analysed):
    """
    A demo must not die because Ollama is not running. Pointing at a model
    that does not exist stands in for the server being down.
    """
    run, _, result, evidence, facts = analysed
    outcome = report.generate_brief(
        evidence, facts, run, result, model="no-such-model-exists:0b"
    )

    assert outcome.is_fallback
    assert outcome.brief.headline
    assert outcome.rejections, "the reason for falling back was not recorded"


def test_the_fallback_brief_always_passes_its_own_validator(analysed):
    """
    The template is the last line of defence. If it could fail validation
    there would be nothing left to show.
    """
    for run_id in runs.list_runs(prefix="run")[:5]:
        run = runs.load_run(run_id)
        detection = detect.detect_run(run)
        result = attribute.attribute_run(run, detection)
        evidence = report.build_evidence(run, detection, result)
        facts = report.allowed_facts_from(evidence, run)

        brief = report.template_brief(evidence, run, result)
        assert report.validate_brief(brief, facts, evidence) == [], (
            "the fallback template failed validation on %s" % run_id
        )


def test_batch_statistics_add_up():
    stats = report.BatchStats(total=10, first_time=6, second_time=2, fallback=2)
    text = stats.report()
    assert "10" in text and "60%" in text and "20%" in text
    assert stats.first_time + stats.second_time + stats.fallback == stats.total


# --------------------------------------------------------------------------
# The evidence pack itself
# --------------------------------------------------------------------------

def test_the_evidence_pack_gives_away_nothing_it_should_not(analysed):
    """
    The evidence pack is built from the analysis, not from the answer sheet.
    It must not contain the true chain or the attacker's identity as such -
    only what the pipeline worked out for itself.
    """
    import json
    _, _, _, evidence, _ = analysed
    text = json.dumps(evidence).lower()

    for banned in ("true_origin", "chain", "via_broker", "onset_seconds"):
        assert banned not in text


def test_every_id_offered_to_the_model_is_a_real_connection(analysed):
    run, _, _, evidence, facts = analysed
    real_ids = set(run.connections["conn_id"])

    for sample in evidence["connections"]:
        assert sample["id"] in real_ids
    assert facts.evidence_ids <= real_ids


# --------------------------------------------------------------------------
# Two false positives that a measurement found, and the fixes for them
# --------------------------------------------------------------------------

def test_a_capitalised_device_name_is_still_that_device(honest, analysed):
    """
    'Cam2 began sending data' starts a sentence, so the name is capitalised.
    It is still the device cam2, and rejecting it was the single largest
    source of template fallbacks in the first 20-brief measurement - the
    validator being wrong, not the model inventing anything.
    """
    brief = honest.model_copy(deep=True)
    brief.headline = "Cam2 and ESP32-04 both contacted an outside address."

    assert problems_with(brief, analysed) == []


def test_hyphenated_english_is_not_treated_as_a_device_name(honest, analysed):
    """
    The original rule flagged any token containing a hyphen, which rejected
    ordinary English. It caught no real inventions and cost real briefs.
    """
    brief = honest.model_copy(deep=True)
    brief.uncertainty = (
        "This is the highest-ranked candidate, but it is a well-known "
        "limitation that receive-only devices are under-represented."
    )
    assert problems_with(brief, analysed) == []


def test_a_near_miss_of_a_real_device_name_is_still_rejected(honest, analysed):
    """
    The important half of the fix. 'laptop-x' has no digit and no underscore,
    so nothing about its shape marks it as a machine name - but it is one
    character from the real 'laptop-c'. That is exactly what a plausible
    fabrication looks like, and relaxing the rule must not let it through.
    """
    brief = honest.model_copy(deep=True)
    brief.headline = "The attack started on laptop-x."

    assert any("laptop-x" in p for p in problems_with(brief, analysed))


def test_generic_security_words_are_not_treated_as_devices(honest, analysed):
    brief = honest.model_copy(deep=True)
    brief.uncertainty = "The device contacted a C2 server over HTTPS."

    assert problems_with(brief, analysed) == []


def test_case_insensitivity_does_not_extend_to_the_structured_fields(honest, analysed):
    """
    Prose is read case-insensitively; the structured fields are not, because
    the dashboard looks devices up by name and 'Cam2' would not match.
    """
    brief = honest.model_copy(deep=True)
    brief.origin.device = brief.origin.device.upper()

    assert problems_with(brief, analysed)
