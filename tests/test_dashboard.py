"""
Tests for dashboard/app.py.

A Streamlit page cannot be tested by clicking it, so the app is written with
its logic in plain functions and only the layout inside main(). Everything
worth being wrong about - which device gets coloured red, which edges count as
the attack path, how the bars are scaled - lives in those functions and is
tested here.

The one thing these tests deliberately guarantee is that IMPORTING the module
does not draw anything. If main() ran at import time, this file could not
exist, and neither could any check of the app short of a browser.
"""

import plotly.graph_objects as go
import pytest

from dashboard import app
from src import attribute, detect, runs


@pytest.fixture(scope="module")
def analysed():
    run = runs.load_run("run_001")
    detection = detect.detect_run(run)
    result = attribute.attribute_run(run, detection)
    return run, detection, result


# --------------------------------------------------------------------------
# Layout
# --------------------------------------------------------------------------

def test_every_device_gets_a_position():
    names = ["a", "b", "c", "d"]
    positions = app.circle_layout(names)

    assert set(positions) == set(names)
    for x, y in positions.values():
        assert -1.01 <= x <= 1.01 and -1.01 <= y <= 1.01


def test_positions_are_stable_between_calls():
    """
    The diagram must not rearrange itself every time Streamlit reruns the
    script, which it does on every click.
    """
    names = ["camera", "plug", "laptop-c"]
    assert app.circle_layout(names) == app.circle_layout(names)


def test_devices_do_not_land_on_top_of_each_other():
    positions = list(app.circle_layout(["a", "b", "c", "d", "e"]).values())
    for i, first in enumerate(positions):
        for second in positions[i + 1:]:
            distance = ((first[0] - second[0]) ** 2 + (first[1] - second[1]) ** 2) ** 0.5
            assert distance > 0.3, "two devices drawn in the same place"


def test_an_empty_network_does_not_divide_by_zero():
    assert app.circle_layout([]) == {}


# --------------------------------------------------------------------------
# Colouring
# --------------------------------------------------------------------------

def test_the_named_origin_is_coloured_as_the_origin(analysed):
    _, detection, result = analysed
    if result.abstained:
        pytest.skip("this run abstained")

    assert app.device_role(result.named, result, detection) == "origin"
    assert app.ROLE_COLOUR["origin"] == app.COLOUR_ORIGIN


def test_a_device_that_was_never_flagged_is_drawn_as_clean(analysed):
    run, detection, result = analysed
    unflagged = [d for d in run.device_names if d not in detection.onsets]
    if not unflagged:
        pytest.skip("every device was flagged in this run")

    assert app.device_role(unflagged[0], result, detection) == "clean"


def test_when_the_analysis_abstains_nothing_is_coloured_as_the_origin():
    """
    An abstention must not look like an accusation. If the page painted one
    device red anyway, the whole point of abstaining would be lost on the
    person reading it.
    """
    for run_id in runs.list_runs(prefix="run")[:12]:
        run = runs.load_run(run_id)
        detection = detect.detect_run(run)
        result = attribute.attribute_run(run, detection)
        if not result.abstained:
            continue

        roles = {d: app.device_role(d, result, detection) for d in run.device_names}
        assert "origin" not in roles.values()
        assert sum(1 for r in roles.values() if r == "shortlist") == len(result.shortlist)
        return
    pytest.skip("no abstaining run in the sample")


def test_every_role_has_a_colour_and_a_label():
    for role in ("origin", "shortlist", "flagged", "clean"):
        assert role in app.ROLE_COLOUR
        assert role in app.ROLE_LABEL


# --------------------------------------------------------------------------
# The attack path
# --------------------------------------------------------------------------

def test_path_edges_are_consecutive_pairs():
    assert app.path_edges(["a", "b", "c"]) == {("a", "b"), ("b", "c")}


def test_a_single_device_path_has_no_edges():
    assert app.path_edges(["a"]) == set()
    assert app.path_edges([]) == set()


# --------------------------------------------------------------------------
# The figures
# --------------------------------------------------------------------------

def test_the_network_figure_draws_every_device(analysed):
    run, detection, result = analysed
    figure = app.network_figure(run, detection, result)

    assert isinstance(figure, go.Figure)
    drawn = set()
    for trace in figure.data:
        if trace.mode and "markers" in trace.mode and trace.text:
            drawn.update(trace.text)
    assert drawn == set(run.device_names)


def test_the_network_figure_keeps_the_circle_circular(analysed):
    """Without a locked aspect ratio the layout is drawn as an ellipse."""
    run, detection, result = analysed
    figure = app.network_figure(run, detection, result)
    assert figure.layout.yaxis.scaleanchor == "x"


def test_the_timeline_shows_every_flagged_device(analysed):
    run, detection, result = analysed
    figure = app.timeline_figure(run, detection, result)

    plotted = set()
    for trace in figure.data:
        if trace.y is not None:
            plotted.update(trace.y)
    assert plotted == set(detection.onsets)


def test_the_timeline_marks_where_the_baseline_ends(analysed):
    run, detection, result = analysed
    figure = app.timeline_figure(run, detection, result)

    lines = [s for s in figure.layout.shapes if s.type == "line"]
    assert lines, "the baseline boundary is not drawn"
    assert lines[0].x0 == pytest.approx(run.baseline_seconds / 3600.0)


def test_a_run_with_nothing_flagged_still_produces_a_figure(analysed):
    """A demo must not crash on a quiet capture."""
    run, _, result = analysed
    empty = detect.Detection()
    figure = app.timeline_figure(run, empty, result)
    assert isinstance(figure, go.Figure)


# --------------------------------------------------------------------------
# The ranking bars
# --------------------------------------------------------------------------

def test_the_ranking_bars_stay_within_range(analysed):
    _, detection, result = analysed
    rows = app.ranking_rows(result, detection)

    assert len(rows) == len(result.ranking)
    for row in rows:
        assert 0.0 <= row["bar"] <= 1.0, "a progress bar would overflow"


def test_the_bars_are_in_ranking_order_and_the_leader_is_full(analysed):
    _, detection, result = analysed
    rows = app.ranking_rows(result, detection)

    assert [r["device"] for r in rows] == result.ranking
    assert max(r["bar"] for r in rows) == pytest.approx(1.0)


def test_every_row_explains_itself(analysed):
    """
    The stage-2 re-ranking can put a lower story score above a higher one. The
    page must say why, or it looks like a sorting bug.
    """
    _, detection, result = analysed
    for row in app.ranking_rows(result, detection):
        assert row["explanation"]


def test_no_ranking_gives_no_rows():
    assert app.ranking_rows(attribute.Attribution(), detect.Detection()) == []


# --------------------------------------------------------------------------
# Replay mode and the answer sheet
# --------------------------------------------------------------------------

def test_the_answer_is_only_read_for_display_and_never_returned_to_the_pipeline():
    """
    The reveal switch reads the answer sheet. This checks it is a plain read
    with no side effects: running the analysis before and after produces the
    identical ranking.
    """
    run = runs.load_run("run_001")
    detection = detect.detect_run(run)

    before = attribute.attribute_run(run, detection).ranking
    answer = app.load_answer_for_display("run_001")
    after = attribute.attribute_run(run, detection).ranking

    assert answer is not None and "origin" in answer
    assert before == after


def test_a_missing_answer_file_is_handled_quietly():
    assert app.load_answer_for_display("run_does_not_exist") is None


def test_checking_for_the_model_server_never_raises():
    """
    The demo must survive the model server being absent, so this check has to
    return a boolean rather than throw, whatever the network is doing.
    """
    assert app.ollama_is_awake(timeout=0.001) in (True, False)


def test_importing_the_app_does_not_draw_the_page():
    """
    If main() ran at import time, none of the tests in this file could exist.
    """
    import inspect
    source = inspect.getsource(app)
    assert 'if __name__ == "__main__":' in source
    assert source.rstrip().endswith("main()")


def test_the_app_uses_streamlit_and_not_a_javascript_framework():
    """
    The brief was explicit: Streamlit only, no Node, no React.

    Checked against what the file IMPORTS and what is on disk, not against the
    words in it - the docstring says "no React" and a naive text search
    happily flagged that.
    """
    import ast
    import inspect

    tree = ast.parse(inspect.getsource(app))
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(a.name.split(".")[0] for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module.split(".")[0])

    assert "streamlit" in imported, "the dashboard must be a Streamlit app"
    assert "subprocess" not in imported, "nothing should be shelling out"

    from pathlib import Path
    dashboard_dir = Path(inspect.getfile(app)).parent
    stray = [p.name for p in dashboard_dir.rglob("*")
             if p.suffix in {".js", ".jsx", ".ts", ".tsx"}
             or p.name in {"package.json", "package-lock.json"}]
    assert not stray, "JavaScript build files found in dashboard/: %s" % stray
