"""
THE RULE THAT MUST NEVER BE BROKEN.

groundtruth/ holds the answer sheet: which device really started each attack.
Only src/evaluate.py - the file whose whole job is marking our homework - is
allowed to look at it.

If detection or attribution code could see the answers, every accuracy number
we report would be fiction. We would be measuring how well the code can read
the answer sheet, not how well it can do the job. In a viva that is fatal, and
it is very easy to do by accident (one stray debug line that never gets
removed).

So this test reads every file in src/ and fails if any of them - other than
evaluate.py - so much as mentions the word "groundtruth", or imports json in
order to load from that folder. It is deliberately blunt: a false alarm costs
ten seconds to explain, a missed leak costs the whole project's credibility.
"""

from pathlib import Path

import pytest

SRC = Path(__file__).resolve().parents[1] / "src"

# The only file permitted to know the answers.
ALLOWED = {"evaluate.py"}

# Spellings that all mean "the answer sheet".
FORBIDDEN_TERMS = ["groundtruth", "ground_truth", "ground truth"]


def _source_files():
    return sorted(p for p in SRC.rglob("*.py") if p.name != "__init__.py")


def test_src_folder_exists_and_has_files():
    """A guard on the guard: if src/ were empty this test would pass vacuously."""
    assert SRC.is_dir(), "src/ is missing"
    assert _source_files(), "src/ has no Python files - this test would prove nothing"


@pytest.mark.parametrize("path", _source_files(), ids=lambda p: p.name)
def test_only_evaluate_may_mention_the_answers(path):
    if path.name in ALLOWED:
        pytest.skip("%s is the marking script and is allowed to read the answers" % path.name)

    text = path.read_text(encoding="utf-8", errors="replace").lower()

    for term in FORBIDDEN_TERMS:
        assert term not in text, (
            "LEAK: src/%s mentions %r.\n"
            "Only src/evaluate.py may touch the answer sheet. If detection or\n"
            "attribution code can see the true origin, all reported accuracy\n"
            "numbers are meaningless." % (path.name, term)
        )


@pytest.mark.parametrize("path", _source_files(), ids=lambda p: p.name)
def test_no_file_outside_evaluate_reads_the_truth_at_runtime(path):
    """
    Belt and braces: catch an attempt to reach the folder by a sneaky path,
    e.g. building it from parts like "ground" + "truth", or walking up to the
    project root and globbing for *.json answers.
    """
    if path.name in ALLOWED:
        pytest.skip("%s is the marking script" % path.name)

    text = path.read_text(encoding="utf-8", errors="replace").lower()
    suspicious = ['"truth"', "'truth'", "truth_dir", "truth_path", "answers_dir"]
    for term in suspicious:
        assert term not in text, (
            "LEAK: src/%s contains %r, which looks like a route to the answer "
            "sheet by another name." % (path.name, term)
        )
