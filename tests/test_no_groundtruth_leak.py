"""
THE RULE THAT MUST NEVER BE BROKEN.

groundtruth/ holds the answer sheet: which device really started each attack.
If detection or attribution code could see the answers, every accuracy number
we report would be fiction - we would be measuring how well the code can read
the answer sheet, not how well it can do the job.

The rule is about READING. Written out in full:

    Nothing in src/ may READ the answer sheet, except src/evaluate.py, whose
    entire job is marking our homework.

One file has to WRITE it. src/generate.py invents the incident, so it is the
only thing in the universe that knows the answer; somebody has to write it
down. That is not a leak - a leak is the answer flowing back INTO the
detection pipeline. So generate.py is allowed to name the folder, and is then
held to a stricter standard than everyone else: this file parses its source
code and fails if it contains ANY file-reading operation at all. It may write.
It may not read. Not from the answer folder, not from anywhere.

Everyone else - features.py, detect.py, attribute.py, report.py - may not so
much as mention the word.

The checks are deliberately blunt. A false alarm costs ten seconds to explain;
a missed leak costs the whole project's credibility.
"""

import ast
from pathlib import Path

import pytest

SRC = Path(__file__).resolve().parents[1] / "src"

# May read the answers. Its only job is scoring us against them.
MAY_READ = {"evaluate.py"}

# May write the answers, and is then forbidden from reading anything.
MAY_WRITE = {"generate.py"}

# Spellings that all mean "the answer sheet".
FORBIDDEN_TERMS = ["groundtruth", "ground_truth", "ground truth"]

# Function names that read data in from somewhere.
READING_FUNCTIONS = {
    "load", "loads", "read", "read_text", "read_bytes", "readline", "readlines",
    "read_json", "read_parquet", "read_csv", "glob", "rglob", "iterdir", "listdir",
}


def _source_files():
    return sorted(p for p in SRC.rglob("*.py") if p.name != "__init__.py")


def test_src_folder_exists_and_has_files():
    """A guard on the guard: if src/ were empty, these tests would pass vacuously."""
    assert SRC.is_dir(), "src/ is missing"
    assert _source_files(), "src/ has no Python files - these tests would prove nothing"


# --------------------------------------------------------------------------
# Everybody except evaluate.py and generate.py: do not mention the answers
# --------------------------------------------------------------------------

@pytest.mark.parametrize("path", _source_files(), ids=lambda p: p.name)
def test_only_the_marker_and_the_generator_may_mention_the_answers(path):
    if path.name in MAY_READ or path.name in MAY_WRITE:
        pytest.skip("%s is allowed to name the answer folder" % path.name)

    text = path.read_text(encoding="utf-8", errors="replace").lower()

    for term in FORBIDDEN_TERMS:
        assert term not in text, (
            "LEAK: src/%s mentions %r.\n"
            "Only src/evaluate.py may read the answer sheet, and only\n"
            "src/generate.py may write it. If detection or attribution code\n"
            "can see the true origin, every accuracy number we report is\n"
            "meaningless." % (path.name, term)
        )


@pytest.mark.parametrize("path", _source_files(), ids=lambda p: p.name)
def test_no_sneaky_route_to_the_answers(path):
    """
    Belt and braces: catch an attempt to reach the folder by another name,
    e.g. building the path from pieces, or globbing the project root for
    whatever JSON files happen to be lying around.
    """
    if path.name in MAY_READ or path.name in MAY_WRITE:
        pytest.skip("%s is allowed to name the answer folder" % path.name)

    text = path.read_text(encoding="utf-8", errors="replace").lower()
    suspicious = ['"truth"', "'truth'", "truth_dir", "truth_path", "answers_dir",
                  "answer_dir", "answer_path"]
    for term in suspicious:
        assert term not in text, (
            "LEAK: src/%s contains %r, which looks like a route to the answer "
            "sheet by another name." % (path.name, term)
        )


# --------------------------------------------------------------------------
# The generator: may write, may never read
# --------------------------------------------------------------------------

def _reading_calls(tree):
    """Every call in the file that looks like it reads data in from somewhere."""
    found = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue

        # open(...) is only acceptable with an explicit write/append mode.
        name = getattr(node.func, "id", None)
        if name == "open":
            modes = [a for a in node.args[1:2]] + [
                k.value for k in node.keywords if k.arg == "mode"
            ]
            literal = next(
                (m.value for m in modes if isinstance(m, ast.Constant)), None
            )
            if literal is None or not str(literal).startswith(("w", "a", "x")):
                found.append("open(mode=%r) on line %d" % (literal, node.lineno))
            continue

        attribute = getattr(node.func, "attr", None)
        if attribute in READING_FUNCTIONS:
            found.append("%s() on line %d" % (attribute, node.lineno))
        elif name in READING_FUNCTIONS:
            found.append("%s() on line %d" % (name, node.lineno))

    return found


@pytest.mark.parametrize("name", sorted(MAY_WRITE))
def test_the_generator_writes_the_answers_but_never_reads_anything(name):
    path = SRC / name
    if not path.exists():
        pytest.skip("%s does not exist yet" % name)

    tree = ast.parse(path.read_text(encoding="utf-8"))
    offenders = _reading_calls(tree)

    assert not offenders, (
        "LEAK RISK: src/%s performs file-reading operations: %s.\n"
        "The generator is allowed to WRITE the answer sheet because it is the\n"
        "only thing that knows the answer. It is not allowed to read anything\n"
        "back, so the answer can never flow into the detection pipeline."
        % (name, ", ".join(offenders))
    )


@pytest.mark.parametrize("name", sorted(MAY_WRITE))
def test_the_generator_does_not_import_the_marking_script(name):
    """
    evaluate.py can read the answers. If the generator imported it, the answers
    would be one function call away from everything the generator touches.
    """
    path = SRC / name
    if not path.exists():
        pytest.skip("%s does not exist yet" % name)

    tree = ast.parse(path.read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names = [a.name for a in node.names]
        elif isinstance(node, ast.ImportFrom):
            names = [node.module or ""] + [a.name for a in node.names]
        else:
            continue
        for imported in names:
            assert "evaluate" not in imported, (
                "src/%s imports %r - the marking script can read the answers, "
                "so nothing else should import it." % (name, imported)
            )
