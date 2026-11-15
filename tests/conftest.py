"""
Shared test settings, in force for the WHOLE session - before any fixture,
including the module-scoped ones that replay a capture once for many tests
(a function-scoped guard would be set up too late for those).

Step P3: the live engine prints the report to PDF with Edge at STOP. Dozens of
tests finish a session; starting a browser for each would be slow and would
depend on this laptop. So the PDF is switched off, and the tests that are
about the PDF switch it back on themselves (with monkeypatch, which puts it
back afterwards).

Step P4: this laptop has a key in API_KEY.env. With it, the Past sessions page
would default to the cloud writer and --llm cloud would really call the
model. IOT_NO_CLOUD=1 makes both behave as if there were no key, so no test
can reach the real cloud; the analyst's tests use fake transports.
"""

import pytest

from src import live


@pytest.fixture(autouse=True, scope="session")
def _session_guards():
    guards = pytest.MonkeyPatch()
    guards.setattr(live, "WRITE_PDF", False)
    guards.setenv("IOT_NO_CLOUD", "1")
    yield
    guards.undo()
