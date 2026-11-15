"""
Shared test settings.

Step P3: the live engine prints the report to PDF with Edge at STOP. Dozens of
tests finish a session; starting a browser for each would be slow and would
depend on this laptop. So the PDF is switched off for every test, and the
tests that are about the PDF switch it back on themselves.
"""

import pytest

from src import live


@pytest.fixture(autouse=True)
def _no_pdf_at_stop(monkeypatch):
    monkeypatch.setattr(live, "WRITE_PDF", False)
