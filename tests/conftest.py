"""Global test configuration.

All tests run with real socket connections disabled (pytest-socket).
This catches any urllib / http.client / requests call that would reach
the internet without an explicit monkeypatch.

Note: subprocess-based network calls (e.g. `gh api`) are not intercepted
by pytest-socket.  Those are guarded individually by pre-populating the
relevant in-memory caches (_advisory_cache, _osv_cache) via monkeypatch.
"""
import pytest


@pytest.fixture(autouse=True)
def _no_network(socket_disabled):
    """Fail any test that attempts a real socket connection."""
