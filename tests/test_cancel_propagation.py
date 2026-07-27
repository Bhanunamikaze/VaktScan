"""Phase 3 regression test: bare ``except:`` that wrapped awaited network calls
were converted to ``except Exception:`` so that ``asyncio.CancelledError`` (a
``BaseException``, not an ``Exception``) is no longer swallowed.

This test injects a ``CancelledError`` into a converted scanner path
(``prometheus.detect_protocol``, whose ``except`` clause wraps
``await client.get(...)``) and asserts the cancellation propagates instead of
being caught and turned into a normal return value. A companion assertion
confirms an ordinary ``Exception`` is still swallowed (fail-open preserved).
"""
import asyncio

import pytest

from modules import prometheus


class _FakeClient:
    """Async-context-manager stand-in for ``httpx.AsyncClient`` whose ``get``
    raises whatever exception it is configured with when awaited."""

    def __init__(self, exc, *args, **kwargs):
        self._exc = exc

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc_info):
        return False

    async def get(self, *args, **kwargs):
        raise self._exc


def _patch_client(monkeypatch, exc):
    def _factory(*args, **kwargs):
        return _FakeClient(exc, *args, **kwargs)

    monkeypatch.setattr(prometheus.httpx, "AsyncClient", _factory)


def test_cancelled_error_propagates(monkeypatch):
    """CancelledError injected into the awaited call must NOT be swallowed by
    the converted ``except Exception:`` clause."""
    _patch_client(monkeypatch, asyncio.CancelledError())

    with pytest.raises(asyncio.CancelledError):
        asyncio.run(prometheus.detect_protocol("192.0.2.1", 9090))


def test_ordinary_exception_still_swallowed(monkeypatch):
    """A normal Exception is still caught (fail-open behavior preserved),
    proving the conversion narrowed the catch rather than removing it."""
    _patch_client(monkeypatch, RuntimeError("boom"))

    # detect_protocol falls through both protocols and returns the default.
    result = asyncio.run(prometheus.detect_protocol("192.0.2.1", 9090))
    assert result == "http"
