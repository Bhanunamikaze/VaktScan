"""Unit tests for `main._reraise_if_bug` — the resilience-vs-bug policy.

Orchestration code tolerates per-target/tool/network failures (so one bad
target does not abort a whole scan), but must NOT swallow programming bugs.
`_reraise_if_bug` re-raises the "this is a code defect" exception classes and
returns everything else untouched. `UnboundLocalError` (the class behind the
original recon crash) is a subclass of `NameError`, so it must be re-raised.
"""

import asyncio
import os
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import main  # noqa: E402


class ReraiseIfBugTest(unittest.TestCase):
    def test_reraises_name_error(self):
        with self.assertRaises(NameError):
            main._reraise_if_bug(NameError("name 'x' is not defined"))

    def test_reraises_unbound_local_error(self):
        # This is the exact class of the original "free variable ... not
        # associated with a value" recon crash.
        with self.assertRaises(UnboundLocalError):
            main._reraise_if_bug(UnboundLocalError("cannot access local variable"))

    def test_reraises_import_error(self):
        with self.assertRaises(ImportError):
            main._reraise_if_bug(ImportError("no module named foo"))

    def test_returns_non_bug_exceptions_untouched(self):
        # These represent tolerable runtime/environmental failures — they must
        # be returned (so the caller can log-and-continue), never raised.
        for exc in (
            ValueError("bad data"),
            OSError("connection refused"),
            RuntimeError("tool failed"),
            asyncio.TimeoutError(),
            KeyError("missing"),
        ):
            with self.subTest(exc=type(exc).__name__):
                returned = main._reraise_if_bug(exc)
                self.assertIs(returned, exc)


if __name__ == "__main__":
    unittest.main()
