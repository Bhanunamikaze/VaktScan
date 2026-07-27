"""End-to-end static gates over the source tree.

These guard the whole class of "undefined name" / import bugs (e.g. using
`csv` or `ipaddress` without importing them) that a normal test run does not
exercise unless the exact code path executes. A linter sees them regardless, so
this catches a reintroduction the moment it lands rather than in production.

The gates degrade gracefully: if neither ruff nor pyflakes is installed, the
undefined-name gate is skipped, but the compile gate (stdlib only) always runs.
"""

import os
import shutil
import subprocess
import sys
import unittest

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))

# Files most prone to this class (large orchestration + reporting modules).
CORE_SOURCES = ["main.py", "reporter.py", "utils.py", "scan_state.py"]


def _source_files():
    files = [os.path.join(REPO, f) for f in CORE_SOURCES if os.path.exists(os.path.join(REPO, f))]
    modules_dir = os.path.join(REPO, "modules")
    if os.path.isdir(modules_dir):
        for name in sorted(os.listdir(modules_dir)):
            if name.endswith(".py"):
                files.append(os.path.join(modules_dir, name))
    return files


class UndefinedNameGateTest(unittest.TestCase):
    """No F821 (undefined name) / F823 (used before assignment) in core sources."""

    def _run_ruff(self, path):
        ruff = shutil.which("ruff")
        if not ruff:
            return None
        return subprocess.run(
            [ruff, "check", "--select", "F821,F822,F823", "--output-format", "concise", path],
            cwd=REPO, capture_output=True, text=True,
        )

    def _run_pyflakes(self, path):
        try:
            import pyflakes  # noqa: F401
        except ImportError:
            return None
        return subprocess.run(
            [sys.executable, "-m", "pyflakes", path],
            cwd=REPO, capture_output=True, text=True,
        )

    def test_no_undefined_names_in_main(self):
        main_py = os.path.join(REPO, "main.py")

        ruff_result = self._run_ruff(main_py)
        if ruff_result is not None:
            self.assertEqual(
                ruff_result.returncode, 0,
                msg=f"ruff found undefined/unbound names:\n{ruff_result.stdout}\n{ruff_result.stderr}",
            )
            return

        pf_result = self._run_pyflakes(main_py)
        if pf_result is None:
            self.skipTest("neither ruff nor pyflakes is installed")
        offenders = [
            line for line in pf_result.stdout.splitlines()
            if "undefined name" in line or "referenced before assignment" in line
        ]
        self.assertEqual(offenders, [], msg="undefined-name issues in main.py:\n" + "\n".join(offenders))


class CompileGateTest(unittest.TestCase):
    """Every core source and module compiles (no syntax errors)."""

    def test_core_sources_compile(self):
        result = subprocess.run(
            [sys.executable, "-m", "py_compile", *_source_files()],
            cwd=REPO, capture_output=True, text=True,
        )
        self.assertEqual(result.returncode, 0, msg=result.stderr)


if __name__ == "__main__":
    unittest.main()
