"""Unit tests for modules/screenshots.py.

These run WITHOUT gowitness or aquatone installed: the tool binary is faked via
``shutil.which`` and the subprocess is mocked via ``asyncio.create_subprocess_exec``.
"""

import os
import re
import shutil
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from modules import screenshots  # noqa: E402
from modules.schema import validate_finding  # noqa: E402


def _slug(url):
    return re.sub(r"[^a-zA-Z0-9]", "-", url)


class _FakeProc:
    """Minimal stand-in for an asyncio subprocess."""

    def __init__(self, returncode=0, on_communicate=None):
        self.returncode = returncode
        self._on_communicate = on_communicate

    async def communicate(self, input=None):
        if self._on_communicate is not None:
            self._on_communicate(input)
        return (b"", b"")


def _make_gowitness_exec():
    """Fake create_subprocess_exec that mimics gowitness writing screenshots.

    Reads the URL file passed with ``-f`` and drops one ``<slug>.png`` per URL
    into the directory given by ``--screenshot-path`` / ``-P``.
    """

    async def fake_exec(*args, **kwargs):
        argv = list(args)
        shots_dir = None
        for flag in ("--screenshot-path", "-P"):
            if flag in argv:
                shots_dir = argv[argv.index(flag) + 1]
                break
        urls_file = argv[argv.index("-f") + 1] if "-f" in argv else None
        if shots_dir and urls_file and os.path.exists(urls_file):
            os.makedirs(shots_dir, exist_ok=True)
            with open(urls_file, encoding="utf-8") as fh:
                for line in fh:
                    url = line.strip()
                    if url:
                        open(os.path.join(shots_dir, f"{_slug(url)}.png"), "wb").close()
        return _FakeProc(returncode=0)

    return fake_exec


def _make_aquatone_exec():
    """Fake create_subprocess_exec that mimics aquatone (URLs via stdin).

    aquatone nests screenshots under ``<out>/screenshots/``.
    """

    async def fake_exec(*args, **kwargs):
        argv = list(args)
        out_dir = argv[argv.index("-out") + 1] if "-out" in argv else None

        def _on_communicate(payload):
            if not (out_dir and payload):
                return
            shots = os.path.join(out_dir, "screenshots")
            os.makedirs(shots, exist_ok=True)
            for line in payload.decode().splitlines():
                url = line.strip()
                if url:
                    open(os.path.join(shots, f"{_slug(url)}.png"), "wb").close()

        return _FakeProc(returncode=0, on_communicate=_on_communicate)

    return fake_exec


class ScreenshotsGracefulSkipTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="vaktscan_screenshots_")
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        # Ensure env overrides never leak in from the host.
        env = mock.patch.dict(
            os.environ, {"VAKT_GOWITNESS_BIN": "", "VAKT_AQUATONE_BIN": ""}
        )
        env.start()
        self.addCleanup(env.stop)

    async def test_empty_input_returns_empty_list(self):
        self.assertEqual(await screenshots.capture_screenshots([], self.tmp), [])

    async def test_whitespace_only_input_returns_empty_list(self):
        self.assertEqual(await screenshots.capture_screenshots(["", "   "], self.tmp), [])

    async def test_missing_tool_skips_gracefully(self):
        with mock.patch("shutil.which", return_value=None):
            findings = await screenshots.capture_screenshots(
                ["https://example.com"], self.tmp
            )
        self.assertEqual(findings, [])
        # No screenshots directory work should have been attempted beyond creation.
        self.assertFalse(
            os.path.exists(os.path.join(self.tmp, "screenshots", "manifest.csv"))
        )


class ScreenshotsSuccessfulRunTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="vaktscan_screenshots_")
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        env = mock.patch.dict(
            os.environ, {"VAKT_GOWITNESS_BIN": "", "VAKT_AQUATONE_BIN": ""}
        )
        env.start()
        self.addCleanup(env.stop)
        self.urls = ["https://a.example.com", "http://b.example.com:8080"]

    async def test_gowitness_run_creates_manifest_and_findings(self):
        def which(name):
            return "/usr/bin/gowitness" if name == "gowitness" else None

        with mock.patch("shutil.which", side_effect=which), \
             mock.patch("asyncio.create_subprocess_exec", side_effect=_make_gowitness_exec()):
            findings = await screenshots.capture_screenshots(self.urls, self.tmp, concurrency=5)

        shots_dir = os.path.join(self.tmp, "screenshots")

        # Screenshot files were produced, one per URL.
        pngs = [f for f in os.listdir(shots_dir) if f.endswith(".png")]
        self.assertEqual(len(pngs), 2)

        # Manifest artifacts exist.
        manifest_csv = os.path.join(shots_dir, "manifest.csv")
        index_html = os.path.join(shots_dir, "index.html")
        self.assertTrue(os.path.exists(manifest_csv))
        self.assertTrue(os.path.exists(index_html))

        with open(manifest_csv, encoding="utf-8") as fh:
            manifest = fh.read()
        self.assertIn("https://a.example.com", manifest)
        self.assertIn("http://b.example.com:8080", manifest)
        # Each URL is mapped to a screenshot (non-empty second column).
        self.assertIn(".png", manifest)

        # Findings: one per captured URL + a summary, all canonical INFO.
        self.assertEqual(len(findings), 3)
        per_url = [f for f in findings if f["vulnerability"] == "Web Service Screenshot Captured"]
        summary = [f for f in findings if f["vulnerability"] == "Screenshot Visual Triage Summary"]
        self.assertEqual(len(per_url), 2)
        self.assertEqual(len(summary), 1)

        for f in findings:
            self.assertEqual(f["status"], "INFO")
            self.assertEqual(f["severity"], "INFO")
            self.assertEqual(f["module"], "screenshots")
            self.assertEqual(validate_finding(f), [], f"schema violations: {validate_finding(f)}")

        # Per-URL findings reference their screenshot path.
        for f in per_url:
            self.assertIn(".png", f["payload_url"])
            self.assertIn(".png", f["details"])

    async def test_aquatone_used_when_gowitness_absent(self):
        def which(name):
            return "/usr/bin/aquatone" if name == "aquatone" else None

        with mock.patch("shutil.which", side_effect=which), \
             mock.patch("asyncio.create_subprocess_exec", side_effect=_make_aquatone_exec()):
            findings = await screenshots.capture_screenshots(self.urls, self.tmp, concurrency=5)

        # aquatone nests screenshots; the module should still find them recursively.
        captured = [f for f in findings if f["vulnerability"] == "Web Service Screenshot Captured"]
        self.assertEqual(len(captured), 2)
        summary = [f for f in findings if f["vulnerability"] == "Screenshot Visual Triage Summary"]
        self.assertEqual(len(summary), 1)
        for f in findings:
            self.assertEqual(validate_finding(f), [])
        self.assertIn("aquatone", summary[0]["details"])

    async def test_tool_run_producing_no_screenshots_still_returns_summary(self):
        """A tool that runs cleanly but captures nothing yields just a summary."""
        async def empty_exec(*args, **kwargs):
            return _FakeProc(returncode=0)

        def which(name):
            return "/usr/bin/gowitness" if name == "gowitness" else None

        with mock.patch("shutil.which", side_effect=which), \
             mock.patch("asyncio.create_subprocess_exec", side_effect=empty_exec):
            findings = await screenshots.capture_screenshots(self.urls, self.tmp)

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["vulnerability"], "Screenshot Visual Triage Summary")
        self.assertEqual(validate_finding(findings[0]), [])


if __name__ == "__main__":
    unittest.main()
