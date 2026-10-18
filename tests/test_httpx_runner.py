import asyncio
import csv
import json
import os
import shutil
import sys
import time
import unittest
import tempfile
from unittest.mock import AsyncMock, MagicMock, patch

from modules.httpx_runner import HTTPXRunner


class _FakeStream:
    """Minimal async-iterable stand-in for process.stdout / process.stderr."""

    def __init__(self, lines):
        self._lines = list(lines)

    def __aiter__(self):
        return self

    async def __anext__(self):
        if not self._lines:
            raise StopAsyncIteration
        return self._lines.pop(0)


class _FakeProc:
    def __init__(self, stdout_lines, stderr_lines=()):
        self.stdout = _FakeStream(stdout_lines)
        self.stderr = _FakeStream(stderr_lines)
        self.returncode = 0

    async def wait(self):
        return 0


class HTTPXRunnerTests(unittest.IsolatedAsyncioTestCase):
    async def test_run_httpx_uses_library_fallback_when_binary_missing(self):
        with patch.object(HTTPXRunner, "_resolve_binary", return_value=None):
            runner = HTTPXRunner(output_dir="/tmp/vaktscan_httpx_runner_tests")

        runner._run_httpx_library = AsyncMock(return_value=[{"url": "http://example.com"}])
        results = await runner.run_httpx(["example.com"], concurrency=7)

        runner._run_httpx_library.assert_awaited_once_with(["example.com"], 7)
        self.assertEqual(results, [{"url": "http://example.com"}])

    def test_expand_targets_for_library_adds_default_schemes(self):
        with patch.object(HTTPXRunner, "_resolve_binary", return_value=None):
            runner = HTTPXRunner(output_dir="/tmp/vaktscan_httpx_runner_tests")

        expanded = runner._expand_targets_for_library(
            ["example.com", "https://secure.example.com", "example.com"]
        )

        self.assertEqual(
            expanded,
            [
                "http://example.com",
                "https://example.com",
                "https://secure.example.com",
            ],
        )

    async def test_binary_path_streams_results_and_reports_progress(self):
        """Regression: the httpx binary path must stream results from stdout and
        push live progress to the dashboard, instead of sitting at a frozen
        "Starting" until process.communicate() returns (which looked like a hang
        on large target sets)."""
        tmp = tempfile.mkdtemp(prefix="vaktscan_httpx_binary_")
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)

        with patch.object(HTTPXRunner, "_resolve_binary", return_value="/fake/httpx"):
            runner = HTTPXRunner(output_dir=tmp)
        self.assertTrue(runner.binary, "test requires the binary path to be taken")

        alive = {"url": "http://a.example.com", "host": "a.example.com", "port": 80, "status_code": 200}
        stdout_lines = [(json.dumps(alive) + "\n").encode()]

        fake_dashboard = MagicMock()
        fake_dashboard.active = True

        async def fake_exec(*args, **kwargs):
            return _FakeProc(stdout_lines)

        with patch("modules.dashboard.LiveDashboard", return_value=fake_dashboard), \
             patch("asyncio.create_subprocess_exec", fake_exec):
            results = await runner.run_httpx(["a.example.com", "b.example.com"], concurrency=10)

        # Results are parsed from the streamed stdout, not a post-run file read.
        self.assertEqual(results, [alive])

        # Progress was pushed to the dashboard task during the run (the bug was
        # that this never happened on the binary path).
        httpx_status_updates = [
            c for c in fake_dashboard.update_task.call_args_list
            if c.args and c.args[0] == "httpx" and c.kwargs.get("status")
        ]
        self.assertTrue(
            httpx_status_updates,
            "binary httpx path must report live status to the dashboard",
        )

        # Temp input/output files are cleaned up.
        self.assertEqual(
            [f for f in os.listdir(tmp) if f.startswith("httpx_")], [],
            "httpx temp files should be removed",
        )

    @unittest.skipIf(sys.platform == "win32", "POSIX process-group teardown")
    async def test_cancel_during_streaming_tears_down_within_grace(self):
        """Regression: a single Ctrl+C (CancelledError) while httpx is streaming
        must tear the child down within the grace window and not deadlock.

        The streaming loop runs a concurrent stderr-drain task; the ``finally``
        must cancel BOTH the heartbeat AND the stderr-drain task before awaiting
        them. If only the heartbeat is cancelled, ``await stderr_task`` blocks on
        the still-open stderr pipe of the (undrained-stdout) child forever, so
        spawn_tool's group teardown never runs - the classic single-Ctrl+C
        httpx deadlock. This drives the REAL _run_httpx_binary path against a
        real child whose stderr stays open while stdout streams continuously.
        """
        tmp = tempfile.mkdtemp(prefix="vaktscan_httpx_cancel_")
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)

        with patch.object(HTTPXRunner, "_resolve_binary", return_value="/fake/httpx"):
            runner = HTTPXRunner(output_dir=tmp)
        self.assertTrue(runner.binary, "test requires the binary path to be taken")

        # Child: emit one stderr line (then keep stderr open, no EOF) while
        # streaming stdout forever. Mirrors httpx holding both pipes open.
        stub = (
            "import sys, time\n"
            "sys.stderr.write('go\\n'); sys.stderr.flush()\n"
            "while True:\n"
            "    sys.stdout.write('{}\\n'); sys.stdout.flush()\n"
            "    time.sleep(0.02)\n"
        )

        launched = {}
        real_exec = asyncio.create_subprocess_exec

        async def fake_exec(*_cmd, **kw):
            # Ignore the fake httpx argv; launch our stub with the SAME kwargs
            # (crucially start_new_session=True so group teardown applies).
            child = await real_exec(sys.executable, "-c", stub, **kw)
            launched["child"] = child
            return child

        with patch("asyncio.create_subprocess_exec", fake_exec):
            task = asyncio.create_task(
                runner._run_httpx_binary(["a.example.com"], concurrency=5)
            )
            # Let the child spawn and the streaming loop start.
            for _ in range(200):
                await asyncio.sleep(0.01)
                if "child" in launched:
                    break
            self.assertIn("child", launched, "stub child was never launched")
            child_pid = launched["child"].pid

            task.cancel()
            # Must unwind + tear down well within proc's 5s grace. A regression
            # (missing stderr_task.cancel) would hang here until this times out.
            try:
                await asyncio.wait_for(
                    asyncio.gather(task, return_exceptions=True), timeout=8.0
                )
            except asyncio.TimeoutError:
                self.fail("httpx teardown deadlocked on cancel (stderr_task not cancelled)")

        # The child's process group was torn down.
        deadline = time.monotonic() + 5.0
        alive = True
        while time.monotonic() < deadline:
            try:
                os.kill(child_pid, 0)
            except ProcessLookupError:
                alive = False
                break
            await asyncio.sleep(0.02)
        self.assertFalse(alive, "httpx child survived cancellation teardown")

    def test_get_help_output_combines_stdout_and_stderr(self):
        with patch.object(HTTPXRunner, "_resolve_binary", return_value=None):
            runner = HTTPXRunner(output_dir="/tmp/vaktscan_httpx_runner_tests")

        class Result:
            stdout = "stdout text"
            stderr = "stderr text"

        with patch("modules.httpx_runner.subprocess.run", return_value=Result()):
            help_text = runner._get_help_output("/fake/httpx")

        self.assertEqual(help_text, "stdout textstderr text")

    def test_save_csv_distinguishes_source_endpoint_from_redirect_destination(self):
        tmp = tempfile.mkdtemp(prefix="vaktscan_httpx_csv_")
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        with patch.object(HTTPXRunner, "_resolve_binary", return_value=None):
            runner = HTTPXRunner(output_dir=tmp)

        output = runner.save_csv([{
            "input": "http://ads.example.com:2082",
            "url": "http://ads.example.com:2082",
            "host": "ads.example.com",
            "host_ip": "192.0.2.10",
            "port": "2082",
            "final_url": "https://www.example.com/",
            "chain_status_codes": [301, 301, 200],
            "status_code": 200,
            "title": "Example site",
            "tech": ["Cloudflare", "WordPress"],
        }], "redirect")

        with open(output, newline="", encoding="utf-8") as handle:
            row = next(csv.DictReader(handle))

        self.assertEqual(row["IP Address"], "192.0.2.10")
        self.assertEqual(row["Domain"], "ads.example.com")
        self.assertEqual(row["Port"], "2082")
        self.assertEqual(row["URL"], "http://ads.example.com:2082")
        self.assertEqual(row["Source URL"], "http://ads.example.com:2082")
        self.assertEqual(row["Final URL"], "https://www.example.com/")
        self.assertEqual(row["Redirect Status Chain"], "301 -> 301 -> 200")
        self.assertEqual(row["Status Code"], "200")
        self.assertEqual(row["Title"], "Example site")
        self.assertEqual(row["Technologies"], "Cloudflare,WordPress")

    async def test_library_fallback_keeps_sources_that_share_a_final_url(self):
        tmp = tempfile.mkdtemp(prefix="vaktscan_httpx_library_")
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        with patch.object(HTTPXRunner, "_resolve_binary", return_value=None):
            runner = HTTPXRunner(output_dir=tmp)

        class Response:
            def __init__(self, source):
                self.url = "https://www.example.com/"
                self.status_code = 200
                self.history = [MagicMock(status_code=301)]
                self.text = "<title>Example site</title>"
                self.headers = {"server": "cloudflare"}

        class Client:
            async def __aenter__(self):
                return self

            async def __aexit__(self, *args):
                return None

            async def get(self, source):
                return Response(source)

        targets = [
            "http://ads.example.com:2082",
            "http://ads.example.com:8880",
        ]
        with patch("modules.httpx_runner.python_httpx.AsyncClient", return_value=Client()):
            results = await runner._run_httpx_library(targets, concurrency=2)

        self.assertEqual([item["url"] for item in results], targets)
        self.assertEqual(
            [item["final_url"] for item in results],
            ["https://www.example.com/", "https://www.example.com/"],
        )
        self.assertEqual(
            [item["port"] for item in results],
            [2082, 8880],
        )
        self.assertEqual(results[0]["chain_status_codes"], [301, 200])


if __name__ == "__main__":
    unittest.main()
