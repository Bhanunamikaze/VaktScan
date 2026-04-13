import unittest
from unittest.mock import AsyncMock, patch

from modules.httpx_runner import HTTPXRunner


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

    def test_get_help_output_combines_stdout_and_stderr(self):
        with patch.object(HTTPXRunner, "_resolve_binary", return_value=None):
            runner = HTTPXRunner(output_dir="/tmp/vaktscan_httpx_runner_tests")

        class Result:
            stdout = "stdout text"
            stderr = "stderr text"

        with patch("modules.httpx_runner.subprocess.run", return_value=Result()):
            help_text = runner._get_help_output("/fake/httpx")

        self.assertEqual(help_text, "stdout textstderr text")


if __name__ == "__main__":
    unittest.main()
