import asyncio
from unittest import mock

from modules.gau_runner import GAURunner
from modules.waybackurls_runner import WaybackURLsRunner


def _exercise_timeout(runner, patch_target):
    runner.binary = "/usr/bin/fake-tool"

    async def run():
        with mock.patch(
            patch_target,
            new=mock.AsyncMock(side_effect=asyncio.TimeoutError),
        ) as run_tool:
            result = await runner._run_single(
                "example.com", asyncio.Semaphore(1), "20261018_000000"
            )
            run_tool.assert_awaited_once_with(
                ["/usr/bin/fake-tool", *runner_args(runner), "example.com"],
                timeout=17,
            )
            return result

    assert asyncio.run(run()) == ("example.com", [])


def runner_args(runner):
    return ["--subs"] if isinstance(runner, GAURunner) else []


def test_gau_timeout_is_bounded_and_nonfatal(tmp_path):
    _exercise_timeout(
        GAURunner(output_dir=str(tmp_path), timeout=17),
        "modules.gau_runner.proc.run_tool",
    )


def test_wayback_timeout_is_bounded_and_nonfatal(tmp_path):
    _exercise_timeout(
        WaybackURLsRunner(output_dir=str(tmp_path), timeout=17),
        "modules.waybackurls_runner.proc_runner.run_tool",
    )


def test_archive_timeout_environment_override(tmp_path, monkeypatch):
    monkeypatch.setenv("VAKT_ARCHIVE_TOOL_TIMEOUT", "41")
    assert GAURunner(output_dir=str(tmp_path / "gau")).timeout == 41
    assert WaybackURLsRunner(output_dir=str(tmp_path / "wayback")).timeout == 41
