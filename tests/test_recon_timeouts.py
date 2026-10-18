import asyncio
from unittest import mock

from modules.recon import ReconScanner


def test_recon_tool_uses_configured_timeout(tmp_path):
    scanner = ReconScanner("example.com", output_dir=str(tmp_path), detailed_dashboard=False)
    result = mock.Mock(returncode=0, stdout=b"a.example.com\n", stderr=b"")

    async def run():
        with mock.patch("modules.recon.proc_runner.run_tool", new=mock.AsyncMock(return_value=result)) as run_tool:
            lines = await scanner._run_command("sublist3r -d example.com", "Sublist3r")
            run_tool.assert_awaited_once_with(
                "sublist3r -d example.com",
                timeout=ReconScanner.TOOL_TIMEOUTS["sublist3r"],
            )
            return lines

    assert asyncio.run(run()) == ["a.example.com"]


def test_recon_timeout_is_nonfatal(tmp_path):
    scanner = ReconScanner("example.com", output_dir=str(tmp_path), detailed_dashboard=False)

    async def run():
        with mock.patch(
            "modules.recon.proc_runner.run_tool",
            new=mock.AsyncMock(side_effect=asyncio.TimeoutError),
        ):
            return await scanner._run_command("sublist3r -d example.com", "Sublist3r")

    assert asyncio.run(run()) == []
