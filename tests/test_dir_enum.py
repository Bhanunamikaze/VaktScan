import os
import tempfile
import unittest
from unittest.mock import AsyncMock, MagicMock, patch

from modules.dir_enum import DirEnumerator


class DirEnumeratorTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.output_dir = self.temp_dir.name

    def tearDown(self):
        self.temp_dir.cleanup()

    @patch("modules.dir_enum.shutil.which")
    def test_init_checks_binaries(self, mock_which):
        mock_which.side_effect = lambda x: f"/usr/bin/{x}"
        enumerator = DirEnumerator("example.com", output_dir=self.output_dir)
        self.assertEqual(enumerator.binary, "/usr/bin/ffuf")
        self.assertEqual(enumerator.dirsearch_binary, "/usr/bin/dirsearch")
        self.assertTrue(enumerator.is_available())
        self.assertTrue(enumerator.dirsearch_available())

    @patch("modules.dir_enum.shutil.which")
    async def test_run_dirsearch_missing_binary(self, mock_which):
        mock_which.return_value = None
        enumerator = DirEnumerator("example.com", output_dir=self.output_dir)
        result = await enumerator.run_dirsearch(["http://example.com"])
        self.assertIsNone(result)

    @patch("modules.dir_enum.shutil.which")
    @patch("modules.dir_enum.asyncio.create_subprocess_shell")
    async def test_run_dirsearch_success(self, mock_create_process, mock_which):
        mock_which.side_effect = lambda x: f"/usr/bin/{x}"
        enumerator = DirEnumerator("example.com", output_dir=self.output_dir)

        # Mock successful process execution
        mock_process = AsyncMock()
        mock_process.returncode = 0
        mock_process.communicate.return_value = (b"", b"")
        mock_create_process.return_value = mock_process

        # We need to simulate that the output file was created by dirsearch
        # To do this, we patch _run_dirsearch_target to write to the file
        original_run = enumerator._run_dirsearch_target

        async def fake_run_target(url, threads, env, reports_dir):
            # Create a dummy report file to simulate dirsearch output
            output_file = os.path.join(reports_dir, "dirsearch_report_example_com_80_20260602_120000.txt")
            with open(output_file, "w") as f:
                f.write("http://example.com/admin\n")
            return output_file

        with patch.object(enumerator, "_run_dirsearch_target", side_effect=fake_run_target):
            result = await enumerator.run_dirsearch(["http://example.com"])
            self.assertEqual(result, os.path.join(self.output_dir, "dirsearch_reports"))
            self.assertTrue(os.path.exists(result))

    @patch("modules.dir_enum.shutil.which")
    @patch("modules.dir_enum.asyncio.create_subprocess_shell")
    async def test_run_dirsearch_non_zero_exit_with_content(self, mock_create_process, mock_which):
        mock_which.side_effect = lambda x: f"/usr/bin/{x}"
        enumerator = DirEnumerator("example.com", output_dir=self.output_dir)

        mock_process = AsyncMock()
        mock_process.returncode = 1  # Exit code 1 (warnings)
        mock_process.communicate.return_value = (b"", b"Some warning on stderr")
        mock_create_process.return_value = mock_process

        # We patch os.path.exists and os.path.getsize to simulate file created with size > 0
        with patch("modules.dir_enum.os.path.exists", return_value=True), \
             patch("modules.dir_enum.os.path.getsize", return_value=128):
            
            reports_dir = os.path.join(self.output_dir, "dirsearch_reports")
            os.makedirs(reports_dir, exist_ok=True)
            
            res = await enumerator._run_dirsearch_target("http://example.com", 10, {}, reports_dir)
            self.assertIsNotNone(res)
            self.assertTrue(res.endswith(".txt"))

    @patch("modules.dir_enum.shutil.which")
    @patch("modules.dir_enum.asyncio.create_subprocess_shell")
    async def test_run_dirsearch_failure_no_content(self, mock_create_process, mock_which):
        mock_which.side_effect = lambda x: f"/usr/bin/{x}"
        enumerator = DirEnumerator("example.com", output_dir=self.output_dir)

        mock_process = AsyncMock()
        # Mock process exit code 2 (critical error) to ensure it fails
        mock_process.returncode = 2
        mock_process.communicate.return_value = (b"", b"Connection failed")
        mock_create_process.return_value = mock_process

        # File does not exist / is empty
        with patch("modules.dir_enum.os.path.exists", return_value=False):
            reports_dir = os.path.join(self.output_dir, "dirsearch_reports")
            res = await enumerator._run_dirsearch_target("http://example.com", 10, {}, reports_dir)
            self.assertIsNone(res)

    @patch("modules.dir_enum.shutil.which")
    @patch("modules.dir_enum.asyncio.create_subprocess_shell")
    async def test_run_dirsearch_success_zero_size_file(self, mock_create_process, mock_which):
        mock_which.side_effect = lambda x: f"/usr/bin/{x}"
        enumerator = DirEnumerator("example.com", output_dir=self.output_dir)

        mock_process = AsyncMock()
        mock_process.returncode = 0
        mock_process.communicate.return_value = (b"", b"")
        mock_create_process.return_value = mock_process

        # File exists but is 0 bytes
        with patch("modules.dir_enum.os.path.exists", return_value=True), \
             patch("modules.dir_enum.os.path.getsize", return_value=0):
            reports_dir = os.path.join(self.output_dir, "dirsearch_reports")
            res = await enumerator._run_dirsearch_target("http://example.com", 10, {}, reports_dir)
            self.assertIsNotNone(res)
            self.assertTrue(res.endswith(".txt"))

    @patch("modules.dir_enum.shutil.which")
    @patch("modules.dir_enum.asyncio.create_subprocess_shell")
    async def test_run_dirsearch_env_retry(self, mock_create_process, mock_which):
        mock_which.side_effect = lambda x: f"/usr/bin/{x}"
        enumerator = DirEnumerator("example.com", output_dir=self.output_dir)

        # First mock process (fails)
        mock_process_fail = AsyncMock()
        mock_process_fail.returncode = 2
        mock_process_fail.communicate.return_value = (b"", b"Environment error")

        # Second mock process (succeeds)
        mock_process_success = AsyncMock()
        mock_process_success.returncode = 0
        mock_process_success.communicate.return_value = (b"", b"")

        mock_create_process.side_effect = [mock_process_fail, mock_process_success]

        # File exists on second run
        with patch("modules.dir_enum.os.path.exists", side_effect=[False, True]), \
             patch("modules.dir_enum.os.path.getsize", return_value=10):
            reports_dir = os.path.join(self.output_dir, "dirsearch_reports")
            res = await enumerator._run_dirsearch_target(
                "http://example.com", 10, {"VIRTUAL_ENV": "/foo/env"}, reports_dir
            )
            self.assertIsNotNone(res)
            self.assertTrue(res.endswith(".txt"))
            self.assertEqual(mock_create_process.call_count, 2)
            
            # Verify environment on second call has popped python variables
            first_call_env = mock_create_process.call_args_list[0][1]["env"]
            second_call_env = mock_create_process.call_args_list[1][1]["env"]
            self.assertIn("VIRTUAL_ENV", first_call_env)
            self.assertNotIn("VIRTUAL_ENV", second_call_env)


if __name__ == "__main__":
    unittest.main()
