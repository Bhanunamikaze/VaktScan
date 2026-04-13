import asyncio
import errno
import unittest
from unittest.mock import patch

import port_scanner


class DummyWriter:
    def close(self):
        return None

    async def wait_closed(self):
        return None


class PortScannerTests(unittest.IsolatedAsyncioTestCase):
    async def test_timeout_is_retried_and_port_is_recorded(self):
        attempts = 0
        target = {
            "scan_address": "example.com",
            "display_target": "example.com",
            "resolved_ip": "203.0.113.10",
        }

        async def fake_open_connection(host, port):
            nonlocal attempts
            attempts += 1
            if attempts == 1:
                raise asyncio.TimeoutError
            return object(), DummyWriter()

        with patch("port_scanner.DEFAULT_RETRY_BACKOFF", 0.0), patch(
            "port_scanner.asyncio.open_connection",
            side_effect=fake_open_connection,
        ):
            results = await port_scanner.scan_ports(
                [target],
                [443],
                concurrency=10,
                connect_timeout=0.1,
                retries=1,
            )

        self.assertEqual(attempts, 2)
        self.assertEqual(results[0][1]["open_ports"], [443])

    async def test_connection_refused_is_not_retried(self):
        attempts = 0
        target = {
            "scan_address": "example.com",
            "display_target": "example.com",
            "resolved_ip": "203.0.113.10",
        }

        async def fake_open_connection(host, port):
            nonlocal attempts
            attempts += 1
            raise ConnectionRefusedError

        with patch("port_scanner.DEFAULT_RETRY_BACKOFF", 0.0), patch(
            "port_scanner.asyncio.open_connection",
            side_effect=fake_open_connection,
        ):
            results = await port_scanner.scan_ports(
                [target],
                [9200],
                concurrency=10,
                connect_timeout=0.1,
                retries=3,
            )

        self.assertEqual(attempts, 1)
        self.assertEqual(results[0][1]["open_ports"], [])

    async def test_transient_socket_error_is_retried(self):
        attempts = 0
        target = {
            "scan_address": "example.com",
            "display_target": "example.com",
            "resolved_ip": "203.0.113.10",
        }

        async def fake_open_connection(host, port):
            nonlocal attempts
            attempts += 1
            if attempts == 1:
                raise OSError(errno.EMFILE, "too many open files")
            return object(), DummyWriter()

        with patch("port_scanner.DEFAULT_RETRY_BACKOFF", 0.0), patch(
            "port_scanner.asyncio.open_connection",
            side_effect=fake_open_connection,
        ):
            results = await port_scanner.scan_ports(
                [target],
                [5601],
                concurrency=10,
                connect_timeout=0.1,
                retries=1,
            )

        self.assertEqual(attempts, 2)
        self.assertEqual(results[0][1]["open_ports"], [5601])

    def test_calculate_effective_concurrency_uses_fd_budget(self):
        if port_scanner.resource is None:
            self.skipTest("resource module unavailable")

        with patch("port_scanner.resource.getrlimit", return_value=(256, 256)):
            self.assertEqual(port_scanner.calculate_effective_concurrency(200), 32)
            self.assertEqual(port_scanner.calculate_effective_concurrency(8), 8)


if __name__ == "__main__":
    unittest.main()
