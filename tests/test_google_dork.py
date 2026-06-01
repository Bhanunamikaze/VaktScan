import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
import asyncio
import unittest
from unittest.mock import patch, AsyncMock, MagicMock
from modules.google_dork import run, BUILTIN_DORKS, MODULE_NAME
from modules.schema import CANONICAL_KEYS


class TestGoogleDork(unittest.TestCase):
    def test_builtin_dorks_count(self):
        self.assertEqual(len(BUILTIN_DORKS), 28)

    def test_module_name(self):
        self.assertEqual(MODULE_NAME, 'google_dork')

    def test_empty_key_returns_empty_in_api_mode(self):
        result = asyncio.run(run('example.com', api_key='', cx='', method='api'))
        self.assertEqual(result, [])

    def test_ip_target_returns_empty(self):
        result = asyncio.run(run('192.168.1.1', api_key='key', cx='cx'))
        self.assertEqual(result, [])

    def test_canonical_schema_in_findings(self):
        """Mock the API to return one result and verify canonical schema."""
        mock_response_data = {
            'items': [{
                'link': 'https://s3.amazonaws.com/example-bucket',
                'title': 'Example Bucket',
                'snippet': 'Public bucket content',
            }]
        }

        async def fake_run():
            mock_resp = MagicMock()
            mock_resp.status_code = 200
            mock_resp.json.return_value = mock_response_data

            with patch('httpx.AsyncClient') as mock_client_class:
                mock_client = AsyncMock()
                mock_client.__aenter__ = AsyncMock(return_value=mock_client)
                mock_client.__aexit__ = AsyncMock(return_value=None)
                mock_client.get = AsyncMock(return_value=mock_resp)
                mock_client_class.return_value = mock_client

                # Only run 1 dork to keep the test fast
                dorks = [BUILTIN_DORKS[0]]
                with patch('modules.google_dork.BUILTIN_DORKS', dorks):
                    return await run('example.com', api_key='testkey', cx='testcx', method='api', delay=0)

        findings = asyncio.run(fake_run())
        self.assertTrue(len(findings) > 0)
        for f in findings:
            missing = [k for k in CANONICAL_KEYS if k not in f]
            self.assertEqual(missing, [], f"Missing keys: {missing}")

    def test_dork_has_domain_placeholder(self):
        for name, template in BUILTIN_DORKS:
            self.assertIn('{domain}', template, f"Dork '{name}' missing {{domain}} placeholder")

    @patch('modules.google_dork.async_playwright')
    def test_playwright_scraping(self, mock_async_playwright):
        # Mock playwright objects
        mock_p = MagicMock()
        mock_browser = AsyncMock()
        mock_context = AsyncMock()
        mock_page = AsyncMock()

        mock_async_playwright.return_value.__aenter__.return_value = mock_p
        mock_p.chromium.launch = AsyncMock(return_value=mock_browser)
        mock_browser.new_context = AsyncMock(return_value=mock_context)
        mock_context.new_page = AsyncMock(return_value=mock_page)

        # Mock page content and evaluate response
        mock_page.content = AsyncMock(return_value="<html>hello world</html>")
        mock_page.evaluate = AsyncMock(return_value=[{
            'link': 'https://s3.amazonaws.com/example-bucket',
            'title': 'Example Bucket',
            'snippet': 'Public bucket content',
        }])

        # Only run 1 dork to keep the test fast
        dorks = [BUILTIN_DORKS[0]]
        with patch('modules.google_dork.BUILTIN_DORKS', dorks):
            result = asyncio.run(run('example.com', method='playwright', delay=0))

        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]['url'], 'https://s3.amazonaws.com/example-bucket')
        self.assertEqual(result[0]['page_title'], 'Example Bucket')
        self.assertEqual(result[0]['details'], 'Dork: site:s3.amazonaws.com "example.com" | Snippet: Public bucket content')

    @patch('httpx.AsyncClient')
    def test_html_scraping(self, mock_client_class):
        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=None)

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        # HTML payload simulating a search result
        mock_resp.text = """
        <html>
            <body>
                <div class="g">
                    <a href="/url?q=https://s3.amazonaws.com/example-bucket&sa=U&ved=...">
                        <h3>Example Bucket</h3>
                    </a>
                    <div>Public bucket content that has length greater than 30 characters so that it matches snippet selection criteria.</div>
                </div>
            </body>
        </html>
        """
        mock_client.get = AsyncMock(return_value=mock_resp)
        mock_client_class.return_value = mock_client

        # Only run 1 dork to keep the test fast
        dorks = [BUILTIN_DORKS[0]]
        with patch('modules.google_dork.BUILTIN_DORKS', dorks):
            result = asyncio.run(run('example.com', method='html', delay=0))

        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]['url'], 'https://s3.amazonaws.com/example-bucket')
        self.assertEqual(result[0]['page_title'], 'Example Bucket')
        self.assertIn('Public bucket content', result[0]['details'])

    @patch('modules.google_dork.async_playwright')
    def test_auto_fallback_to_playwright(self, mock_async_playwright):
        # If API credentials are not provided, it should use playwright if available
        mock_p = MagicMock()
        mock_browser = AsyncMock()
        mock_context = AsyncMock()
        mock_page = AsyncMock()

        mock_async_playwright.return_value.__aenter__.return_value = mock_p
        mock_p.chromium.launch = AsyncMock(return_value=mock_browser)
        mock_browser.new_context = AsyncMock(return_value=mock_context)
        mock_context.new_page = AsyncMock(return_value=mock_page)

        mock_page.content = AsyncMock(return_value="<html>hello world</html>")
        mock_page.evaluate = AsyncMock(return_value=[])

        dorks = [BUILTIN_DORKS[0]]
        with patch('modules.google_dork.BUILTIN_DORKS', dorks):
            result = asyncio.run(run('example.com', method='auto', delay=0))

        # Should call playwright because API credentials are not set and playwright is mockable
        mock_p.chromium.launch.assert_called_once()


if __name__ == '__main__':
    unittest.main()
