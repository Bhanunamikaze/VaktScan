import os
import unittest
from types import SimpleNamespace
from unittest import mock

import main


class NetworkTuningTests(unittest.TestCase):
    def test_web_concurrency_respects_requested_value_and_ceiling(self):
        with mock.patch.dict(os.environ, {"VAKT_WEB_CONCURRENCY": "12"}, clear=False):
            self.assertEqual(main._web_concurrency(8), 12)
            self.assertEqual(main._web_concurrency(100), 12)

    def test_web_concurrency_defaults_to_global_concurrency(self):
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("VAKT_WEB_CONCURRENCY", None)
            self.assertEqual(main._web_concurrency(100), 100)
            self.assertEqual(main._web_concurrency(37), 37)

    def test_cli_tuning_maps_to_module_environment(self):
        args = SimpleNamespace(
            web_concurrency=14,
            nuclei_concurrency=11,
            nuclei_rate_limit=31,
            nuclei_bulk_size=17,
            dirsearch_threads=6,
            dirsearch_parallel=3,
            js_threads=9,
        )
        keys = [
            "VAKT_WEB_CONCURRENCY", "VAKT_NUCLEI_CONCURRENCY",
            "VAKT_NUCLEI_RATE_LIMIT", "VAKT_NUCLEI_BULK_SIZE",
            "VAKT_DIRSEARCH_THREADS", "VAKT_DIRSEARCH_PARALLEL_TARGETS",
            "VAKT_JS_THREADS",
        ]
        with mock.patch.dict(os.environ, {}, clear=False):
            for key in keys:
                os.environ.pop(key, None)
            main._apply_network_tuning_args(args)
            self.assertEqual(
                [os.environ[key] for key in keys],
                ["14", "11", "31", "17", "6", "3", "9"],
            )

    def test_js_threads_inherit_global_concurrency_by_default(self):
        args = SimpleNamespace(
            concurrency=100,
            web_concurrency=None,
            nuclei_concurrency=None,
            nuclei_rate_limit=None,
            nuclei_bulk_size=None,
            dirsearch_threads=None,
            dirsearch_parallel=None,
            js_threads=None,
        )
        with mock.patch.dict(os.environ, {}, clear=False):
            for key in (
                "VAKT_JS_THREADS",
                "VAKT_NUCLEI_CONCURRENCY",
                "VAKT_NUCLEI_RATE_LIMIT",
                "VAKT_NUCLEI_BULK_SIZE",
            ):
                os.environ.pop(key, None)
            main._apply_network_tuning_args(args)
            self.assertEqual(os.environ["VAKT_JS_THREADS"], "100")
            self.assertEqual(os.environ["VAKT_NUCLEI_CONCURRENCY"], "100")
            self.assertEqual(os.environ["VAKT_NUCLEI_RATE_LIMIT"], "500")
            self.assertEqual(os.environ["VAKT_NUCLEI_BULK_SIZE"], "100")

    def test_explicit_js_threads_override_global_concurrency(self):
        args = SimpleNamespace(
            concurrency=100,
            web_concurrency=None,
            nuclei_concurrency=None,
            nuclei_rate_limit=None,
            nuclei_bulk_size=None,
            dirsearch_threads=None,
            dirsearch_parallel=None,
            js_threads=175,
        )
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("VAKT_JS_THREADS", None)
            main._apply_network_tuning_args(args)
            self.assertEqual(os.environ["VAKT_JS_THREADS"], "175")

    def test_positive_int_rejects_zero(self):
        with self.assertRaises(Exception):
            main._positive_int("0")
        self.assertEqual(main._positive_int("3"), 3)


if __name__ == "__main__":
    unittest.main()
