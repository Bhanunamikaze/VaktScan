import os

import main


def test_primary_report_dir_uses_requested_target_not_intermediate_file():
    path = main._primary_report_dir("CounselGo.COM")
    assert path == os.path.join("reports", "counselgo.com")


def test_primary_report_dir_sanitizes_path_like_labels():
    path = main._primary_report_dir("customer targets/list.txt")
    assert path == os.path.join("reports", "customer_targets_list.txt")


def test_primary_report_dir_allows_missing_primary_target_fallback():
    assert main._primary_report_dir(None) is None
