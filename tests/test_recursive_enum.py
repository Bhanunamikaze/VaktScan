"""Recursive enumeration must stay in scope and stop at the requested depth."""

import asyncio
from pathlib import Path

from modules.recon import ReconScanner


def test_recursive_enumeration_respects_depth_and_deduplicates(tmp_path, monkeypatch):
    calls = []
    results = {
        "a.example.com": ["x.a.example.com", "x.a.example.com", "outside.test"],
        "b.example.com": ["x.a.example.com", "y.b.example.com"],
        "x.a.example.com": ["z.x.a.example.com"],
        "y.b.example.com": ["q.y.b.example.com"],
    }

    async def fake_run_all(self):
        calls.append(self.domain)
        return "unused", results.get(self.domain, [])

    monkeypatch.setattr(ReconScanner, "run_all", fake_run_all)
    scanner = ReconScanner("example.com", output_dir=str(tmp_path), recursive_levels=2)
    scanner.subdomains = {"a.example.com", "b.example.com"}
    asyncio.run(scanner._run_recursive_levels())

    assert set(calls) == {"a.example.com", "b.example.com", "x.a.example.com", "y.b.example.com"}
    assert len(calls) == 4
    assert "z.x.a.example.com" in scanner.subdomains
    assert "q.y.b.example.com" in scanner.subdomains
    assert "outside.test" not in scanner.subdomains


def test_recursive_enumeration_excludes_branch_and_rejects_suffix_trick(tmp_path, monkeypatch):
    calls = []

    async def fake_run_all(self):
        calls.append(self.domain)
        return "unused", ["new." + self.domain]

    monkeypatch.setattr(ReconScanner, "run_all", fake_run_all)
    scanner = ReconScanner(
        "example.com", output_dir=str(tmp_path), recursive_levels=1,
        recursive_exclude=lambda host: host == "skip.example.com",
    )
    scanner.subdomains = {"skip.example.com", "ok.example.com"}
    assert not scanner._add_subdomain("evil-example.com")
    asyncio.run(scanner._run_recursive_levels())
    assert calls == ["ok.example.com"]
    assert "new.ok.example.com" in scanner.subdomains
    assert "new.skip.example.com" not in scanner.subdomains


def test_recursive_results_are_written_to_parent_output(tmp_path, monkeypatch):
    monkeypatch.setattr(ReconScanner, "check_tools",
                        lambda self: [name for name in self.tools if name != "subfinder"])

    async def fake_subfinder(self):
        for host in {"example.com": ["a.example.com"],
                     "a.example.com": ["deep.a.example.com"]}.get(self.domain, []):
            self._add_subdomain(host)

    monkeypatch.setattr(ReconScanner, "run_subfinder", fake_subfinder)
    scanner = ReconScanner(
        "example.com", output_dir=str(tmp_path), recursive_levels=1,
        skip_tools={"virustotal", "shodan", "censys-api"},
    )
    output, hosts = asyncio.run(scanner.run_all())
    assert hosts == ["a.example.com", "deep.a.example.com"]
    assert Path(output).read_text(encoding="utf-8").splitlines() == hosts


def test_recursive_children_do_not_create_dashboard_rows(tmp_path, monkeypatch):
    class Dashboard:
        active = True

        def __init__(self):
            self.tasks = {}
            self.max_tasks = 0

        def add_task(self, task_id, name, total=None):
            self.tasks[task_id] = name
            self.max_tasks = max(self.max_tasks, len(self.tasks))

        def update_task(self, task_id, **kwargs):
            assert task_id in self.tasks

        def complete_task(self, task_id, status="Completed"):
            assert task_id in self.tasks

    dashboard = Dashboard()
    monkeypatch.setattr("modules.dashboard.LiveDashboard", lambda: dashboard)
    monkeypatch.setattr(
        ReconScanner, "check_tools",
        lambda self: [name for name in self.tools if name != "subfinder"],
    )

    async def fake_subfinder(self):
        if self.domain == "example.com":
            for index in range(31):
                self._add_subdomain(f"child{index}.example.com")
        else:
            self._add_subdomain(f"deep.{self.domain}")

    monkeypatch.setattr(ReconScanner, "run_subfinder", fake_subfinder)
    scanner = ReconScanner(
        "example.com", output_dir=str(tmp_path), recursive_levels=1,
        skip_tools={"virustotal", "shodan", "censys-api"},
    )
    _, hosts = asyncio.run(scanner.run_all())

    assert len(hosts) == 62
    assert dashboard.max_tasks == 2
    assert set(dashboard.tasks) == {"subfinder", "recursive_example.com"}
