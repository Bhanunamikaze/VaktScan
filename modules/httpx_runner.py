import asyncio
import csv
import ipaddress
import json
import math
import os
import re
import shutil
import subprocess
import time
from datetime import datetime
from urllib.parse import urlparse

import httpx as python_httpx

from modules import proc


def _print_httpx_progress(completed, total, alive, step):
    if completed % step == 0 or completed == total:
        pct = completed * 100 // total
        print(
            f"\r\033[96m[*] httpx: {completed}/{total} probed ({pct}%) | alive: {alive}\033[0m",
            end='', flush=True
        )


class HTTPXRunner:
    def __init__(self, output_dir="reports"):
        self.output_dir = output_dir
        if not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir)
        self.binary = self._resolve_binary()

    def _resolve_binary(self):
        """Prefer the ProjectDiscovery binary (v1.7.4+) over any python httpx CLI."""
        candidates = [
            os.environ.get("VAKT_HTTPX_BIN"),
            "/usr/local/bin/httpx",
            "/opt/homebrew/bin/httpx",
            os.path.expanduser("~/.bbot/tools/httpx"),
            shutil.which("httpx"),
            shutil.which("pd-httpx"),
        ]
        seen = set()
        for cand in candidates:
            path = self._normalize_path(cand)
            if not path or path in seen:
                continue
            seen.add(path)
            if self._is_projectdiscovery_httpx(path):
                return path
        fallback = shutil.which("httpx")
        if fallback:
            print("\033[93m[!] ProjectDiscovery httpx not found. Falling back to system httpx at: "
                  f"{fallback}\033[0m")
            if "-l, -list" not in self._get_help_output(fallback):
                print("\033[91m[!] System httpx does not support the required CLI flags. "
                      "Using the Python httpx library fallback instead.\033[0m")
                return None
            return fallback
        return None

    def _normalize_path(self, candidate):
        if not candidate:
            return None
        expanded = os.path.expanduser(candidate)
        if os.path.isabs(expanded):
            return expanded if os.path.exists(expanded) else None
        return shutil.which(expanded)

    def _is_projectdiscovery_httpx(self, path):
        help_text = self._get_help_output(path)
        if not help_text:
            return False
        if "Usage:" in help_text and "[flags]" in help_text:
            return True
        if "-l, -list" in help_text:
            return True
        if "<URL> [OPTIONS]" in help_text:
            return False
        return False

    def _get_help_output(self, path):
        try:
            result = subprocess.run(
                [path, "--help"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            return (result.stdout or "") + (result.stderr or "")
        except Exception:
            return ""

    def _extract_title(self, html_text):
        if not html_text:
            return ""
        match = re.search(r"<title[^>]*>(.*?)</title>", html_text, flags=re.IGNORECASE | re.DOTALL)
        if not match:
            return ""
        return " ".join(match.group(1).split())

    def _extract_tech(self, response):
        tech = []
        for header_name in ("server", "x-powered-by"):
            header_value = response.headers.get(header_name)
            if header_value:
                tech.append(f"{header_name}:{header_value}")
        return tech

    def _expand_targets_for_library(self, targets):
        expanded_targets = []
        seen = set()
        for target in targets:
            target = (target or "").strip()
            if not target:
                continue
            if "://" in target:
                variants = [target]
            else:
                variants = [f"http://{target}", f"https://{target}"]
            for variant in variants:
                if variant in seen:
                    continue
                seen.add(variant)
                expanded_targets.append(variant)
        return expanded_targets

    async def _run_httpx_binary(self, targets, concurrency):
        if not self.binary:
            return []

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        input_file = os.path.join(self.output_dir, f"httpx_input_{timestamp}.txt")
        json_output = os.path.join(self.output_dir, f"httpx_raw_{timestamp}.json")

        try:
            with open(input_file, 'w') as f:
                for target in targets:
                    f.write(f"{target}\n")
        except Exception as e:
            print(f"\033[91m[!] Error creating httpx input file: {e}\033[0m")
            return []

        cmd = [
            self.binary,
            "-l", input_file,
            "-json",
            "-nc",
            "-silent",
            "-status-code",
            "-title",
            "-tech-detect",
            "-follow-redirects",
            "-ip",
            "-o", json_output,
            "-t", str(concurrency),
            "-timeout", "10",  # bound per-request time so one dead host can't stall throughput
        ]

        from modules.dashboard import LiveDashboard
        dashboard = LiveDashboard()
        total = len(targets)

        print(f"\033[96m[*] Running httpx on {total} hosts to find alive web services (Concurrency: {concurrency})...\033[0m")

        results = []
        start = time.monotonic()

        def _status():
            elapsed = int(time.monotonic() - start)
            timeout_bound = max(1, math.ceil(total / max(1, concurrency)) * 10)
            remaining = max(0, timeout_bound - elapsed)
            mins, secs = divmod(remaining, 60)
            return (
                f"{len(results)} alive · {elapsed}s elapsed · {total:,} hosts · "
                f"timeout-bound ETA ≤{mins}m{secs:02d}s"
            )

        # httpx streams one JSON object per alive host to stdout, and large target
        # sets take a long time. Emit a live heartbeat (elapsed + alive count) so
        # the task never sits at a frozen "Starting" - it is working, not hung.
        hb_interval = 2 if dashboard.active else 30

        async def _heartbeat():
            try:
                while True:
                    await asyncio.sleep(hb_interval)
                    if dashboard.active:
                        dashboard.update_task("httpx", status=_status())
                    else:
                        print(f"\033[96m[*] httpx still probing… {_status()}\033[0m")
            except asyncio.CancelledError:
                pass

        stderr_chunks = []

        # spawn_tool guarantees process-group teardown on normal exit,
        # exception, or cancellation; the streaming/heartbeat logic below is
        # unchanged inside the context.
        try:
            async with proc.spawn_tool(
                cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            ) as process:

                async def _drain_stderr():
                    # Drain stderr concurrently so a full stderr pipe can't
                    # deadlock the stdout streaming loop below.
                    try:
                        async for chunk in process.stderr:
                            stderr_chunks.append(chunk)
                    except asyncio.CancelledError:
                        pass

                heartbeat_task = asyncio.create_task(_heartbeat())
                stderr_task = asyncio.create_task(_drain_stderr())
                try:
                    async for raw_line in process.stdout:
                        line = raw_line.decode("utf-8", "ignore").strip()
                        if not line:
                            continue
                        try:
                            data = json.loads(line)
                        except json.JSONDecodeError:
                            continue
                        results.append(data)
                        if dashboard.active:
                            dashboard.update_task("httpx", status=_status())
                    await process.wait()
                except Exception as e:
                    print(f"\033[91m[!] Error running httpx: {e}\033[0m")
                finally:
                    # Cancel BOTH helper tasks before awaiting them. On
                    # cancellation the stdout loop above is interrupted and
                    # nobody drains httpx's stdout pipe; if we awaited the
                    # still-running stderr drain without cancelling it, the
                    # httpx child would block writing stdout (~64 KB pipe),
                    # stop emitting stderr, and this await would deadlock -
                    # the spawn_tool teardown never runs. Cancelling first
                    # guarantees prompt group teardown on a single Ctrl+C.
                    heartbeat_task.cancel()
                    stderr_task.cancel()
                    for _t in (heartbeat_task, stderr_task):
                        try:
                            await _t
                        except (asyncio.CancelledError, Exception):
                            pass
        except Exception as e:
            print(f"\033[91m[!] Error running httpx: {e}\033[0m")
            try:
                os.remove(input_file)
            except OSError:
                pass
            return []

        # Fallback: if nothing streamed to stdout (httpx build differences), parse
        # the -o file that httpx also wrote to.
        if not results and os.path.exists(json_output):
            try:
                with open(json_output, 'r') as f:
                    for line in f:
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            results.append(json.loads(line))
                        except json.JSONDecodeError:
                            continue
            except OSError:
                pass

        if not results:
            stderr_text = b"".join(stderr_chunks).decode("utf-8", "ignore").strip()
            if stderr_text:
                print(f"\033[91m[!] httpx produced no results: {stderr_text.splitlines()[-1]}\033[0m")

        for _path in (input_file, json_output):
            try:
                os.remove(_path)
            except OSError:
                pass

        print(f"\033[92m[+] httpx finished. Found {len(results)} alive services.\033[0m")
        return results

    async def _run_httpx_library(self, targets, concurrency=100):
        expanded_targets = self._expand_targets_for_library(targets)
        if not expanded_targets:
            return []

        from modules.dashboard import LiveDashboard
        dashboard = LiveDashboard()
        
        print(
            f"\033[96m[*] Running Python httpx fallback on {len(expanded_targets)} URL probes "
            f"(Concurrency: {concurrency})...\033[0m"
        )

        semaphore = asyncio.Semaphore(max(1, int(concurrency)))
        timeout = python_httpx.Timeout(10.0, connect=5.0)
        results = []
        seen_urls = set()
        total = len(expanded_targets)
        completed = 0
        progress_step = max(1, total // 10)
        started = time.monotonic()

        def _library_status():
            elapsed = max(0.001, time.monotonic() - started)
            rate = completed / elapsed
            remaining = max(0, total - completed)
            eta_seconds = int(remaining / rate) if rate > 0 else 0
            mins, secs = divmod(eta_seconds, 60)
            return (
                f"Probed {completed}/{total} (alive: {len(results)}) | "
                f"{rate:.1f}/s | ETA {mins}m{secs:02d}s"
            )

        if dashboard.active:
            dashboard.update_task("httpx", total=total)

        async with python_httpx.AsyncClient(
            timeout=timeout,
            verify=False,
            follow_redirects=True,
        ) as client:
            async def probe(target):
                nonlocal completed
                async with semaphore:
                    try:
                        response = await client.get(target)
                    except python_httpx.HTTPError:
                        completed += 1
                        if dashboard.active:
                            dashboard.update_task("httpx", completed=completed, status=_library_status())
                        else:
                            _print_httpx_progress(completed, total, len(results), progress_step)
                        return

                    source_url = target
                    final_url = str(response.url)
                    completed += 1
                    if dashboard.active:
                        dashboard.update_task("httpx", completed=completed, status=_library_status())
                    else:
                        _print_httpx_progress(completed, total, len(results), progress_step)
                    # Keep every distinct source endpoint in inventory even when
                    # several ports/hosts redirect to the same canonical page.
                    # ProjectDiscovery httpx uses this same source-url meaning
                    # for its ``url`` field when redirects are followed.
                    if source_url in seen_urls:
                        return
                    seen_urls.add(source_url)

                    parsed = urlparse(source_url)
                    input_parsed = parsed
                    input_value = input_parsed.netloc or input_parsed.path or target
                    port = parsed.port or (443 if parsed.scheme == "https" else 80)
                    chain_status_codes = [
                        redirect.status_code for redirect in response.history
                    ] + [response.status_code]
                    results.append({
                        "input": input_value,
                        "url": source_url,
                        "source_url": source_url,
                        "final_url": final_url,
                        "host": parsed.hostname or "",
                        "port": port,
                        "status_code": response.status_code,
                        "chain_status_codes": chain_status_codes,
                        "title": self._extract_title(response.text),
                        "tech": self._extract_tech(response),
                    })

            await asyncio.gather(*(probe(target) for target in expanded_targets))
        
        if not dashboard.active:
            print()  # newline after progress line

        print(f"\033[92m[+] Python httpx fallback finished. Found {len(results)} alive services.\033[0m")
        return results

    async def run_httpx(self, targets, concurrency=100):
        """
        Runs httpx on a list of targets (host:port) using the specified concurrency.
        """
        if not targets:
            return []

        from modules.dashboard import LiveDashboard
        dashboard = LiveDashboard()
        if dashboard.active:
            dashboard.add_task("httpx", "HTTPX Probing", total=len(targets))

        res = []
        try:
            if self.binary:
                res = await self._run_httpx_binary(targets, concurrency)
            else:
                print("\033[93m[!] ProjectDiscovery httpx binary unavailable. Using Python httpx fallback.\033[0m")
                res = await self._run_httpx_library(targets, concurrency)
            return res
        finally:
            if dashboard.active:
                dashboard.complete_task("httpx", f"Found {len(res)} alive services")

    def save_csv(self, httpx_data, domain_label):
        """
        Save parsed httpx data while keeping source and redirect attribution
        explicit.

        ProjectDiscovery httpx deliberately leaves ``url``, ``host``, and
        ``port`` pointing at the probed source endpoint when
        ``-follow-redirects`` is enabled, while the status/title/technology
        fields describe the terminal response.  Preserve that source inventory
        and expose the terminal URL and compact status-only redirect chain in
        separate columns.  Raw chain requests/responses are intentionally not
        requested or stored because they can contain cookies or credentials.
        """
        if not httpx_data:
            return None

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"httpx_alive_{domain_label}_{timestamp}.csv"
        filepath = os.path.join(self.output_dir, filename)
        
        # ``URL`` remains the source URL for backwards compatibility with scan
        # resume and downstream consumers.  ``Source URL`` makes that contract
        # unambiguous to humans reading the CSV.
        headers = [
            'IP Address', 'Domain', 'Port', 'URL', 'Source URL', 'Final URL',
            'Redirect Status Chain', 'Status Code', 'Title', 'Technologies',
        ]

        try:
            with open(filepath, 'w', newline='', encoding='utf-8') as csvfile:
                writer = csv.writer(csvfile)
                writer.writerow(headers)
                
                for entry in httpx_data:
                    source_url = str(
                        entry.get('source_url')
                        or entry.get('url')
                        or entry.get('input')
                        or ''
                    ).strip()
                    parse_value = source_url
                    if parse_value and '://' not in parse_value:
                        parse_value = f'//{parse_value}'
                    parsed = urlparse(parse_value)

                    domain = parsed.hostname or str(entry.get('host') or '').strip() or 'N/A'
                    try:
                        parsed_port = parsed.port
                    except ValueError:
                        parsed_port = None
                    port = parsed_port or entry.get('port', '')

                    ip = str(entry.get('host_ip') or entry.get('ip') or '').strip()
                    if not ip and domain != 'N/A':
                        try:
                            ipaddress.ip_address(domain)
                        except ValueError:
                            pass
                        else:
                            ip = domain
                    if not ip:
                        ip = 'N/A'

                    final_url = str(entry.get('final_url') or source_url).strip()
                    status_chain = entry.get('chain_status_codes') or []
                    if isinstance(status_chain, (list, tuple)):
                        status_chain = ' -> '.join(str(code) for code in status_chain)
                    else:
                        status_chain = str(status_chain)
                    title = entry.get('title', '')
                    status = entry.get('status_code', '')
                    technologies = entry.get('tech', [])
                    tech = technologies if isinstance(technologies, str) else ",".join(technologies)

                    writer.writerow([
                        ip, domain, port, source_url, source_url, final_url,
                        status_chain, status, title, tech,
                    ])
            
            print(f"\033[92m[+] Alive services CSV saved to: \033[1m{filepath}\033[0m")
            return filepath
        except Exception as e:
            print(f"\033[91m[!] Error saving httpx CSV: {e}\033[0m")
            return None
