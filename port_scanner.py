import asyncio
import contextlib
import errno
import sys
import time
import os

try:
    import resource
except ImportError:  # pragma: no cover - non-Unix fallback
    resource = None


def _env_float(name, default):
    value = os.environ.get(name)
    if value is None:
        return default
    try:
        return float(value)
    except ValueError:
        return default


def _env_int(name, default):
    value = os.environ.get(name)
    if value is None:
        return default
    try:
        return int(value)
    except ValueError:
        return default


DEFAULT_CONNECT_TIMEOUT = max(0.5, _env_float("VAKT_CONNECT_TIMEOUT", 3.5))
DEFAULT_PORT_RETRIES = max(0, _env_int("VAKT_PORT_RETRIES", 1))
DEFAULT_RETRY_BACKOFF = max(0.0, _env_float("VAKT_PORT_RETRY_BACKOFF", 0.15))
FD_RESERVE = 128
FD_BUDGET_PER_CONNECTION = 4
TRANSIENT_SOCKET_ERRNOS = {
    getattr(errno, "EAGAIN", None),
    getattr(errno, "EADDRNOTAVAIL", None),
    getattr(errno, "EINTR", None),
    getattr(errno, "EMFILE", None),
    getattr(errno, "ENFILE", None),
    getattr(errno, "ENOBUFS", None),
    getattr(errno, "ENOMEM", None),
}
TRANSIENT_SOCKET_ERRNOS.discard(None)

# Color codes for terminal output
class Colors:
    # Basic colors
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    GRAY = '\033[90m'
    
    # Bright colors
    BRIGHT_RED = '\033[1;91m'
    BRIGHT_GREEN = '\033[1;92m'
    BRIGHT_YELLOW = '\033[1;93m'
    BRIGHT_BLUE = '\033[1;94m'
    BRIGHT_MAGENTA = '\033[1;95m'
    BRIGHT_CYAN = '\033[1;96m'
    
    # Styles
    BOLD = '\033[1m'
    DIM = '\033[2m'
    UNDERLINE = '\033[4m'
    RESET = '\033[0m'

def calculate_effective_concurrency(requested_concurrency):
    """
    Keeps the requested concurrency within a conservative file-descriptor budget.
    """
    requested = max(1, int(requested_concurrency))

    if resource is None:
        return requested

    try:
        soft_limit, _ = resource.getrlimit(resource.RLIMIT_NOFILE)
    except (OSError, ValueError):
        return requested

    if soft_limit in (-1, getattr(resource, "RLIM_INFINITY", -1)):
        return requested

    budget = max(1, soft_limit - FD_RESERVE)
    safe_concurrency = max(1, budget // FD_BUDGET_PER_CONNECTION)
    return min(requested, safe_concurrency)


def is_transient_socket_error(exc):
    errno_value = getattr(exc, "errno", None)
    if errno_value in TRANSIENT_SOCKET_ERRNOS:
        return True

    message = str(exc).lower()
    return (
        "resource temporarily unavailable" in message
        or "temporary failure" in message
        or "cannot assign requested address" in message
    )


async def check_port_with_progress(
    target_obj,
    port,
    semaphore,
    completed_tasks,
    state_manager=None,
    connect_timeout=DEFAULT_CONNECT_TIMEOUT,
    retries=DEFAULT_PORT_RETRIES,
    retry_backoff=DEFAULT_RETRY_BACKOFF,
    scan_stats=None,
    host_pending=None,
):
    """
    Tries to connect to a single port on a given target with progress tracking.
    Uses 'scan_address' for connection and 'resolved_ip' for state.
    Returns the port number if open, otherwise None.
    """
    scan_address = target_obj['scan_address']
    resolved_ip = target_obj['resolved_ip']

    # Use resolved_ip for the actual TCP connection to avoid issues if scan_address is a URL
    connect_host = resolved_ip if resolved_ip else scan_address
    if connect_host.startswith(('http://', 'https://')):
        import urllib.parse
        connect_host = urllib.parse.urlparse(connect_host).hostname or connect_host
    # Strip brackets from IPv6 addresses - asyncio.open_connection handles bare IPv6 without brackets
    connect_host = connect_host.strip('[]')

    async with semaphore:
        result = None
        attempt = 0
        probe_completed = False
        try:
            while True:
                try:
                    _, writer = await asyncio.wait_for(
                        asyncio.open_connection(connect_host, port),
                        timeout=connect_timeout
                    )
                    writer.close()
                    with contextlib.suppress(Exception):
                        await writer.wait_closed()
                    result = port
                    # Save open port immediately using the resolved IP for state consistency
                    if state_manager:
                        state_manager.add_open_port(resolved_ip, port)
                    break
                except ConnectionRefusedError:
                    break
                except asyncio.TimeoutError:
                    if attempt >= retries:
                        if scan_stats is not None:
                            scan_stats["timeout_failures"] += 1
                        break
                    attempt += 1
                    if scan_stats is not None:
                        scan_stats["retries"] += 1
                    if retry_backoff > 0:
                        await asyncio.sleep(min(retry_backoff * attempt, 0.5))
                except OSError as exc:
                    transient_error = is_transient_socket_error(exc)
                    if transient_error and attempt < retries:
                        attempt += 1
                        if scan_stats is not None:
                            scan_stats["retries"] += 1
                        if retry_backoff > 0:
                            await asyncio.sleep(min(retry_backoff * attempt, 0.5))
                        continue
                    if transient_error and scan_stats is not None:
                        scan_stats["transient_socket_failures"] += 1
                    break
            # Reached only when the probe ran to a definite conclusion (open,
            # refused, timed-out, or errored). A cancellation (Ctrl+C) raises
            # out of an await above and skips this line, leaving the flag False.
            probe_completed = True
        finally:
            completed_tasks[0] += 1
            # Update progress periodically
            if state_manager:
                state_manager.update_port_scan_progress(completed_tasks[0])
                # Per-host sweep completion (Phase 6): when this host's LAST
                # port probe finishes, checkpoint the host as fully scanned so a
                # resume skips it - even hosts with zero open ports. The
                # decrement + check run synchronously (no await between), so the
                # single-threaded event loop makes this atomic without a lock.
                #
                # ONLY count a probe that actually completed. On cancellation
                # the finally still runs, but the port was never probed; if we
                # decremented here an in-flight host could hit 0 and be marked
                # fully scanned, so resume would skip its un-probed ports (and
                # could lose an entire host whose probes were all in-flight).
                # Skipping the decrement leaves the host un-marked, so resume
                # re-scans it - re-probing done ports is wasteful but correct.
                if probe_completed and host_pending is not None:
                    remaining = host_pending.get(resolved_ip)
                    if remaining is not None:
                        remaining -= 1
                        host_pending[resolved_ip] = remaining
                        if remaining <= 0:
                            state_manager.mark_ip_scanned(resolved_ip)
            from modules.dashboard import LiveDashboard
            dashboard = LiveDashboard()
            if dashboard.active:
                dashboard.update_task("port_scan", completed=completed_tasks[0])
        return result

async def progress_reporter(total_tasks, completed_tasks, start_time):
    """
    Reports scanning progress in real-time.
    """
    from modules.dashboard import LiveDashboard
    dashboard = LiveDashboard()
    
    while completed_tasks[0] < total_tasks:
        await asyncio.sleep(0.1)
        current_time = time.time()
        elapsed = current_time - start_time
        completed = completed_tasks[0]
        
        if completed > 0:
            progress = (completed / total_tasks) * 100
            rate = completed / elapsed if elapsed > 0 else 0
            eta = (total_tasks - completed) / rate if rate > 0 else 0
            
            if dashboard.active:
                dashboard.update_task(
                    "port_scan", 
                    completed=completed, 
                    total=total_tasks,
                    status=f"{completed:,}/{total_tasks:,} | Rate: {rate:.1f} scans/s | ETA: {eta:.0f}s"
                )
            else:
                sys.stdout.write(f"\r[*] Progress: {completed:,}/{total_tasks:,} ({progress:.1f}%) | Rate: {rate:.1f} scans/sec | ETA: {eta:.0f}s")
                sys.stdout.flush()

async def scan_ports(
    targets,
    ports,
    concurrency,
    state_manager=None,
    connect_timeout=DEFAULT_CONNECT_TIMEOUT,
    retries=DEFAULT_PORT_RETRIES,
):
    """
    Scans a list of target objects for a list of ports concurrently.
    Returns a list of tuples, where each tuple contains (target_object, open_ports_data).
    """
    connect_timeout = max(0.5, float(connect_timeout))
    retries = max(0, int(retries))
    effective_concurrency = calculate_effective_concurrency(concurrency)
    semaphore = asyncio.Semaphore(effective_concurrency)
    tasks = []
    progress_task = None
    scan_stats = {
        "retries": 0,
        "timeout_failures": 0,
        "transient_socket_failures": 0,
    }

    # Resume skip (Phase 6): drop hosts whose full sweep already completed on a
    # prior run. scanned_ips now records hosts even when they had zero open
    # ports, so a resume never re-scans a host merely because nothing was open.
    # Skipped hosts keep their previously-found open ports in the results.
    skipped_targets = []
    if state_manager is not None:
        already_scanned = set(state_manager.get_scanned_ips())
        if already_scanned:
            _remaining = []
            for _t in targets:
                _ip = _t.get('resolved_ip') or _t.get('scan_address')
                if _ip in already_scanned:
                    skipped_targets.append(_t)
                else:
                    _remaining.append(_t)
            if skipped_targets:
                print(f"{Colors.CYAN}[*] Resume: skipping {len(skipped_targets)} host(s) "
                      f"already port-scanned; scanning {len(_remaining)} remaining.{Colors.RESET}")
            targets = _remaining

    # Per-host completion tracking (Phase 6): count the ports pending for each
    # resolved IP so we can mark_ip_scanned() the instant a host's LAST port
    # probe finishes - even mid-scan, so an interrupt checkpoints completed
    # hosts. Populated only for the hosts actually being scanned this run.
    host_pending = {}
    for _t in targets:
        _ip = _t.get('resolved_ip') or _t.get('scan_address')
        if _ip:
            host_pending[_ip] = host_pending.get(_ip, 0) + len(ports)

    total_tasks = len(targets) * len(ports)
    completed_tasks = [0]
    start_time = time.time()
    
    from modules.dashboard import LiveDashboard
    dashboard = LiveDashboard()
    if dashboard.active:
        dashboard.add_task("port_scan", "Port Scan", total=total_tasks)
    
    print(f"{Colors.CYAN}[*] Scanning {len(targets)} targets across {len(ports)} ports ({total_tasks:,} total combinations){Colors.RESET}")
    if effective_concurrency != concurrency:
        print(
            f"{Colors.YELLOW}[*] Requested concurrency {concurrency} reduced to "
            f"{effective_concurrency} based on the local file descriptor budget{Colors.RESET}"
        )
    else:
        print(f"{Colors.CYAN}[*] Concurrency level: {effective_concurrency}{Colors.RESET}")
    print(
        f"{Colors.CYAN}[*] Port connect timeout: {connect_timeout:.1f}s | Retries per port: {retries}{Colors.RESET}"
    )
    print()
    
    # Associate each task with its target object
    for target_obj in targets:
        for port in ports:
            task = asyncio.create_task(
                check_port_with_progress(
                    target_obj,
                    port,
                    semaphore,
                    completed_tasks,
                    state_manager,
                    connect_timeout=connect_timeout,
                    retries=retries,
                    retry_backoff=DEFAULT_RETRY_BACKOFF,
                    scan_stats=scan_stats,
                    host_pending=host_pending,
                )
            )
            tasks.append((target_obj, port, task))
            
    try:
        progress_task = asyncio.create_task(progress_reporter(total_tasks, completed_tasks, start_time))
        
        # Wait for all scanning tasks to complete
        await asyncio.gather(*(task for _, _, task in tasks), return_exceptions=True)
        
    except asyncio.CancelledError:
        # The outer main task was cancelled (first Ctrl+C). Cancel our child
        # port-probe tasks, await their teardown, then RE-RAISE so the
        # cancellation propagates to the orchestrator (which checkpoints state).
        # Returning [] here would swallow the cancel and let the scan continue.
        print(f"\n[!] Scan interrupted. Cleaning up port-probe tasks...")
        for _, _, task in tasks:
            task.cancel()
        if tasks:
            await asyncio.gather(*(task for _, _, task in tasks), return_exceptions=True)
        raise

    finally:
        if progress_task and not progress_task.done():
            progress_task.cancel()
        if dashboard.active:
            open_ports_count = 0
            for _, _, t in tasks:
                try:
                    if t.done() and not t.exception() and t.result():
                        open_ports_count += 1
                except Exception:
                    pass
            dashboard.complete_task("port_scan", f"Found {open_ports_count} open ports")
    
    elapsed = time.time() - start_time
    rate = total_tasks / elapsed if elapsed > 0 else 0
    print(f"\r{Colors.GREEN}[+] Port scan completed: {total_tasks:,} combinations in {elapsed:.1f}s ({rate:.1f} scans/sec){Colors.RESET}")
    if scan_stats["retries"]:
        print(
            f"{Colors.YELLOW}[*] Retried {scan_stats['retries']} connection attempt(s) due to timeouts "
            f"or transient socket errors{Colors.RESET}"
        )
    if scan_stats["timeout_failures"] or scan_stats["transient_socket_failures"]:
        print(
            f"{Colors.YELLOW}[!] {scan_stats['timeout_failures']} probe(s) timed out and "
            f"{scan_stats['transient_socket_failures']} probe(s) hit transient socket errors. "
            f"If results look incomplete, lower `-c` or raise `--connect-timeout`.{Colors.RESET}"
        )
    print()
    
    # Process results
    results_map = {tuple(target.items()): {'open_ports': []} for target in targets}
    open_ports_found = 0

    for target_obj, port, task in tasks:
        target_key = tuple(target_obj.items())
        result = task.result()
        if isinstance(result, int) and result == port:
            results_map[target_key]['open_ports'].append(port)
            open_ports_found += 1
            
    # Convert the map back to the desired list of tuples format
    final_results = []
    for target_items, data in results_map.items():
        final_results.append((dict(target_items), data))

    # Re-attach hosts skipped on resume (Phase 6) with their persisted open
    # ports, so downstream service validation still sees them.
    if skipped_targets and state_manager is not None:
        saved_open = state_manager.get_open_ports()
        for _t in skipped_targets:
            _ip = _t.get('resolved_ip') or _t.get('scan_address')
            final_results.append((_t, {'open_ports': list(saved_open.get(_ip, []))}))

    print(f"{Colors.GREEN}[+] Found {open_ports_found} open ports across {len([d for _, d in final_results if d['open_ports']])} targets{Colors.RESET}")
    return final_results
