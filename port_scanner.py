import asyncio
import time
import sys

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

async def check_port_with_progress(target_obj, port, semaphore, completed_tasks, state_manager=None):
    """
    Tries to connect to a single port on a given target with progress tracking.
    Uses 'scan_address' for connection and 'resolved_ip' for state.
    Returns the port number if open, otherwise None.
    """
    scan_address = target_obj['scan_address']
    resolved_ip = target_obj['resolved_ip']
    
    async with semaphore:
        try:
            _, writer = await asyncio.wait_for(
                asyncio.open_connection(scan_address, port),
                timeout=2.0
            )
            writer.close()
            await writer.wait_closed()
            result = port
            # Save open port immediately using the resolved IP for state consistency
            if state_manager:
                state_manager.add_open_port(resolved_ip, port)
        except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
            result = None
        finally:
            completed_tasks[0] += 1
            # Update progress periodically
            if state_manager:
                state_manager.update_port_scan_progress(completed_tasks[0])
        return result

async def progress_reporter(total_tasks, completed_tasks, start_time):
    """
    Reports scanning progress in real-time.
    """
    while completed_tasks[0] < total_tasks:
        await asyncio.sleep(0.1)
        current_time = time.time()
        elapsed = current_time - start_time
        completed = completed_tasks[0]
        
        if completed > 0:
            progress = (completed / total_tasks) * 100
            rate = completed / elapsed if elapsed > 0 else 0
            eta = (total_tasks - completed) / rate if rate > 0 else 0
            
            sys.stdout.write(f"\r[*] Progress: {completed:,}/{total_tasks:,} ({progress:.1f}%) | Rate: {rate:.1f} scans/sec | ETA: {eta:.0f}s")
            sys.stdout.flush()

async def scan_ports(targets, ports, concurrency, state_manager=None):
    """
    Scans a list of target objects for a list of ports concurrently.
    Returns a list of tuples, where each tuple contains (target_object, open_ports_data).
    """
    semaphore = asyncio.Semaphore(concurrency)
    tasks = []
    progress_task = None
    
    total_tasks = len(targets) * len(ports)
    completed_tasks = [0]
    start_time = time.time()
    
    print(f"{Colors.CYAN}[*] Scanning {len(targets)} targets across {len(ports)} ports ({total_tasks:,} total combinations){Colors.RESET}")
    print(f"{Colors.CYAN}[*] Concurrency level: {concurrency}{Colors.RESET}")
    print()
    
    # Associate each task with its target object
    for target_obj in targets:
        for port in ports:
            task = asyncio.create_task(check_port_with_progress(target_obj, port, semaphore, completed_tasks, state_manager))
            tasks.append((target_obj, port, task))
            
    try:
        progress_task = asyncio.create_task(progress_reporter(total_tasks, completed_tasks, start_time))
        
        # Wait for all scanning tasks to complete
        await asyncio.gather(*(task for _, _, task in tasks), return_exceptions=True)
        
    except KeyboardInterrupt:
        print(f"\n[!] Scan interrupted by user. Cleaning up...")
        for _, _, task in tasks:
            task.cancel()
        if tasks:
            await asyncio.gather(*(task for _, _, task in tasks), return_exceptions=True)
        return []
        
    finally:
        if progress_task and not progress_task.done():
            progress_task.cancel()

    elapsed = time.time() - start_time
    rate = total_tasks / elapsed if elapsed > 0 else 0
    print(f"\r{Colors.GREEN}[+] Port scan completed: {total_tasks:,} combinations in {elapsed:.1f}s ({rate:.1f} scans/sec){Colors.RESET}")
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

    print(f"{Colors.GREEN}[+] Found {open_ports_found} open ports across {len([d for _, d in final_results if d['open_ports']])} targets{Colors.RESET}")
    return final_results
