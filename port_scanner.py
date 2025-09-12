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

async def check_port(ip, port, semaphore):
    """
    Tries to connect to a single port on a given IP.
    Returns the port number if open, otherwise None.
    """
    async with semaphore:
        try:
            # Set a timeout for the connection attempt
            _, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port),
                timeout=2.0
            )
            writer.close()
            await writer.wait_closed()
            return port
        except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
            return None

async def progress_reporter(total_tasks, completed_tasks, start_time):
    """
    Reports scanning progress in real-time.
    """
    last_completed = 0
    last_update_time = start_time
    
    # Wait for some progress before showing initial message
    
    while completed_tasks[0] < total_tasks:
        await asyncio.sleep(0.1)  # Very frequent checks for high concurrency
        current_time = time.time()
        elapsed = current_time - start_time
        completed = completed_tasks[0]
        
        # Update every 0.2 seconds or if any progress made
        time_since_update = current_time - last_update_time
        
        if (time_since_update >= 0.2 or completed != last_completed) and completed > 0:
            progress = (completed / total_tasks) * 100
            rate = completed / elapsed if elapsed > 0 else 0
            eta = (total_tasks - completed) / rate if rate > 0 else 0
            
            # Force immediate display
            sys.stdout.write(f"\r[*] Progress: {completed:,}/{total_tasks:,} ({progress:.1f}%) | Rate: {rate:.1f} scans/sec | ETA: {eta:.0f}s")
            sys.stdout.flush()
            
            last_completed = completed
            last_update_time = current_time

async def check_port_with_progress(ip, port, semaphore, completed_tasks, state_manager=None):
    """
    Tries to connect to a single port on a given IP with progress tracking.
    Returns the port number if open, otherwise None.
    """
    async with semaphore:
        try:
            _, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port),
                timeout=2.0
            )
            writer.close()
            await writer.wait_closed()
            result = port
            # Save open port immediately
            if state_manager:
                state_manager.add_open_port(ip, port)
        except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
            result = None
        finally:
            completed_tasks[0] += 1
            # Update progress periodically
            if state_manager:
                state_manager.update_port_scan_progress(completed_tasks[0])
        return result

async def scan_ports(ips, ports, concurrency, state_manager=None):
    """
    Scans a list of IPs for a list of ports concurrently with progress reporting.
    Returns a dictionary with results for each IP.
    """
    semaphore = asyncio.Semaphore(concurrency)
    results = {ip: {'open_ports': []} for ip in ips}
    tasks = []
    progress_task = None
    
    total_tasks = len(ips) * len(ports)
    completed_tasks = [0]
    start_time = time.time()
    
    print(f"{Colors.CYAN}[*] Scanning {len(ips)} IPs across {len(ports)} ports ({total_tasks:,} total combinations){Colors.RESET}")
    print(f"{Colors.CYAN}[*] Concurrency level: {concurrency}{Colors.RESET}")
    print()  # Add blank line for progress updates
    
    try:
        # Start progress reporter first
        progress_task = asyncio.create_task(progress_reporter(total_tasks, completed_tasks, start_time))
        
        # Give progress reporter a moment to initialize and show initial state
        await asyncio.sleep(0.1)
        
        # Create all scanning tasks
        for ip in ips:
            for port in ports:
                tasks.append(asyncio.create_task(check_port_with_progress(ip, port, semaphore, completed_tasks, state_manager)))
        
        print(f"{Colors.CYAN}[*] Starting scan of {len(tasks)} tasks...{Colors.RESET}")
        
        # Wait for all scanning tasks to complete
        scan_results = await asyncio.gather(*tasks, return_exceptions=True)
        
    except KeyboardInterrupt:
        print(f"\n[!] Scan interrupted by user. Cleaning up {len(tasks)} tasks...")
        
        # Cancel all running tasks
        for task in tasks:
            if not task.done():
                task.cancel()
        
        # Wait for tasks to be cancelled
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
        
        print("[!] Cleanup completed.")
        return results
        
    except Exception as e:
        print(f"\n[!] Error during scanning: {e}")
        return results
        
    finally:
        # Always clean up progress reporter
        if progress_task and not progress_task.done():
            progress_task.cancel()
            try:
                await progress_task
            except asyncio.CancelledError:
                pass
    
    # Final progress update - clear the line first
    elapsed = time.time() - start_time
    rate = total_tasks / elapsed if elapsed > 0 else 0
    print(f"\r{Colors.GREEN}[+] Port scan completed: {total_tasks:,} combinations in {elapsed:.1f}s ({rate:.1f} scans/sec){Colors.RESET}")
    print()  # Add blank line after completion
    
    # Process results
    task_index = 0
    open_ports_found = 0
    for ip in ips:
        for port in ports:
            if task_index < len(scan_results):
                result = scan_results[task_index]
                if isinstance(result, int) and result == port:
                    results[ip]['open_ports'].append(port)
                    open_ports_found += 1
            task_index += 1
    
    print(f"{Colors.GREEN}[+] Found {open_ports_found} open ports across {len([ip for ip, data in results.items() if data['open_ports']])} hosts{Colors.RESET}")
    return results
