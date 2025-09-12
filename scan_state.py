import json
import os
import time
import hashlib
import threading
import atexit
from typing import Dict, List, Any

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

class ScanStateManager:
    """
    Manages scan state persistence for resuming interrupted scans.
    Optimized for high concurrency with batched saves and file handle management.
    """
    
    def __init__(self, targets_file: str, concurrency: int):
        # Create state filename based on targets file and settings
        targets_hash = hashlib.md5(f"{targets_file}_{concurrency}".encode()).hexdigest()[:8]
        self.state_file = f"scan_state_{targets_hash}.json"
        self.targets_file = targets_file
        self.concurrency = concurrency
        
        # Threading controls for batched saves
        self._lock = threading.Lock()
        self._save_pending = False
        self._last_save_time = time.time()
        self._min_save_interval = 120.0  # Save every 2 minutes
        self._pending_open_ports = {}  # Buffer for open ports to save
        self._shutdown = False
        
        # Start background save timer
        self._save_timer = None
        self._start_background_saver()
        
        # Ensure cleanup on exit
        atexit.register(self._cleanup_on_exit)
        
        self.state = {
            "scan_id": targets_hash,
            "targets_file": targets_file,
            "concurrency": concurrency,
            "start_time": time.time(),
            "last_updated": time.time(),
            "phase": "initializing",  # initializing, port_scanning, service_validation, vulnerability_scanning, completed
            "total_ips": 0,
            "total_combinations": 0,
            "port_scan_progress": {
                "completed_combinations": 0,
                "scanned_ips": []
            },
            "open_ports": {},  # {ip: [ports]}
            "validated_services": {},  # {ip: {port: service}}
            "vulnerabilities": [],
            "completed": False
        }
    
    def load_existing_state(self) -> bool:
        """
        Load existing scan state if available.
        Returns True if state was loaded, False if starting fresh.
        """
        if os.path.exists(self.state_file):
            try:
                with open(self.state_file, 'r') as f:
                    saved_state = json.load(f)
                
                # Verify this is the same scan
                if (saved_state.get("targets_file") == self.targets_file and 
                    saved_state.get("concurrency") == self.concurrency):
                    self.state.update(saved_state)
                    print(f"[+] Resuming scan from {self.state_file}")
                    print(f"    Phase: {self.state['phase']}")
                    print(f"    Progress: {self.state['port_scan_progress']['completed_combinations']:,}/{self.state['total_combinations']:,}")
                    print(f"    Open ports found: {sum(len(ports) for ports in self.state['open_ports'].values())}")
                    print(f"    Vulnerabilities found: {len(self.state['vulnerabilities'])}")
                    return True
            except Exception as e:
                print(f"[!] Error loading state file: {e}")
                print("[*] Starting fresh scan")
        
        print(f"[*] Creating new scan state: {self.state_file}")
        return False
    
    def _start_background_saver(self):
        """
        Start background timer to periodically save pending changes.
        """
        if not self._shutdown:
            self._save_timer = threading.Timer(self._min_save_interval, self._background_save)
            self._save_timer.daemon = True
            self._save_timer.start()
    
    def _background_save(self):
        """
        Background timer callback to save state every 2 minutes.
        """
        if not self._shutdown:
            # Always save current state (not just when pending)
            self.save_state(force=True)
            print(f"\n\033[92m[*] State checkpoint saved at {time.strftime('%H:%M:%S')}\033[0m")
        
        # Schedule next save in 2 minutes
        self._start_background_saver()
    
    def _cleanup_on_exit(self):
        """
        Cleanup method called on exit.
        """
        self._shutdown = True
        if self._save_timer:
            self._save_timer.cancel()
        if self._save_pending:
            self.save_state(force=True)
    
    def save_state(self, force=False):
        """
        Save current scan state to disk with rate limiting and proper file handling.
        """
        with self._lock:
            current_time = time.time()
            
            # Rate limit saves unless forced
            if not force and (current_time - self._last_save_time) < self._min_save_interval:
                self._save_pending = True
                return
            
            try:
                # Merge any pending open ports
                if self._pending_open_ports:
                    for ip, ports in self._pending_open_ports.items():
                        if ip not in self.state["open_ports"]:
                            self.state["open_ports"][ip] = []
                        for port in ports:
                            if port not in self.state["open_ports"][ip]:
                                self.state["open_ports"][ip].append(port)
                    self._pending_open_ports.clear()
                
                self.state["last_updated"] = current_time
                
                # Use atomic write with temporary file
                temp_file = f"{self.state_file}.tmp"
                with open(temp_file, 'w') as f:
                    json.dump(self.state, f, indent=2)
                
                # Atomic rename
                os.rename(temp_file, self.state_file)
                
                self._last_save_time = current_time
                self._save_pending = False
                
            except Exception as e:
                print(f"[!] Error saving state: {e}")
                # Clean up temp file if it exists
                try:
                    if os.path.exists(f"{self.state_file}.tmp"):
                        os.remove(f"{self.state_file}.tmp")
                except:
                    pass
    
    def update_phase(self, phase: str):
        """
        Update the current scan phase.
        """
        self.state["phase"] = phase
        self.save_state()
    
    def set_totals(self, total_ips: int, total_combinations: int):
        """
        Set the total counts for the scan.
        """
        self.state["total_ips"] = total_ips
        self.state["total_combinations"] = total_combinations
        self.save_state()
    
    def update_port_scan_progress(self, completed_combinations: int):
        """
        Update port scanning progress - saves handled by 2-minute timer.
        """
        self.state["port_scan_progress"]["completed_combinations"] = completed_combinations
        # No immediate saves - 2-minute timer will handle persistence
    
    def add_open_port(self, ip: str, port: int):
        """
        Record an open port - saves handled by 2-minute timer.
        """
        with self._lock:
            if ip not in self.state["open_ports"]:
                self.state["open_ports"][ip] = []
            if port not in self.state["open_ports"][ip]:
                self.state["open_ports"][ip].append(port)
            # Timer-based saves every 2 minutes - no immediate disk I/O
    
    def add_validated_service(self, ip: str, port: int, service: str):
        """
        Record a validated service.
        """
        if ip not in self.state["validated_services"]:
            self.state["validated_services"][ip] = {}
        self.state["validated_services"][ip][str(port)] = service
        self.save_state()
    
    def add_vulnerability(self, vulnerability: Dict[str, Any]):
        """
        Record a found vulnerability.
        """
        self.state["vulnerabilities"].append(vulnerability)
        # Save immediately for vulnerabilities (they're the main goal)
        self.save_state()
    
    def get_scanned_ips(self) -> List[str]:
        """
        Get list of IPs that have already been port scanned.
        """
        return list(self.state["open_ports"].keys())
    
    def get_remaining_ips(self, all_ips: List[str]) -> List[str]:
        """
        Get list of IPs that still need to be scanned.
        """
        scanned = set(self.state["open_ports"].keys())
        return [ip for ip in all_ips if ip not in scanned]
    
    def get_open_ports(self) -> Dict[str, List[int]]:
        """
        Get all discovered open ports.
        """
        return self.state["open_ports"]
    
    def get_validated_services(self) -> Dict[str, Dict[str, str]]:
        """
        Get all validated services.
        """
        return self.state["validated_services"]
    
    def get_vulnerabilities(self) -> List[Dict[str, Any]]:
        """
        Get all found vulnerabilities.
        """
        return self.state["vulnerabilities"]
    
    def flush_pending_saves(self):
        """
        Force save any pending state changes.
        """
        if self._save_pending or self._pending_open_ports:
            self.save_state(force=True)
    
    def mark_completed(self):
        """
        Mark the scan as completed.
        """
        self.state["completed"] = True
        self.state["phase"] = "completed"
        self.save_state(force=True)  # Force final save
    
    def cleanup_state_file(self):
        """
        Remove the state file (call after successful completion).
        """
        # Stop background saver
        self._shutdown = True
        if self._save_timer:
            self._save_timer.cancel()
        
        # Ensure all pending saves are flushed before cleanup
        self.flush_pending_saves()
        
        try:
            if os.path.exists(self.state_file):
                os.remove(self.state_file)
                print(f"{Colors.GREEN}[+] Cleaned up state file: {self.state_file}{Colors.RESET}")
        except Exception as e:
            print(f"[!] Error removing state file: {e}")
    
    def get_scan_summary(self) -> str:
        """
        Get a summary of the current scan state.
        """
        elapsed = time.time() - self.state["start_time"]
        return f"""
{Colors.BRIGHT_CYAN}Scan Summary:{Colors.RESET}
  {Colors.CYAN}Phase:{Colors.RESET} {Colors.YELLOW}{self.state['phase']}{Colors.RESET}
  {Colors.CYAN}Runtime:{Colors.RESET} {Colors.WHITE}{elapsed:.1f}s{Colors.RESET}
  {Colors.CYAN}Total IPs:{Colors.RESET} {Colors.WHITE}{self.state['total_ips']:,}{Colors.RESET}
  {Colors.CYAN}Total combinations:{Colors.RESET} {Colors.WHITE}{self.state['total_combinations']:,}{Colors.RESET}
  {Colors.CYAN}Port scan progress:{Colors.RESET} {Colors.WHITE}{self.state['port_scan_progress']['completed_combinations']:,}{Colors.RESET}
  {Colors.CYAN}Open ports found:{Colors.RESET} {Colors.GREEN}{sum(len(ports) for ports in self.state['open_ports'].values())}{Colors.RESET}
  {Colors.CYAN}Validated services:{Colors.RESET} {Colors.GREEN}{sum(len(services) for services in self.state['validated_services'].values())}{Colors.RESET}
  {Colors.CYAN}Vulnerabilities found:{Colors.RESET} {Colors.BRIGHT_RED}{len(self.state['vulnerabilities'])}{Colors.RESET}
"""