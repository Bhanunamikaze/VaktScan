import json
import os
import glob
import time
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
    
    def __init__(self, scan_id: str, canonical_targets: List[str], scope: str,
                 non_scope_config: Dict[str, Any] = None, primary_target: str = None):
        # Stable, resumable state identity (Phase 4). ``scan_id`` is derived from
        # the normalized target set + scope-affecting config (see state_key.py),
        # NEVER from a temp path or ``concurrency`` - so ad-hoc ``scan <ip|domain
        # |cidr>`` runs and a renamed-but-identical targets file both resume, and
        # changing ``-c`` does not break resume. State files live in a dedicated
        # dir (``./.vaktscan/state/``) overridable via ``VAKT_STATE_DIR``; the
        # atomic ``.tmp``+rename stays inside that dir (one filesystem).
        #
        # ``non_scope_config`` (Phase 5) carries settings that DON'T change the
        # scan id (concurrency, timeouts, ...); a diff on resume warns and adopts
        # the new values. ``primary_target`` is the human-readable label surfaced
        # in ``--list-resumable`` / the state index.
        base_dir = os.environ.get("VAKT_STATE_DIR") or os.path.join(".vaktscan", "state")
        try:
            os.makedirs(base_dir, exist_ok=True)
        except OSError:
            pass
        self._state_dir = base_dir
        self.scan_id = scan_id
        self.canonical_targets = list(canonical_targets or [])
        self.scope = scope
        self.non_scope_config = dict(non_scope_config or {})
        self.primary_target = primary_target or (
            self.canonical_targets[0] if self.canonical_targets else scan_id
        )
        # Set True by load_existing_state(strict=True) when a forced --resume-id
        # lands on a state whose targets/scope differ - so the caller can refuse.
        self.identity_mismatch = False
        self.state_file = os.path.join(base_dir, f"{scan_id}.json")

        # Threading controls for batched saves
        self._lock = threading.Lock()
        self._save_pending = False
        self._last_save_time = time.time()
        # Checkpoint cadence (Phase 6): tightened 120 -> 30s so an interrupt
        # loses at most ~30s of un-forced progress. Phase changes, vulns,
        # validated services, web batches, and per-host port sweeps still
        # force-save immediately regardless of this interval.
        self._min_save_interval = 30.0
        self._pending_open_ports = {}  # Buffer for open ports to save
        # Batch counter so mark_ip_scanned() force-saves every N hosts instead
        # of once per host (bounds disk I/O on large sweeps while keeping the
        # scanned_ips checkpoint durable).
        self._ip_scanned_since_save = 0
        self._ip_scan_save_batch = 25
        self._shutdown = False

        # Start background save timer
        self._save_timer = None
        self._start_background_saver()

        # Ensure cleanup on exit
        atexit.register(self._cleanup_on_exit)

        self.state = self._fresh_state()

    def _fresh_state(self) -> Dict[str, Any]:
        """Build a clean, default state dict carrying this manager's identity."""
        now = time.time()
        return {
            "scan_id": self.scan_id,
            "canonical_targets": self.canonical_targets,
            "scope": self.scope,
            "non_scope_config": self.non_scope_config,
            "primary_target": self.primary_target,
            "start_time": now,
            "last_updated": now,
            "phase": "initializing",  # initializing, port_scanning, service_validation, vulnerability_scanning, completed
            "total_ips": 0,
            "total_combinations": 0,
            "port_scan_progress": {
                "completed_combinations": 0,
                "scanned_ips": []
            },
            # Hosts whose FULL port sweep finished (Phase 6). Unlike open_ports
            # keys - which only record hosts with >=1 open port - this includes
            # hosts that came back fully closed, so a resume never re-scans a
            # host just because it had zero open ports.
            "scanned_ips": [],
            "open_ports": {},  # {ip: [ports]}
            "validated_services": {},  # {ip: {port: service}}
            # Per-service scans that already ran to completion (Phase 6), keyed
            # "{ip}:{port}:{service}", so an interrupted vulnerability-scanning
            # phase resumes without redoing scanners that already finished.
            "completed_service_scans": [],
            # Recon domains whose enumeration+probe pipeline already completed
            # (Phase 6); persisted so recon findings survive an interrupt.
            "completed_recon_domains": [],
            # Per completed recon domain, the subdomain set it yielded, so a
            # resume can skip re-running the (finding-adding) recon pipeline yet
            # still rebuild the downstream target set. {domain: [subdomains]}
            "recon_results": {},
            "vulnerabilities": [],
            # URLs whose full web-probe pipeline (httpx→nuclei→web_checks→
            # dirsearch→JS) already finished, so an interrupted web-probe can
            # resume from the URLs it had not reached yet.
            "completed_web_urls": [],
            "completed": False
        }

    def reset_to_fresh(self):
        """Discard any loaded/persisted progress and start clean, keeping the
        stable identity. Used for ``--fresh`` and when an auto-resume finds a
        state that is already ``completed`` (a finished scan is not resumable)."""
        self.state = self._fresh_state()
    
    def _read_state_json(self, path):
        """Read+parse a state file, returning the dict or None on any error."""
        try:
            with open(path, 'r') as f:
                return json.load(f)
        except Exception as e:
            print(f"[!] Error loading state file: {e}")
            print("[*] Starting fresh scan")
            return None

    def _load_legacy_state(self):
        """Best-effort legacy shim: pre-Phase-4 runs wrote a single
        ``scan_state_<hash>.json`` into the CWD, keyed off the (temp) targets-file
        path + concurrency. That key can't be recomputed here, so - only when the
        new-location file is absent - adopt the sole legacy file in the CWD if it
        looks like a valid state. Ad-hoc legacy states were never resumable
        anyway; this just preserves file-target resumes across the relocation for
        one release. Returns the parsed dict or None."""
        try:
            legacy = sorted(glob.glob("scan_state_*.json"))
        except Exception:
            return None
        if len(legacy) != 1:
            return None  # ambiguous or none -> don't guess
        saved = self._read_state_json(legacy[0])
        if isinstance(saved, dict) and "phase" in saved and "open_ports" in saved:
            print(f"[*] Migrating legacy state {legacy[0]} -> {self.state_file}")
            return saved
        return None

    def load_existing_state(self, strict: bool = False) -> bool:
        """
        Load existing scan state if available.
        Returns True if state was loaded, False if starting fresh.

        Identity is verified against the stored ``canonical_targets`` AND
        ``scope``. Normally, on a mismatch (a hash collision or a reused id) the
        existing state is NEVER clobbered - this run's writes are relocated to
        ``<scan_id>-1.json`` and we start fresh. When ``strict`` (a forced
        ``--resume-id``) the mismatch instead sets ``self.identity_mismatch`` and
        returns False WITHOUT forking, so the caller can refuse and point the user
        at ``--fresh`` rather than silently starting a new scan.
        """
        saved_state = None
        if os.path.exists(self.state_file):
            saved_state = self._read_state_json(self.state_file)
        else:
            saved_state = self._load_legacy_state()

        if isinstance(saved_state, dict):
            # Phase-4 states carry canonical_targets + scope; verify them. Legacy
            # states (migrated via the shim) lack both keys - accept those as-is.
            has_identity = ("canonical_targets" in saved_state) or ("scope" in saved_state)
            if has_identity:
                same_targets = saved_state.get("canonical_targets") == self.canonical_targets
                same_scope = saved_state.get("scope") == self.scope
                if not (same_targets and same_scope):
                    if strict:
                        self.identity_mismatch = True
                        return False
                    self.state_file = os.path.join(self._state_dir, f"{self.scan_id}-1.json")
                    print(f"[!] State id collision for '{self.scan_id}' (targets/scope differ); "
                          f"preserving old state, writing to {os.path.basename(self.state_file)}.")
                    print(f"[*] Creating new scan state: {self.state_file}")
                    return False

            # Non-scope config (concurrency/timeouts/...) may legitimately change
            # across a resume - warn once, then adopt the new values.
            saved_nsc = saved_state.get("non_scope_config") or {}
            if saved_nsc and self.non_scope_config and saved_nsc != self.non_scope_config:
                changed = sorted(
                    k for k in set(saved_nsc) | set(self.non_scope_config)
                    if saved_nsc.get(k) != self.non_scope_config.get(k)
                )
                print(f"[!] Resuming with changed settings ({', '.join(changed)}); "
                      f"using the new values (does not affect scan identity).")

            self.state.update(saved_state)
            # Keep our identity authoritative regardless of what was on disk.
            self.state["scan_id"] = self.scan_id
            self.state["canonical_targets"] = self.canonical_targets
            self.state["scope"] = self.scope
            self.state["non_scope_config"] = self.non_scope_config
            self.state["primary_target"] = self.primary_target
            print(f"[+] Resuming scan from {self.state_file}")
            print(f"    Phase: {self.state['phase']}")
            print(f"    Progress: {self.state['port_scan_progress']['completed_combinations']:,}/{self.state['total_combinations']:,}")
            print(f"    Open ports found: {sum(len(ports) for ports in self.state['open_ports'].values())}")
            print(f"    Vulnerabilities found: {len(self.state['vulnerabilities'])}")
            return True

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
                
                # The state dir can vanish mid-run (manual cleanup, tmpfs); recreate
                # it so a save never silently fails and loses resumable progress.
                os.makedirs(self._state_dir, exist_ok=True)

                # Use atomic write with temporary file
                temp_file = f"{self.state_file}.tmp"
                with open(temp_file, 'w') as f:
                    json.dump(self.state, f, indent=2)
                
                # Atomic rename
                os.rename(temp_file, self.state_file)

                # Keep the resumable-scan index in step with every real save so
                # ``--list-resumable`` reflects live progress (best-effort).
                self._update_index()

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

        Force-saved (Phase 6): the phase is the primary resume anchor, so it
        must hit disk immediately - not wait on the 30s timer - or an interrupt
        right after a phase transition would resume into the wrong branch.
        """
        self.state["phase"] = phase
        self.save_state(force=True)
    
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
            # Timer-based saves - no immediate disk I/O here

    def mark_ip_scanned(self, ip: str):
        """Record that a host's FULL port sweep finished (Phase 6).

        Called once per host as its last port probe completes - including hosts
        with zero open ports - so ``get_remaining_ips`` / the port-scan skip on
        resume never re-scan a completed host. Force-saved in batches of
        ``_ip_scan_save_batch`` to keep the checkpoint durable without one disk
        write per host.
        """
        if not ip:
            return
        force = False
        with self._lock:
            bucket = self.state.setdefault("scanned_ips", [])
            if ip not in bucket:
                bucket.append(ip)
            self._ip_scanned_since_save += 1
            if self._ip_scanned_since_save >= self._ip_scan_save_batch:
                self._ip_scanned_since_save = 0
                force = True
        # save_state re-acquires the lock (not reentrant) - call it outside.
        if force:
            self.save_state(force=True)

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
    
    def get_completed_web_urls(self) -> set:
        """
        URLs whose full web-probe pipeline already completed (used to skip them
        when resuming an interrupted web-probe phase).
        """
        return set(self.state.get("completed_web_urls", []))

    def add_completed_web_urls(self, urls: List[str]):
        """
        Record web-probe URLs as fully processed and persist immediately, so an
        interrupted web-probe resumes from the not-yet-probed URLs instead of
        re-probing everything.
        """
        with self._lock:
            bucket = self.state.setdefault("completed_web_urls", [])
            seen = set(bucket)
            for url in urls:
                if url not in seen:
                    bucket.append(url)
                    seen.add(url)
        # Force outside the lock (save_state re-acquires it - Lock isn't reentrant).
        self.save_state(force=True)

    def get_scanned_ips(self) -> List[str]:
        """
        Get list of IPs whose port sweep already completed.

        Phase 6: this is the persisted ``scanned_ips`` set (hosts whose full
        sweep finished, open ports or not), unioned with ``open_ports`` keys for
        backward-compatibility with pre-Phase-6 state files that only recorded
        hosts with open ports.
        """
        scanned = set(self.state.get("scanned_ips") or [])
        scanned.update(self.state["open_ports"].keys())
        return list(scanned)

    def get_remaining_ips(self, all_ips: List[str]) -> List[str]:
        """
        Get list of IPs that still need to be scanned.

        Phase 6: skips every host whose full sweep completed (``scanned_ips``),
        not just those that happened to have an open port.
        """
        scanned = set(self.get_scanned_ips())
        return [ip for ip in all_ips if ip not in scanned]

    def mark_service_scan_done(self, ip: str, port, service: str):
        """Record that a per-service scanner finished for ``{ip}:{port}:{service}``.

        Force-saved so a resume of an interrupted ``vulnerability_scanning`` phase
        can skip the service scans that already completed instead of redoing them.
        """
        key = f"{ip}:{port}:{service}"
        with self._lock:
            bucket = self.state.setdefault("completed_service_scans", [])
            if key in bucket:
                return
            bucket.append(key)
        self.save_state(force=True)

    def get_completed_service_scans(self) -> set:
        """Set of completed ``{ip}:{port}:{service}`` scan keys (Phase 6)."""
        return set(self.state.get("completed_service_scans") or [])

    def is_service_scan_done(self, ip: str, port, service: str) -> bool:
        """True if ``{ip}:{port}:{service}`` already ran to completion (Phase 6)."""
        return f"{ip}:{port}:{service}" in (self.state.get("completed_service_scans") or [])

    def mark_recon_domain_done(self, domain: str, subdomains=None):
        """Record that a recon domain's pipeline finished (Phase 6).

        The domain's discovered ``subdomains`` are persisted so a resume can
        skip the (finding-adding, non-dedup) recon pipeline for this domain yet
        still reconstruct the downstream target set from the checkpoint.
        """
        if not domain:
            return
        with self._lock:
            bucket = self.state.setdefault("completed_recon_domains", [])
            if domain not in bucket:
                bucket.append(domain)
            results = self.state.setdefault("recon_results", {})
            # Only overwrite with a non-empty list; never clobber a good
            # checkpoint with an empty one on a defensive re-call.
            if subdomains is not None and (domain not in results or subdomains):
                results[domain] = list(subdomains)
        self.save_state(force=True)

    def get_completed_recon_domains(self) -> set:
        """Set of recon domains whose pipeline already completed (Phase 6)."""
        return set(self.state.get("completed_recon_domains") or [])

    def get_recon_subdomains(self, domain: str) -> List[str]:
        """Subdomains checkpointed for a completed recon domain (Phase 6)."""
        return list((self.state.get("recon_results") or {}).get(domain, []))
    
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
        # Drop it from the resumable-scan index too (a finished scan is not
        # resumable).
        self._remove_from_index()

    # ------------------------------------------------------------------
    # Resumable-scan index (``.vaktscan/state/index.json``): a small map of
    # ``scan_id -> {primary_target, phase, progress, updated, ...}`` maintained
    # on every save so ``--list-resumable`` can enumerate scans without opening
    # every state file.
    # ------------------------------------------------------------------
    def _index_path(self):
        return os.path.join(self._state_dir, "index.json")

    def _index_key(self):
        # Track by the actual on-disk file stem so a collision fork (<id>-1)
        # gets its own index row instead of overwriting the original.
        return os.path.splitext(os.path.basename(self.state_file))[0]

    def _update_index(self):
        try:
            idx = _read_index_at(self._index_path())
            prog = self.state.get("port_scan_progress", {}) or {}
            idx[self._index_key()] = {
                "scan_id": self._index_key(),
                "primary_target": self.primary_target,
                "phase": self.state.get("phase"),
                "completed": self.state.get("completed", False),
                "completed_combinations": prog.get("completed_combinations", 0),
                "total_combinations": self.state.get("total_combinations", 0),
                "vulnerabilities": len(self.state.get("vulnerabilities", [])),
                "updated": self.state.get("last_updated", time.time()),
                "start_time": self.state.get("start_time"),
                "state_file": self.state_file,
            }
            _write_index_at(self._index_path(), idx)
        except Exception:
            pass  # index is best-effort; never let it break a scan

    def _remove_from_index(self):
        try:
            idx = _read_index_at(self._index_path())
            if self._index_key() in idx:
                del idx[self._index_key()]
                _write_index_at(self._index_path(), idx)
        except Exception:
            pass
    
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


# ---------------------------------------------------------------------------
# Module-level state-index helpers (used by ``--list-resumable`` and by the
# per-instance index maintenance above). Kept free of any instance so the CLI
# can enumerate resumable scans without constructing a ScanStateManager.
# ---------------------------------------------------------------------------
def get_state_dir() -> str:
    """The directory state files + ``index.json`` live in (``VAKT_STATE_DIR``
    override, else ``./.vaktscan/state``)."""
    return os.environ.get("VAKT_STATE_DIR") or os.path.join(".vaktscan", "state")


def _read_index_at(path: str) -> Dict[str, Any]:
    try:
        with open(path, 'r') as f:
            idx = json.load(f)
        return idx if isinstance(idx, dict) else {}
    except Exception:
        return {}


def _write_index_at(path: str, idx: Dict[str, Any]):
    tmp = f"{path}.tmp"
    with open(tmp, 'w') as f:
        json.dump(idx, f, indent=2)
    os.rename(tmp, path)  # atomic, stays inside the state dir


def read_index() -> Dict[str, Any]:
    """The raw resumable-scan index map (``scan_id -> entry``)."""
    return _read_index_at(os.path.join(get_state_dir(), "index.json"))


def _format_age(seconds: float) -> str:
    seconds = max(0, int(seconds))
    if seconds < 60:
        return f"{seconds}s"
    if seconds < 3600:
        return f"{seconds // 60}m"
    if seconds < 86400:
        return f"{seconds // 3600}h"
    return f"{seconds // 86400}d"


def list_resumable() -> List[Dict[str, Any]]:
    """Return non-completed, still-present resumable scans (newest first).

    Entries whose state file no longer exists (cleaned up) or that are marked
    completed are skipped - only genuinely resumable scans are returned.
    """
    idx = read_index()
    now = time.time()
    rows = []
    for key, entry in idx.items():
        if not isinstance(entry, dict) or entry.get("completed"):
            continue
        state_file = entry.get("state_file") or os.path.join(get_state_dir(), f"{key}.json")
        if not os.path.exists(state_file):
            continue
        updated = entry.get("updated") or now
        rows.append({
            "scan_id": entry.get("scan_id", key),
            "primary_target": entry.get("primary_target", ""),
            "phase": entry.get("phase", ""),
            "completed_combinations": entry.get("completed_combinations", 0),
            "total_combinations": entry.get("total_combinations", 0),
            "vulnerabilities": entry.get("vulnerabilities", 0),
            "updated": updated,
            "age": _format_age(now - updated),
        })
    rows.sort(key=lambda r: r.get("updated") or 0, reverse=True)
    return rows


def format_resumable_table() -> str:
    """Human-readable table of resumable scans for ``--list-resumable``."""
    rows = list_resumable()
    if not rows:
        return "[*] No resumable scans found."

    def _prog(r):
        total, done = r["total_combinations"], r["completed_combinations"]
        return f"{done:,}/{total:,}" if total else str(done)

    header = ["SCAN_ID", "TARGET", "PHASE", "PROGRESS", "AGE"]
    body = [[r["scan_id"], str(r["primary_target"]), str(r["phase"]), _prog(r), r["age"]]
            for r in rows]
    widths = [max(len(header[i]), *(len(row[i]) for row in body)) for i in range(len(header))]
    line_fmt = "  ".join("{:<%d}" % w for w in widths)
    out = [f"[*] Resumable scans ({len(rows)}):", line_fmt.format(*header)]
    out += [line_fmt.format(*row) for row in body]
    return "\n".join(out)