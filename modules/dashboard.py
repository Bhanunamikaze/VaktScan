import asyncio
import sys
import builtins
import time
import threading
from typing import Dict, Any

class LiveDashboard:
    _instance = None
    _lock = threading.Lock()

    def __new__(cls, *args, **kwargs):
        with cls._lock:
            if not cls._instance:
                cls._instance = super(LiveDashboard, cls).__new__(cls)
                cls._instance._initialized = False
            return cls._instance

    def __init__(self):
        if self._initialized:
            return
        self._initialized = True
        self.tasks: Dict[str, Dict[str, Any]] = {}
        self.active = False
        self.original_print = builtins.print
        self.original_stdout_write = sys.stdout.write
        self.drawn_lines = 0
        self.loop = None
        self.render_task = None
        self.render_interval = 0.1
        self.lock = threading.Lock()

    def start(self):
        with self.lock:
            if self.active:
                return
            self.active = True
            self.drawn_lines = 0
            builtins.print = self._custom_print
            try:
                self.loop = asyncio.get_running_loop()
                self.render_task = asyncio.create_task(self._render_loop())
            except RuntimeError:
                # No event loop running, run in pure fallback mode (sync)
                self.loop = None
                self.render_task = None

    def stop(self):
        with self.lock:
            if not self.active:
                return
            self.active = False
            builtins.print = self.original_print
            if self.render_task and self.loop:
                if self.loop.is_running():
                    self.loop.call_soon_threadsafe(self.render_task.cancel)
            self._clear_dashboard()
            self.original_stdout_write(f"\r")
            sys.stdout.flush()

    def add_task(self, task_id: str, name: str, total: int = None):
        with self.lock:
            self.tasks[task_id] = {
                "name": name,
                "total": total,
                "completed": 0,
                "status": "Starting",
                "progress": 0.0,
                "start_time": time.time()
            }

    def update_task(self, task_id: str, completed: int = None, status: str = None, total: int = None, progress: float = None):
        with self.lock:
            if task_id not in self.tasks:
                return
            task = self.tasks[task_id]
            if completed is not None:
                task["completed"] = completed
            if total is not None:
                task["total"] = total
            if status is not None:
                task["status"] = status
            if progress is not None:
                task["progress"] = progress
            elif task["total"] and task["total"] > 0:
                task["progress"] = min(100.0, (task["completed"] / task["total"]) * 100.0)

    def complete_task(self, task_id: str, status: str = "Completed"):
        self.update_task(task_id, status=status, progress=100.0)

    def remove_task(self, task_id: str):
        with self.lock:
            if task_id in self.tasks:
                del self.tasks[task_id]

    def _custom_print(self, *args, **kwargs):
        sep = kwargs.get('sep', ' ')
        end = kwargs.get('end', '\n')
        message = sep.join(str(arg) for arg in args) + end
        self.log_message(message)

    def log_message(self, message: str):
        with self.lock:
            if not self.active:
                self.original_stdout_write(message)
                return
            self._clear_dashboard()
            self.original_stdout_write(message)
            sys.stdout.flush()
            self._draw_dashboard()

    def _clear_dashboard(self):
        if self.drawn_lines > 0:
            # \033[u restores cursor to the saved position, \033[J clears screen below it
            self.original_stdout_write("\033[u\033[J")
            self.drawn_lines = 0

    def _draw_dashboard(self):
        if not self.active or not self.tasks:
            return
        
        lines = []
        lines.append("\033[90m" + "—"*70 + "\033[0m")
        
        spinners = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏']
        spinner_char = spinners[int(time.time() * 10) % len(spinners)]

        for task_id, task in self.tasks.items():
            name = task["name"]
            progress = task["progress"]
            status = task["status"]
            total = task["total"]
            completed = task["completed"]
            
            if progress >= 100.0:
                bar_length = 20
                bar = '■' * bar_length
                pct_str = "100%"
                indicator = f"[{bar}] {pct_str:>4}"
            elif progress > 0.0:
                bar_length = 20
                filled_length = int(round(bar_length * progress / 100.0))
                bar = '■' * filled_length + '░' * (bar_length - filled_length)
                pct_str = f"{int(progress)}%"
                indicator = f"[{bar}] {pct_str:>4}"
            else:
                indicator = f"[{spinner_char}] Running..."

            line = f" \033[96m* {name:<35}\033[0m {indicator} | {status}"
            lines.append(line)
            
        lines.append("\033[90m" + "—"*70 + "\033[0m")
        
        # Save cursor position (\033[s), write dashboard content with trailing newline, then restore cursor (\033[u)
        dashboard_content = "\033[s" + "\n".join(lines) + "\n" + "\033[u"
        self.original_stdout_write(dashboard_content)
        sys.stdout.flush()
        self.drawn_lines = len(lines)

    async def _render_loop(self):
        try:
            while self.active:
                await asyncio.sleep(self.render_interval)
                with self.lock:
                    self._clear_dashboard()
                    self._draw_dashboard()
        except asyncio.CancelledError:
            pass
