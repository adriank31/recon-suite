# utils/runner.py

import subprocess
import threading
from utils.logger import log

class ReconTask:
    def __init__(self, name, command, timeout=120):
        self.name = name
        self.command = command
        self.timeout = timeout
        self.output = None
        self.error = None
        self.success = False

    def run(self):
        log(f"[RUNNER] Starting task: {self.name}")
        try:
            result = subprocess.run(
                self.command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=self.timeout
            )
            self.output = result.stdout
            self.error = result.stderr
            self.success = result.returncode == 0
            log(f"[RUNNER] Finished: {self.name} | Success: {self.success}")
        except subprocess.TimeoutExpired:
            self.error = "Task timed out"
            self.success = False
            log(f"[RUNNER] Timeout: {self.name}", level="WARN")
        except Exception as e:
            self.error = str(e)
            self.success = False
            log(f"[RUNNER] Exception in task {self.name}: {e}", level="ERROR")


def run_parallel(tasks, max_threads=4):
    log("[RUNNER] Running tasks in parallel mode")
    threads = []
    for task in tasks:
        thread = threading.Thread(target=task.run)
        threads.append(thread)
        thread.start()
        if len(threads) >= max_threads:
            for t in threads:
                t.join()
            threads.clear()
    for t in threads:
        t.join()
    log("[RUNNER] Parallel task execution complete")