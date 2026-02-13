"""Cross-platform file lock helpers using atomic lock-file creation."""

import json
import os
import time
from pathlib import Path


class FileLock:
    """Simple lock based on O_CREAT|O_EXCL with stale lock handling."""

    def __init__(self, lock_path, timeout_seconds=5, stale_seconds=900):
        self.lock_path = str(lock_path)
        self.timeout_seconds = timeout_seconds
        self.stale_seconds = stale_seconds
        self._acquired = False

    def _is_stale(self):
        lock_pid = None
        try:
            with open(self.lock_path, "r", encoding="utf-8") as lock_file:
                payload = json.load(lock_file)
                lock_pid = payload.get("pid")
        except Exception:
            lock_pid = None

        if isinstance(lock_pid, int):
            try:
                os.kill(lock_pid, 0)
            except OSError:
                return True

        try:
            stat = os.stat(self.lock_path)
        except FileNotFoundError:
            return False
        age = time.time() - stat.st_mtime
        return age > self.stale_seconds

    def _try_remove_stale(self):
        if self._is_stale():
            try:
                os.remove(self.lock_path)
            except FileNotFoundError:
                return

    def acquire(self):
        Path(self.lock_path).parent.mkdir(exist_ok=True)
        start = time.time()
        while True:
            self._try_remove_stale()
            try:
                fd = os.open(self.lock_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
                payload = {
                    "pid": os.getpid(),
                    "acquired_at_epoch": time.time(),
                }
                with os.fdopen(fd, "w", encoding="utf-8") as lock_file:
                    json.dump(payload, lock_file)
                self._acquired = True
                return True
            except FileExistsError:
                if time.time() - start >= self.timeout_seconds:
                    return False
                time.sleep(0.1)

    def release(self):
        if not self._acquired:
            return
        try:
            os.remove(self.lock_path)
        except FileNotFoundError:
            pass
        finally:
            self._acquired = False

    def __enter__(self):
        if not self.acquire():
            raise TimeoutError(f"Could not acquire lock: {self.lock_path}")
        return self

    def __exit__(self, exc_type, exc, tb):
        self.release()
