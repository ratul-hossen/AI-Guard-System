import json
import os
import threading
import time
from typing import Any


class AccessLog:
    """Thread-safe JSONL access logger for AI Guard.
    
    Strictly follows NFR1: records metadata only (path, bytes, pid, proc, decision, mode, ts).
    Never logs file contents, prompts, or sensitive payloads.
    Enforces mode 0600 on log files.
    """

    def __init__(self, path: str, session: str):
        self.path = os.path.abspath(os.path.expanduser(path))
        os.makedirs(os.path.dirname(self.path), exist_ok=True)
        
        # Enforce file permission 0600
        fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        # Ensure mode 0600 even if file already existed with different perms
        try:
            os.chmod(self.path, 0o600)
        except OSError:
            pass
            
        self._file = os.fdopen(fd, "a", buffering=1, encoding="utf-8")
        self._lock = threading.Lock()
        self.session = session

    def write(self, **event: Any) -> None:
        """Writes an event dictionary to the JSONL log file with timestamp and session id."""
        event["ts"] = time.time()
        event["session"] = self.session
        # Sanity check: forbid keys that could accidentally leak contents
        for forbidden in ("content", "contents", "data", "prompt", "payload"):
            event.pop(forbidden, None)
            
        line = json.dumps(event, ensure_ascii=False)
        with self._lock:
            self._file.write(line + "\n")
            self._file.flush()

    def close(self) -> None:
        with self._lock:
            if not self._file.closed:
                self._file.flush()
                self._file.close()
