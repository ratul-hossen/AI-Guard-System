import fnmatch
from typing import Iterable, List


class Rules:
    """Evaluates deny patterns against relative filesystem paths.
    
    Supports:
    - Base filename patterns (e.g., '.env', '*.pem', '*.pdf') at any depth.
    - Path-specific patterns (e.g., 'config/keys.json').
    - Directory patterns (e.g., 'secrets', 'secrets/'), blocking the directory and all descendants.
    """

    def __init__(self, deny_patterns: Iterable[str]):
        self.deny: List[str] = [self._norm(p) for p in deny_patterns if p and str(p).strip()]

    @staticmethod
    def _norm(pattern: str) -> str:
        pattern = pattern.strip().lstrip("/")
        pattern = pattern.rstrip("/")
        if pattern.endswith("/**"):
            pattern = pattern[:-3]
        return pattern

    def is_denied(self, rel_path: str) -> bool:
        """rel_path is relative to the project root.
        A path is denied if it, or any of its parent directories, matches a pattern.
        """
        rel = rel_path.strip("/")
        if not rel or rel == ".":
            return False

        parts = rel.split("/")
        for i in range(1, len(parts) + 1):
            prefix = "/".join(parts[:i])
            name = parts[i - 1]
            for pattern in self.deny:
                if "/" in pattern:
                    if fnmatch.fnmatch(prefix, pattern):
                        return True
                else:
                    if fnmatch.fnmatch(name, pattern) or fnmatch.fnmatch(prefix, pattern):
                        return True
        return False
