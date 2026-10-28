import errno
import os
import sys
from typing import Dict, Any, Generator, Tuple

from fuse import FUSE, FuseOSError, Operations, fuse_get_context

from aiguard.config import load_config
from aiguard.logger import AccessLog
from aiguard.rules import Rules

STAT_KEYS = (
    "st_atime", "st_ctime", "st_gid", "st_mode",
    "st_mtime", "st_nlink", "st_size", "st_uid"
)
STATVFS_KEYS = (
    "f_bavail", "f_bfree", "f_blocks", "f_bsize", "f_favail",
    "f_ffree", "f_files", "f_flag", "f_frsize", "f_namemax"
)


class GuardFS(Operations):
    """Filesystem-in-Userspace (FUSE) driver that enforces selective path invisibility,
    blocks forbidden file access, and logs data access metadata.
    """

    def __init__(self, root: str, rules: Rules, log: AccessLog, mode: str = "enforce"):
        self.root = os.path.realpath(root)
        self.rules = rules
        self.log = log
        self.mode = mode  # 'enforce' or 'audit'

    # ---------- Internal Helpers ----------
    def _real(self, path: str) -> str:
        """Resolve a relative fuse path into the real underlying filesystem path."""
        rel = path.lstrip("/")
        return os.path.join(self.root, rel)

    def _who(self) -> Tuple[int, str]:
        """Obtain PID and process comm for the calling process."""
        try:
            _, _, pid = fuse_get_context()
        except Exception:
            pid = 0
        proc = "?"
        if pid > 0:
            try:
                with open(f"/proc/{pid}/comm", "r", encoding="utf-8") as f:
                    proc = f.read().strip()
            except OSError:
                proc = "?"
        return pid, proc

    def _record(self, op: str, path: str, nbytes: int, decision: str) -> None:
        """Write metadata event to AccessLog."""
        pid, proc = self._who()
        self.log.write(
            op=op,
            path=path,
            bytes=nbytes,
            pid=pid,
            proc=proc,
            decision=decision,
            mode=self.mode
        )

    def _violates(self, path: str, resolve: bool) -> bool:
        """Check if path violates deny rules or resolves to forbidden / outside targets."""
        rel_norm = path.strip("/")
        if self.rules.is_denied(rel_norm):
            return True

        if resolve:
            # Check target of symlinks
            real = os.path.realpath(self._real(path))
            try:
                rel = os.path.relpath(real, self.root)
            except ValueError:
                # Different drive or invalid path
                return True

            # If it points outside root (e.g. /etc/passwd or ~/.ssh)
            if rel == ".." or rel.startswith("../"):
                return True

            # If destination is a denied path within root
            if rel != "." and self.rules.is_denied(rel):
                return True

        return False

    def _guard(self, op: str, path: str, resolve: bool = True) -> None:
        """Enforces guard decision. In enforce mode: raises ENOENT. In audit mode: logs would_block."""
        if not self._violates(path, resolve):
            return

        if self.mode == "audit":
            self._record(op, path, 0, "would_block")
            return

        self._record(op, path, 0, "blocked")
        # Return ENOENT ("No such file or directory") to hide existence
        raise FuseOSError(errno.ENOENT)

    # ---------- Reading & Browsing ----------
    def getattr(self, path: str, fh: Any = None) -> Dict[str, Any]:
        self._guard("getattr", path, resolve=False)
        real_path = self._real(path)
        try:
            st = os.lstat(real_path)
            return {k: getattr(st, k) for k in STAT_KEYS}
        except FileNotFoundError:
            raise FuseOSError(errno.ENOENT)

    def readdir(self, path: str, fh: Any) -> Generator[str, None, None]:
        self._guard("readdir", path, resolve=True)
        yield "."
        yield ".."
        real_path = self._real(path)
        try:
            entries = os.listdir(real_path)
        except OSError as e:
            raise FuseOSError(e.errno)

        for name in sorted(entries):
            child = (path.rstrip("/") + "/" + name).lstrip("/")
            if self.mode == "audit" or not self.rules.is_denied(child):
                # Denied files are hidden completely from directory listings
                yield name

    def readlink(self, path: str) -> str:
        self._guard("readlink", path, resolve=False)
        real_path = self._real(path)
        try:
            return os.readlink(real_path)
        except OSError as e:
            raise FuseOSError(e.errno)

    def open(self, path: str, flags: int) -> int:
        self._guard("open", path, resolve=True)
        real_path = self._real(path)
        try:
            return os.open(real_path, flags)
        except OSError as e:
            raise FuseOSError(e.errno)

    def read(self, path: str, size: int, offset: int, fh: int) -> bytes:
        try:
            os.lseek(fh, offset, os.SEEK_SET)
            data = os.read(fh, size)
            self._record("read", path, len(data), "allowed")
            return data
        except OSError as e:
            raise FuseOSError(e.errno)

    def release(self, path: str, fh: int) -> None:
        try:
            os.close(fh)
        except OSError:
            pass

    def statfs(self, path: str) -> Dict[str, Any]:
        real_path = self._real(path)
        try:
            st = os.statvfs(real_path)
            return {k: getattr(st, k) for k in STATVFS_KEYS}
        except OSError as e:
            raise FuseOSError(e.errno)

    # ---------- Writing & Modifications ----------
    def create(self, path: str, mode: int, fi: Any = None) -> int:
        self._guard("create", path, resolve=False)
        real_path = self._real(path)
        try:
            return os.open(real_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
        except OSError as e:
            raise FuseOSError(e.errno)

    def write(self, path: str, data: bytes, offset: int, fh: int) -> int:
        try:
            os.lseek(fh, offset, os.SEEK_SET)
            written = os.write(fh, data)
            self._record("write", path, written, "allowed")
            return written
        except OSError as e:
            raise FuseOSError(e.errno)

    def truncate(self, path: str, length: int, fh: Any = None) -> None:
        self._guard("truncate", path, resolve=True)
        real_path = self._real(path)
        try:
            with open(real_path, "r+b") as f:
                f.truncate(length)
        except OSError as e:
            raise FuseOSError(e.errno)

    def unlink(self, path: str) -> None:
        self._guard("unlink", path, resolve=False)
        real_path = self._real(path)
        try:
            os.unlink(real_path)
        except OSError as e:
            raise FuseOSError(e.errno)

    def mkdir(self, path: str, mode: int) -> None:
        self._guard("mkdir", path, resolve=False)
        real_path = self._real(path)
        try:
            os.mkdir(real_path, mode)
        except OSError as e:
            raise FuseOSError(e.errno)

    def rmdir(self, path: str) -> None:
        self._guard("rmdir", path, resolve=False)
        real_path = self._real(path)
        try:
            os.rmdir(real_path)
        except OSError as e:
            raise FuseOSError(e.errno)

    def rename(self, old: str, new: str) -> None:
        self._guard("rename", old, resolve=False)
        self._guard("rename", new, resolve=False)
        try:
            os.rename(self._real(old), self._real(new))
        except OSError as e:
            raise FuseOSError(e.errno)

    def symlink(self, name: str, target: str) -> None:
        self._guard("symlink", name, resolve=False)
        try:
            os.symlink(target, self._real(name))
        except OSError as e:
            raise FuseOSError(e.errno)

    def link(self, target: str, source: str) -> None:
        """Creates a hard link: guards BOTH target and source, preventing hard links to denied files."""
        self._guard("link", source, resolve=True)
        self._guard("link", target, resolve=False)
        try:
            os.link(self._real(source), self._real(target))
        except OSError as e:
            raise FuseOSError(e.errno)

    def chmod(self, path: str, mode: int) -> None:
        self._guard("chmod", path, resolve=False)
        try:
            os.chmod(self._real(path), mode)
        except OSError as e:
            raise FuseOSError(e.errno)

    def chown(self, path: str, uid: int, gid: int) -> None:
        self._guard("chown", path, resolve=False)
        try:
            os.chown(self._real(path), uid, gid)
        except OSError as e:
            raise FuseOSError(e.errno)

    def utimens(self, path: str, times: Any = None) -> None:
        self._guard("utimens", path, resolve=False)
        try:
            os.utime(self._real(path), times)
        except OSError as e:
            raise FuseOSError(e.errno)

    def fsync(self, path: str, fdatasync: int, fh: int) -> None:
        try:
            if fdatasync != 0:
                os.fdatasync(fh)
            else:
                os.fsync(fh)
        except OSError as e:
            raise FuseOSError(e.errno)


def start_guardfs(config_path: str, session: str) -> None:
    cfg = load_config(config_path)
    os.makedirs(cfg["mountpoint"], exist_ok=True)
    os.makedirs(os.path.dirname(cfg["log"]), exist_ok=True)

    rules = Rules(cfg["deny"])
    log = AccessLog(cfg["log"], session)
    fs = GuardFS(cfg["root"], rules, log, cfg["mode"])

    fuse_kwargs = {
        "foreground": True,
        "nothreads": False,
        "direct_io": True,
        "attr_timeout": 0,
        "entry_timeout": 0,
    }

    try:
        FUSE(fs, cfg["mountpoint"], **fuse_kwargs)
    finally:
        log.close()


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python -m aiguard.guardfs <config_path> <session_id>", file=sys.stderr)
        sys.exit(1)
    start_guardfs(sys.argv[1], sys.argv[2])
