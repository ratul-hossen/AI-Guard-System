import os
import subprocess
from typing import Sequence, List, Dict, Any


def parse_bind(spec: str) -> List[str]:
    """Parse 'src[:dest[:ro|rw]]' into bwrap binding arguments."""
    parts = spec.split(":")
    src = os.path.abspath(os.path.expanduser(parts[0]))
    if not os.path.exists(src):
        return []
        
    dest = parts[1] if len(parts) > 1 and parts[1].strip() else src
    dest = os.path.expanduser(dest)
    mode = parts[2].lower() if len(parts) > 2 and parts[2].strip() else "ro"
    
    flag = "--bind" if mode == "rw" else "--ro-bind"
    return [flag, src, dest]


def build_bwrap_cmd(mountpoint: str, agent_cmd: Sequence[str], cfg: Dict[str, Any]) -> List[str]:
    """Constructs the bwrap command array ensuring process isolation and environment hygiene."""
    sb = cfg.get("sandbox", {})
    mountpoint = os.path.abspath(os.path.expanduser(mountpoint))

    args = [
        "bwrap",
        "--unshare-pid",
        "--die-with-parent",
        "--clearenv",
        "--ro-bind", "/usr", "/usr",
        "--symlink", "usr/bin", "/bin",
        "--symlink", "usr/lib", "/lib",
        "--symlink", "usr/lib64", "/lib64",
        "--ro-bind", "/etc", "/etc",
        "--proc", "/proc",
        "--dev", "/dev",
        "--tmpfs", "/tmp",
        "--tmpfs", "/home/sandbox",
        "--setenv", "HOME", "/home/sandbox",
        "--bind", mountpoint, "/workspace",
        "--chdir", "/workspace",
    ]

    # Cleaned environment variables
    env_allow = sb.get("env_allow", ["PATH", "TERM", "LANG"])
    for var in env_allow:
        if var in os.environ:
            args += ["--setenv", var, os.environ[var]]
        elif var == "PATH":
            args += ["--setenv", "PATH", "/usr/local/bin:/usr/bin:/bin"]

    # Explicit mounts / binds
    for spec in sb.get("binds", []):
        parsed = parse_bind(spec)
        if parsed:
            args.extend(parsed)

    # Agent command to execute in sandbox
    return args + list(agent_cmd)


def run(mountpoint: str, agent_cmd: Sequence[str], cfg: Dict[str, Any]) -> int:
    """Executes the sandboxed command."""
    cmd = build_bwrap_cmd(mountpoint, agent_cmd, cfg)
    return subprocess.call(cmd)
