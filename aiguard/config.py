import os
from typing import Any, Dict
import yaml

PATH_KEYS = ("root", "mountpoint", "log")


def load_config(path: str = "aiguard.yml") -> Dict[str, Any]:
    """Load, validate, and normalize configuration, supporting zero-config automatic defaults."""
    if os.path.isfile(path):
        with open(path, encoding="utf-8") as f:
            cfg = yaml.safe_load(f)

        if not isinstance(cfg, dict):
            raise ValueError("Configuration file must define a YAML mapping/dictionary.")

        for key in PATH_KEYS:
            if key not in cfg:
                raise KeyError(f"Missing required configuration key: '{key}'")
            cfg[key] = os.path.abspath(os.path.expanduser(str(cfg[key])))
    else:
        # Zero-config automatic fallback for arbitrary project directories
        target_dir = os.path.dirname(os.path.abspath(path))
        if os.path.isdir(target_dir) and target_dir != "/" and os.path.basename(path) in ("aiguard.yml", "nonexistent.yml", ""):
            root = target_dir
        else:
            root = os.path.abspath(os.getcwd())
        proj_name = os.path.basename(root) or "default_project"
        cfg = {
            "root": root,
            "mountpoint": os.path.abspath(os.path.expanduser(f"~/.aiguard/mnt/{proj_name}")),
            "log": os.path.abspath(os.path.expanduser("~/.aiguard/logs/access.jsonl")),
            "mode": "enforce",
            "deny": [],
            "sandbox": {}
        }


    cfg.setdefault("mode", "enforce")
    cfg.setdefault("deny", [])
    cfg.setdefault("sandbox", {})

    if cfg["mode"] not in ("enforce", "audit"):
        raise ValueError(f"mode must be 'enforce' or 'audit', got: '{cfg['mode']}'")

    if not isinstance(cfg["deny"], list):
        raise ValueError("`deny` must be a list of glob patterns.")

    # Seamlessly merge rules from .aiguardignore or .guardignore if present in project root
    for ignore_name in [".aiguardignore", ".guardignore"]:
        ignore_path = os.path.join(cfg["root"], ignore_name)
        if os.path.isfile(ignore_path):
            with open(ignore_path, "r", encoding="utf-8") as f:
                for line in f:
                    stripped = line.strip()
                    if stripped and not stripped.startswith("#"):
                        if stripped not in cfg["deny"]:
                            cfg["deny"].append(stripped)

    return cfg


