"""AI Guard Smart Secret Scanner and .guardignore Manager.

Automatically discovers sensitive files and folders in a target repository,
and provides seamless .guardignore file management for developers.
"""

import os
import fnmatch
from typing import List, Dict, Tuple, Set, Optional, Any

# Known sensitive folder names that should be blocked entirely
SENSITIVE_DIRECTORY_PATTERNS = [
    "secrets",
    "secret",
    "private",
    ".ssh",
    ".aws",
    ".azure",
    ".gcp",
    "credentials",
    "certificates",
    "certs",
]

# Sensitive file glob patterns with security category labels
SENSITIVE_FILE_PATTERNS = [
    (".env*", "Environment secret file"),
    ("*.pem", "Cryptographic private key or certificate"),
    ("*.key", "Private cryptographic key"),
    ("id_rsa*", "SSH private key"),
    ("id_ed25519*", "SSH private key"),
    ("id_ecdsa*", "SSH private key"),
    ("*.pfx", "PKCS#12 certificate bundle"),
    ("*.p12", "PKCS#12 certificate bundle"),
    ("*token*", "API token or secret token file"),
    ("*secret*", "Confidential or secret configuration"),
    ("credentials.json", "Cloud or service account credentials"),
    ("service-account*.json", "Google Cloud service account key"),
    ("client_secret*.json", "OAuth client secret file"),
    ("*.pdf", "Document (potentially confidential)"),
    ("*.docx", "Word document (potentially confidential)"),
]

# Standard directories to skip during scanning to avoid wasted traversals
IGNORE_SCAN_DIRS = {
    ".git",
    "__pycache__",
    ".pytest_cache",
    ".venv",
    "node_modules",
    ".idea",
    ".vscode",
}


def scan_project(root_dir: str) -> List[Dict[str, str]]:
    """Recursively scans a project directory and detects sensitive files and folders.
    
    Returns a list of dicts:
        {"path": relative_path, "type": "file" | "folder", "reason": description}
    """
    root_dir = os.path.abspath(root_dir)
    findings: List[Dict[str, str]] = []
    seen_paths: Set[str] = set()

    for dirpath, dirnames, filenames in os.walk(root_dir):
        # Prune unwanted directories
        dirnames[:] = [d for d in dirnames if d not in IGNORE_SCAN_DIRS]

        rel_dir = os.path.relpath(dirpath, root_dir)
        if rel_dir == ".":
            rel_dir = ""

        # 1. Check for sensitive directories
        for d in list(dirnames):
            rel_path = os.path.join(rel_dir, d).replace("\\", "/")
            d_lower = d.lower()
            matched_reason = None

            for pattern in SENSITIVE_DIRECTORY_PATTERNS:
                if fnmatch.fnmatch(d_lower, pattern):
                    matched_reason = f"Sensitive directory ('{pattern}')"
                    break

            if matched_reason and rel_path not in seen_paths:
                seen_paths.add(rel_path)
                findings.append({
                    "path": rel_path + "/",
                    "type": "folder",
                    "reason": matched_reason
                })

        # 2. Check for sensitive files
        for f in filenames:
            rel_path = os.path.join(rel_dir, f).replace("\\", "/")
            f_lower = f.lower()
            matched_reason = None

            for pattern, reason in SENSITIVE_FILE_PATTERNS:
                if fnmatch.fnmatch(f_lower, pattern.lower()):
                    matched_reason = reason
                    break

            if matched_reason and rel_path not in seen_paths:
                seen_paths.add(rel_path)
                findings.append({
                    "path": rel_path,
                    "type": "file",
                    "reason": matched_reason
                })

    # Sort findings for predictable display (folders first, then alphabetically)
    findings.sort(key=lambda x: (0 if x["type"] == "folder" else 1, x["path"]))
    return findings


def get_guardignore_path(project_root: str) -> str:
    """Returns the absolute path to .aiguardignore (or fallback .guardignore) in project root."""
    root = os.path.abspath(project_root)
    p_primary = os.path.join(root, ".aiguardignore")
    p_fallback = os.path.join(root, ".guardignore")
    if os.path.isfile(p_primary):
        return p_primary
    if os.path.isfile(p_fallback):
        return p_fallback
    return p_primary


def init_project(project_root: str) -> Tuple[str, str, List[Dict[str, str]]]:
    """Initializes AI Guard in any project folder without cluttering it.
    
    Creates:
      1. .aiguardignore (populated with detected secrets/sensitive folders)
      2. aiguard-log.sh (live real-time log streaming script)
    
    Returns:
      (guardignore_path, log_script_path, detected_findings)
    """
    root = os.path.abspath(project_root)
    findings = scan_project(root)

    # Determine recommended patterns
    recommended = []
    for f in findings:
        recommended.append(f["path"])

    # If no findings, include default standard protections
    if not recommended:
        recommended = [".env", ".env.*", "*.pem", "secrets/", "*.key", "id_rsa*"]

    ignore_path = write_guardignore(root, sorted(list(set(recommended))))

    # Create aiguard-log.sh
    log_script_path = os.path.join(root, "aiguard-log.sh")
    with open(log_script_path, "w", encoding="utf-8") as f:
        f.write("""#!/usr/bin/env bash
# AI Guard Real-Time Log Viewer for this project
# Run this in a separate terminal to watch file reads & blocks live!

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
echo "=========================================================="
echo " AI Guard Live Access Telemetry Monitor"
echo " Target Project: $DIR"
echo " Watching real-time agent file reads & blocked attempts..."
echo " Press Ctrl+C to stop watching."
echo "=========================================================="
aiguard logs -f
""")
    # Make executable (chmod +x)
    os.chmod(log_script_path, 0o755)

    # Ensure AI Guard files are never pushed to git
    update_gitignore_for_aiguard(root)

    return ignore_path, log_script_path, findings


def update_gitignore_for_aiguard(project_root: str) -> bool:
    """Ensures .gitignore in project_root ignores AI Guard telemetry, rules, and runtime files."""
    gitignore_path = os.path.join(project_root, ".gitignore")
    entries_to_add = [
        ".aiguard/",
        ".aiguardignore",
        "aiguard-log.sh",
        "*.jsonl",
        "access.json",
    ]

    existing_content = ""
    if os.path.isfile(gitignore_path):
        with open(gitignore_path, "r", encoding="utf-8", errors="ignore") as f:
            existing_content = f.read()

    lines = [line.strip() for line in existing_content.splitlines()]
    missing = [e for e in entries_to_add if e not in lines]

    if missing:
        with open(gitignore_path, "a", encoding="utf-8") as f:
            if existing_content and not existing_content.endswith("\n"):
                f.write("\n")
            f.write("\n# AI Guard runtime, rules, and access telemetry\n")
            for m in missing:
                f.write(f"{m}\n")
        return True
    return False


def deinit_project(project_root: str) -> List[str]:
    """Removes AI Guard configuration files from a project folder."""
    root = os.path.abspath(project_root)
    removed = []
    for fname in [".aiguardignore", ".guardignore", "aiguard-log.sh"]:
        p = os.path.join(root, fname)
        if os.path.exists(p):
            os.remove(p)
            removed.append(fname)
    return removed


def setup_shell_aliases(target_rc: Optional[str] = None, agents: Optional[List[str]] = None) -> Dict[str, Any]:
    """Configures transparent agent aliases in user's shell rc file (~/.bashrc, ~/.zshrc).
    
    Allows developers to execute agents normally (e.g. `claude`) while
    AI Guard transparently executes them inside the protected Bubblewrap sandbox.
    """
    if agents is None:
        agents = ["claude", "cursor-agent"]

    candidates = [target_rc] if target_rc else [
        os.path.expanduser("~/.bashrc"),
        os.path.expanduser("~/.zshrc"),
    ]

    target_files = [f for f in candidates if f and os.path.exists(f)]
    if not target_files:
        target_files = [os.path.expanduser("~/.bashrc")]

    added_files = []
    aliases_added = []

    for rc_path in target_files:
        content = ""
        if os.path.exists(rc_path):
            with open(rc_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()

        lines_to_add = []
        for agent in agents:
            alias_pattern = f"alias {agent}="
            if alias_pattern not in content:
                lines_to_add.append(f"alias {agent}='aiguard run -- {agent}'")
                if agent not in aliases_added:
                    aliases_added.append(agent)

        if lines_to_add:
            with open(rc_path, "a", encoding="utf-8") as f:
                f.write("\n# >>> AI Guard Transparent Agent Aliases >>>\n")
                for line in lines_to_add:
                    f.write(f"{line}\n")
                f.write("# <<< AI Guard Transparent Agent Aliases <<<\n")
            if rc_path not in added_files:
                added_files.append(rc_path)

    return {
        "configured": bool(aliases_added),
        "files": added_files,
        "agents": aliases_added,
    }


def remove_shell_aliases(target_rc: Optional[str] = None) -> List[str]:
    """Removes AI Guard transparent alias blocks from shell rc files."""
    candidates = [target_rc] if target_rc else [
        os.path.expanduser("~/.bashrc"),
        os.path.expanduser("~/.zshrc"),
    ]
    cleaned = []
    for rc_path in candidates:
        if rc_path and os.path.exists(rc_path):
            with open(rc_path, "r", encoding="utf-8", errors="ignore") as f:
                lines = f.readlines()
            new_lines = []
            in_block = False
            modified = False
            for line in lines:
                if "# >>> AI Guard Transparent Agent Aliases >>>" in line:
                    in_block = True
                    modified = True
                    continue
                if "# <<< AI Guard Transparent Agent Aliases <<<" in line:
                    in_block = False
                    modified = True
                    continue
                if not in_block:
                    new_lines.append(line)
            if modified:
                with open(rc_path, "w", encoding="utf-8") as f:
                    f.writelines(new_lines)
                cleaned.append(rc_path)
    return cleaned


def read_guardignore(project_root: str) -> List[str]:
    """Reads rules from .guardignore, ignoring blank lines and comments."""
    path = get_guardignore_path(project_root)
    if not os.path.isfile(path):
        return []

    rules: List[str] = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):
                rules.append(line)
    return rules


def write_guardignore(project_root: str, patterns: List[str], header: bool = True) -> str:
    """Writes rules to .guardignore with clear developer instructions."""
    path = get_guardignore_path(project_root)
    with open(path, "w", encoding="utf-8") as f:
        if header:
            f.write("# ====================================================================\n")
            f.write("# AI Guard - Protected File & Folder Rules (.guardignore)\n")
            f.write("# ====================================================================\n")
            f.write("# Files and folders listed here are completely invisible (ENOENT) to\n")
            f.write("# autonomous coding agents (Claude Code, Cursor, terminal agents).\n")
            f.write("#\n")
            f.write("# - To ALLOW an AI agent to read a file/folder: Remove its line below.\n")
            f.write("# - To HIDE a file/folder: Add its path or glob pattern (e.g. docs/secret.pdf).\n")
            f.write("# - To HIDE an entire directory: Add the folder name with a slash (e.g. secrets/).\n")
            f.write("# ====================================================================\n\n")

        for p in patterns:
            p = p.strip()
            if p:
                f.write(f"{p}\n")
    return path


def add_to_guardignore(project_root: str, pattern: str) -> bool:
    """Adds a single pattern or file/folder to .guardignore if not already present."""
    pattern = pattern.strip()
    if not pattern:
        return False

    current_rules = read_guardignore(project_root)
    # Check if already present
    norm_pattern = pattern.rstrip("/")
    for r in current_rules:
        if r.rstrip("/") == norm_pattern:
            return False  # Already exists

    path = get_guardignore_path(project_root)
    # Append to file
    file_exists = os.path.isfile(path)
    with open(path, "a", encoding="utf-8") as f:
        if not file_exists:
            f.write("# AI Guard Protected Rules (.guardignore)\n")
        f.write(f"{pattern}\n")
    return True


def remove_from_guardignore(project_root: str, pattern: str) -> bool:
    """Removes a pattern or file/folder from .guardignore."""
    path = get_guardignore_path(project_root)
    if not os.path.isfile(path):
        return False

    target = pattern.strip().rstrip("/")
    with open(path, "r", encoding="utf-8") as f:
        lines = f.readlines()

    modified = False
    new_lines = []
    for line in lines:
        stripped = line.strip()
        if stripped and not stripped.startswith("#"):
            if stripped.rstrip("/") == target:
                modified = True
                continue
        new_lines.append(line)

    if modified:
        with open(path, "w", encoding="utf-8") as f:
            f.writelines(new_lines)
    return modified
