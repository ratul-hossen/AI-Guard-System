import argparse
import os
import shutil
import subprocess
import sys
import time
import uuid

from aiguard.config import load_config
from aiguard.sandbox import run as run_sandbox


def wait_for_mount(mountpoint: str, timeout: float = 10.0) -> bool:
    """Polls until the mountpoint is recognized as an active mount."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        if os.path.ismount(mountpoint):
            return True
        time.sleep(0.1)
    return False


def cmd_run(args: argparse.Namespace) -> int:
    cfg = load_config(args.config)
    
    # Auto-initialize project if neither .aiguardignore nor .guardignore exists and no deny rules
    ignore_1 = os.path.join(cfg["root"], ".aiguardignore")
    ignore_2 = os.path.join(cfg["root"], ".guardignore")
    if not os.path.isfile(ignore_1) and not os.path.isfile(ignore_2) and not cfg["deny"]:
        from aiguard.scanner import init_project
        print(f"[AI Guard] First-time project detected. Auto-initializing protection in: {cfg['root']}")
        init_project(cfg["root"])
        cfg = load_config(args.config)

    cmd = args.agent_cmd
    if cmd and cmd[0] == "--":
        cmd = cmd[1:]
    if not cmd:
        print("Error: No command specified to run.", file=sys.stderr)
        print("Usage: aiguard run [-c aiguard.yml] [--] <agent command>", file=sys.stderr)
        print("Examples:", file=sys.stderr)
        print("  aiguard run -- claude", file=sys.stderr)
        print("  aiguard run cursor-agent", file=sys.stderr)
        print("  aiguard run bash", file=sys.stderr)
        return 2

    session = uuid.uuid4().hex[:8]
    print(f"[AI Guard] Starting session: {session} (mode: {cfg['mode']})")
    print(f"[AI Guard] Project root: {cfg['root']}")
    print(f"[AI Guard] GuardFS mountpoint: {cfg['mountpoint']}")

    # Start GuardFS daemon
    daemon = subprocess.Popen(
        [sys.executable, "-m", "aiguard.guardfs", args.config, session]
    )


    try:
        if not wait_for_mount(cfg["mountpoint"], timeout=10.0):
            print("[AI Guard] ERROR: GuardFS did not mount in time. Run `aiguard doctor`.", file=sys.stderr)
            return 1
        print("[AI Guard] GuardFS mounted successfully. Launching sandboxed process...")
        ret = run_sandbox(cfg["mountpoint"], cmd, cfg)
        print(f"[AI Guard] Agent process exited with code {ret}")
        return ret
    finally:
        print("[AI Guard] Cleaning up and unmounting GuardFS (fail-closed)...")
        # Try graceful unmount
        subprocess.call(["fusermount", "-u", cfg["mountpoint"]], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if daemon.poll() is None:
            daemon.terminate()
            try:
                daemon.wait(timeout=2.0)
            except subprocess.TimeoutExpired:
                daemon.kill()


def cmd_mount(args: argparse.Namespace) -> int:
    cfg = load_config(args.config)
    session = uuid.uuid4().hex[:8]
    print(f"[AI Guard] Mounting GuardFS session {session} at {cfg['mountpoint']}...")
    from aiguard.guardfs import start_guardfs
    try:
        start_guardfs(args.config, session)
        return 0
    except KeyboardInterrupt:
        print("\n[AI Guard] Unmounting GuardFS...")
        subprocess.call(["fusermount", "-u", cfg["mountpoint"]], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return 0


def cmd_unmount(args: argparse.Namespace) -> int:
    cfg = load_config(args.config)
    print(f"[AI Guard] Unmounting {cfg['mountpoint']}...")
    ret = subprocess.call(["fusermount", "-u", cfg["mountpoint"]])
    if ret == 0:
        print("[AI Guard] Successfully unmounted.")
    else:
        print("[AI Guard] Unmount returned code:", ret)
    return ret


def cmd_doctor(_args: argparse.Namespace) -> int:
    checks = {
        "bubblewrap (bwrap) installed": shutil.which("bwrap") is not None,
        "fusermount / fusermount3 installed": (shutil.which("fusermount") or shutil.which("fusermount3")) is not None,
        "/dev/fuse accessible": os.path.exists("/dev/fuse") and os.access("/dev/fuse", os.R_OK | os.W_OK),
    }

    try:
        import fuse  # noqa: F401
        checks["fusepy importable"] = True
    except Exception as e:
        checks[f"fusepy importable ({e})"] = False

    try:
        import yaml  # noqa: F401
        checks["pyyaml importable"] = True
    except Exception as e:
        checks[f"pyyaml importable ({e})"] = False

    print("================ AI GUARD DOCTOR ================")
    all_ok = True
    for name, passed in checks.items():
        status = "\033[92mPASS\033[0m" if passed else "\033[91mFAIL\033[0m"
        print(f"[{status}]  {name}")
        all_ok = all_ok and passed
    print("=================================================")
    return 0 if all_ok else 1


def cmd_audit(_args: argparse.Namespace) -> int:
    from aiguard.auditor import ComplianceAuditor
    auditor = ComplianceAuditor()
    passed = auditor.run_audit()
    return 0 if passed else 1


def cmd_scan(args: argparse.Namespace) -> int:
    from aiguard.scanner import scan_project, read_guardignore
    cfg = load_config(args.config)
    root = cfg["root"]
    print(f"\n[AI Guard] Scanning repository for sensitive assets: {root}")
    findings = scan_project(root)

    current_denied = set(cfg.get("deny", []))
    guardignore_rules = set(read_guardignore(root))
    all_denied = current_denied | guardignore_rules

    if not findings:
        print("  \033[92m[CLEAN]\033[0m No obvious secret files or folders detected in repository.")
        return 0

    print(f"\nDetected {len(findings)} sensitive file(s) and folder(s):")
    print("-" * 75)
    print(f"{'TYPE':<8} {'PATH':<35} {'PROTECTION':<14} {'CATEGORY'}")
    print("-" * 75)

    from aiguard.rules import Rules
    active_rules = Rules(all_denied)

    for item in findings:
        p = item["path"]
        t = item["type"].upper()
        reason = item["reason"]
        is_blocked = active_rules.is_denied(p.rstrip("/"))
        status = "\033[92m[BLOCKED]\033[0m" if is_blocked else "\033[93m[EXPOSED]\033[0m"
        print(f"{t:<8} {p:<35} {status:<23} {reason}")

    print("-" * 75)
    print("Tip: Run `aiguard config` to interactively select which items to hide from AI coding agents.\n")
    return 0


def cmd_config(args: argparse.Namespace) -> int:
    from aiguard.scanner import scan_project, read_guardignore, write_guardignore
    cfg = load_config(args.config)
    root = cfg["root"]

    print(f"\n=======================================================")
    print(f"       AI Guard Protection Configuration Wizard       ")
    print(f"=======================================================")
    print(f"Target Project: {root}")
    print(f"Rule File:      {os.path.join(root, '.guardignore')}\n")

    findings = scan_project(root)
    existing_rules = read_guardignore(root)
    if not existing_rules and "deny" in cfg:
        existing_rules = list(cfg["deny"])

    current_set = set(existing_rules)

    # Show interactive prompt or batch selection
    print("Discovered Sensitive Files & Directories:")
    selections = {}
    for idx, f in enumerate(findings, 1):
        p = f["path"]
        is_active = p in current_set or p.rstrip("/") in current_set or any(p.startswith(r) for r in current_set)
        selections[idx] = (p, f["reason"])
        state = "[X]" if is_active else "[ ]"
        print(f"  {idx:2d}) {state} {p:<30} ({f['reason']})")

    print("\nOptions:")
    print("  - Press [Enter] to accept detected recommendations and protect all discovered items.")
    print("  - Type item numbers separated by commas to toggle protection (e.g., '1, 3').")
    print("  - Type 'all' to protect everything.")
    print("  - Type 'none' to allow AI agents to read everything.")

    try:
        choice = input("\nYour choice: ").strip()
    except (EOFError, KeyboardInterrupt):
        print("\nConfiguration cancelled.")
        return 0

    final_rules = set(current_set)

    if choice.lower() == "all" or choice == "":
        for _, (p, _) in selections.items():
            final_rules.add(p)
    elif choice.lower() == "none":
        final_rules.clear()
    else:
        # Toggle specified indices
        for part in choice.split(","):
            part = part.strip()
            if part.isdigit() and int(part) in selections:
                idx = int(part)
                path_item = selections[idx][0]
                if path_item in final_rules:
                    final_rules.remove(path_item)
                    print(f"  [-] Removed: {path_item} (AI agents CAN now read this)")
                else:
                    final_rules.add(path_item)
                    print(f"  [+] Added:   {path_item} (AI agents BLOCKED from this)")

    # Save to .guardignore
    saved_path = write_guardignore(root, sorted(list(final_rules)))
    print(f"\n\033[92m[SUCCESS]\033[0m Protection rules saved to: {saved_path}")
    print("These rules will be enforced on all AI coding agents (Claude Code, Cursor, terminal agents).\n")
    return 0


def cmd_add(args: argparse.Namespace) -> int:
    from aiguard.scanner import add_to_guardignore
    cfg = load_config(args.config)
    root = cfg["root"]
    target = args.path

    if not target:
        # Interactive prompt with Tab auto-completion
        try:
            import readline

            def complete_path(text: str, state: int):
                # Auto-complete files and directories relative to root
                search_dir = os.path.dirname(text)
                base_dir = os.path.join(root, search_dir) if search_dir else root
                prefix = os.path.basename(text)

                try:
                    entries = os.listdir(base_dir)
                except OSError:
                    return None

                matches = []
                for e in entries:
                    if e.startswith(prefix):
                        rel = os.path.join(search_dir, e) if search_dir else e
                        full = os.path.join(root, rel)
                        if os.path.isdir(full):
                            rel += "/"
                        matches.append(rel)

                matches.sort()
                return matches[state] if state < len(matches) else None

            readline.set_completer_delims(" \t\n\"'")
            readline.parse_and_bind("tab: complete")
            readline.set_completer(complete_path)

            print(f"[AI Guard] Add file or folder to hide from AI coding agents (Press <TAB> to auto-complete):")
            target = input("Path to hide: ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\nCancelled.")
            return 0

    if not target:
        print("Error: No path specified.")
        return 1

    success = add_to_guardignore(root, target)
    if success:
        print(f"\033[92m[PROTECTED]\033[0m Added '{target}' to .guardignore. AI coding agents CANNOT read it.")
    else:
        print(f"[NOTICE] '{target}' is already protected in .guardignore.")
    return 0


def cmd_remove(args: argparse.Namespace) -> int:
    from aiguard.scanner import remove_from_guardignore
    cfg = load_config(args.config)
    root = cfg["root"]
    target = args.path

    if not target:
        print("Usage: aiguard remove <file_or_folder_path>")
        return 1

    success = remove_from_guardignore(root, target)
    if success:
        print(f"\033[92m[UNLOCKED]\033[0m Removed '{target}' from .guardignore. AI coding agents CAN now read it.")
    else:
        print(f"[NOTICE] '{target}' was not found in .guardignore.")
    return 0


def cmd_list(args: argparse.Namespace) -> int:
    from aiguard.scanner import read_guardignore
    cfg = load_config(args.config)
    root = cfg["root"]

    yml_rules = cfg.get("deny", [])
    ignore_rules = read_guardignore(root)

    print(f"\n================ Active Protection Rules ================")
    print(f"Target Root: {root}")
    print(f"Mode:        {cfg.get('mode', 'enforce').upper()}")
    print("-" * 55)

    if not yml_rules and not ignore_rules:
        print("  No active protection rules. All files are readable by AI agents.")
    else:
        all_rules = sorted(list(set(yml_rules + ignore_rules)))
        for r in all_rules:
            is_folder = r.endswith("/") or not ("." in os.path.basename(r))
            type_lbl = "[FOLDER]" if is_folder else "[FILE]  "
            print(f"  \033[91mBLOCKED\033[0m {type_lbl} {r}")

    print("=" * 55 + "\n")
    return 0


def cmd_init(args: argparse.Namespace) -> int:
    from aiguard.scanner import init_project, setup_shell_aliases
    target_dir = os.path.abspath(args.path or os.getcwd())
    print(f"\n=======================================================")
    print(f"       AI Guard Project Initialization Wizard          ")
    print(f"=======================================================")
    print(f"Target Directory: {target_dir}\n")

    ignore_path, log_script, findings = init_project(target_dir)

    print(f"\033[92m[SUCCESS]\033[0m Initialized AI Guard in: {target_dir}")
    print(f"  ├── Rules File:   {os.path.basename(ignore_path)} (Conceals sensitive files/folders)")
    print(f"  ├── Live Monitor: {os.path.basename(log_script)} (Run `./aiguard-log.sh` to watch live)")
    print(f"  ├── Git Security: Updated .gitignore (Logs, rules & scripts will not be pushed to GitHub)")

    # Configure transparent agent aliases in user's shell rc file
    alias_res = setup_shell_aliases()
    if alias_res.get("configured") and alias_res.get("files"):
        files_str = ", ".join([os.path.basename(f) for f in alias_res["files"]])
        print(f"  └── Shell Alias:  Added 'claude' -> 'aiguard run -- claude' to {files_str}")
    else:
        print(f"  └── Shell Alias:  'claude' is already configured for transparent protection.")

    if findings:
        print(f"\nAutomatically detected and protected {len(findings)} sensitive asset(s):")
        for f in findings:
            print(f"  [{f['type'].upper()}] {f['path']} ({f['reason']})")
    else:
        print("\nDefault standard security patterns (.env, secrets/, *.pem) added to .aiguardignore.")

    print("\nNext Steps:")
    print("  1. Run your AI agent directly:")
    print("     claude                    (Transparently protected via shell alias)")
    print("     - or -")
    print("     aiguard run -- claude     (Direct execution)")
    print("     \033[90m(Note: Run 'source ~/.bashrc' or open a new terminal to use the 'claude' alias immediately)\033[0m")
    print("  2. In another terminal, run `./aiguard-log.sh` to watch live agent reads.")
    print("  3. Inspect or edit .aiguardignore to customize which files/folders are hidden.\n")
    return 0


def cmd_deinit(args: argparse.Namespace) -> int:
    from aiguard.scanner import deinit_project
    target_dir = os.path.abspath(args.path or os.getcwd())
    removed = deinit_project(target_dir)
    if removed:
        print(f"\n\033[92m[CLEANED]\033[0m Removed AI Guard files from {target_dir}:")
        for r in removed:
            print(f"  - {r}")
        print("Project restored to clean state.\n")
    else:
        print(f"\n[NOTICE] No AI Guard files (.aiguardignore, aiguard-log.sh) found in {target_dir}.\n")
    return 0


def cmd_logs(args: argparse.Namespace) -> int:
    import json
    from datetime import datetime

    cfg = load_config(args.config)
    log_path = cfg.get("log", os.path.expanduser("~/.aiguard/logs/access.jsonl"))

    if not os.path.isfile(log_path):
        print(f"\n[AI Guard] No access log found at: {log_path}")
        print("Run an agent or probe first (`aiguard run -- bash`).\n")
        return 0

    if getattr(args, "follow", False):
        print(f"\n==========================================================")
        print(f" AI Guard Live Access Telemetry Monitor")
        print(f" Log Destination: {log_path}")
        print(f" Watching real-time file reads & blocked attempts...")
        print(f" Press Ctrl+C to stop watching.")
        print(f"==========================================================")
        print(f"{'TIME':<9} {'PROC (PID)':<16} {'OP':<6} {'BYTES':<8} {'STATUS':<10} {'PATH'}")
        print("-" * 67)
        try:
            with open(log_path, "r", encoding="utf-8") as f:
                f.seek(0, os.SEEK_END)
                while True:
                    line = f.readline()
                    if not line:
                        time.sleep(0.2)
                        continue
                    try:
                        ev = json.loads(line.strip())
                        ts = ev.get("ts", 0)
                        t_str = datetime.fromtimestamp(ts).strftime("%H:%M:%S") if ts else "--:--:--"
                        proc = f"{ev.get('proc', '?')} ({ev.get('pid', '?')})"
                        op = ev.get("op", "")
                        b = ev.get("bytes", 0)
                        dec = ev.get("decision", "")
                        dec_color = "\033[92mALLOWED\033[0m" if dec == "allowed" else "\033[91mBLOCKED\033[0m"
                        p = ev.get("path", "")
                        print(f"{t_str:<9} {proc:<16} {op:<6} {b:<8} {dec_color:<19} {p}")
                    except json.JSONDecodeError:
                        pass
        except KeyboardInterrupt:
            print("\nStopped live log monitor.")
            return 0

    events = []
    file_bytes = {}
    blocked_files = set()
    total_bytes = 0
    allowed_count = 0
    blocked_count = 0

    with open(log_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                ev = json.loads(line)
                events.append(ev)
                decision = ev.get("decision", "")
                p = ev.get("path", "")
                b = ev.get("bytes", 0)
                if decision == "allowed":
                    allowed_count += 1
                    total_bytes += b
                    if ev.get("op") == "read" and p:
                        file_bytes[p] = file_bytes.get(p, 0) + b
                elif decision in ("blocked", "would_block"):
                    blocked_count += 1
                    if p:
                        blocked_files.add(p)
            except json.JSONDecodeError:
                pass

    if getattr(args, "json", False):
        print(json.dumps(events, indent=2))
        return 0

    export_path = getattr(args, "export", None)
    if export_path:
        with open(export_path, "w", encoding="utf-8") as f:
            json.dump(events, f, indent=2)
        print(f"\n[SUCCESS] Exported {len(events)} access events to: {export_path}\n")
        return 0

    print(f"\n================ AI Guard Access Telemetry & Audit ================")
    print(f"Log Destination: {log_path}")
    print(f"Total Events:    {len(events)} | Allowed Reads: {allowed_count} | Blocked Probes: {blocked_count}")
    print(f"Total Bytes:     {total_bytes:,} bytes ({round(total_bytes/1024, 2)} KB)")
    print("=" * 67)

    if file_bytes:
        print("\nFile Read Breakdown (Bytes Transferred to Agent):")
        print("-" * 67)
        print(f"{'PATH':<45} {'BYTES READ':<12} {'KB'}")
        print("-" * 67)
        for p, b in sorted(file_bytes.items(), key=lambda x: x[1], reverse=True):
            print(f"{p:<45} {b:<12,} {round(b/1024, 2)} KB")
        print("-" * 67)

    if blocked_files:
        print("\nIntercepted / Blocked Paths (Zero Bytes Leaked):")
        print("-" * 67)
        for p in sorted(blocked_files):
            print(f"  \033[91m[BLOCKED - ENOENT]\033[0m {p}")
        print("-" * 67)

    # Show recent N events
    n = args.lines
    recent = events[-n:]
    print(f"\nRecent {len(recent)} Access Event(s):")
    print("-" * 67)
    print(f"{'TIME':<9} {'PROC (PID)':<16} {'OP':<6} {'BYTES':<8} {'STATUS':<10} {'PATH'}")
    print("-" * 67)
    for ev in recent:
        ts = ev.get("ts", 0)
        t_str = datetime.fromtimestamp(ts).strftime("%H:%M:%S") if ts else "--:--:--"
        proc = f"{ev.get('proc', '?')} ({ev.get('pid', '?')})"
        op = ev.get("op", "")
        b = ev.get("bytes", 0)
        dec = ev.get("decision", "")
        dec_color = "\033[92mALLOWED\033[0m" if dec == "allowed" else "\033[91mBLOCKED\033[0m"
        p = ev.get("path", "")
        print(f"{t_str:<9} {proc:<16} {op:<6} {b:<8} {dec_color:<19} {p}")
    print("=" * 67 + "\n")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(prog="aiguard", description="AI Guard: Filesystem-level protection for autonomous coding agents")
    sub = parser.add_subparsers(dest="command", required=True)

    # init
    init_p = sub.add_parser("init", help="Initialize AI Guard protection in a project (creates .aiguardignore & aiguard-log.sh)")
    init_p.add_argument("path", nargs="?", default="", help="Project path to initialize (default: current directory)")
    init_p.set_defaults(func=cmd_init)

    # deinit
    deinit_p = sub.add_parser("deinit", help="Remove AI Guard files (.aiguardignore, aiguard-log.sh) from a project")
    deinit_p.add_argument("path", nargs="?", default="", help="Project path to de-initialize (default: current directory)")
    deinit_p.set_defaults(func=cmd_deinit)

    # run
    run_p = sub.add_parser("run", help="Run an AI coding agent inside the guard and sandbox")
    run_p.add_argument("-c", "--config", default="aiguard.yml", help="Path to aiguard.yml")
    run_p.add_argument("agent_cmd", nargs=argparse.REMAINDER, help="Agent command to execute")
    run_p.set_defaults(func=cmd_run)

    # mount
    mnt_p = sub.add_parser("mount", help="Mount GuardFS directly (useful for IDEs)")
    mnt_p.add_argument("-c", "--config", default="aiguard.yml", help="Path to aiguard.yml")
    mnt_p.set_defaults(func=cmd_mount)

    # unmount
    unmnt_p = sub.add_parser("unmount", help="Unmount GuardFS")
    unmnt_p.add_argument("-c", "--config", default="aiguard.yml", help="Path to aiguard.yml")
    unmnt_p.set_defaults(func=cmd_unmount)

    # doctor
    doc_p = sub.add_parser("doctor", help="Check system prerequisites and dependencies")
    doc_p.set_defaults(func=cmd_doctor)

    # audit-check
    aud_p = sub.add_parser("audit-check", help="Run the Problem Statement, Objectives & Novelty Auditor Agent")
    aud_p.set_defaults(func=cmd_audit)

    # scan
    scan_p = sub.add_parser("scan", help="Scan repository for sensitive files and folders")
    scan_p.add_argument("-c", "--config", default="aiguard.yml", help="Path to aiguard.yml")
    scan_p.set_defaults(func=cmd_scan)

    # config / wizard
    cfg_p = sub.add_parser("config", help="Interactively configure file and folder protection rules")
    cfg_p.add_argument("-c", "--config", default="aiguard.yml", help="Path to aiguard.yml")
    cfg_p.set_defaults(func=cmd_config)

    # add
    add_p = sub.add_parser("add", help="Add a file or folder to protection rules (Tab-completion enabled)")
    add_p.add_argument("path", nargs="?", default="", help="File or folder path to hide from AI agents")
    add_p.add_argument("-c", "--config", default="aiguard.yml", help="Path to aiguard.yml")
    add_p.set_defaults(func=cmd_add)

    # remove
    rem_p = sub.add_parser("remove", help="Remove a file or folder from protection (allow AI agents to read)")
    rem_p.add_argument("path", help="File or folder path to unblock")
    rem_p.add_argument("-c", "--config", default="aiguard.yml", help="Path to aiguard.yml")
    rem_p.set_defaults(func=cmd_remove)

    # list
    list_p = sub.add_parser("list", help="List all currently active file and folder protection rules")
    list_p.add_argument("-c", "--config", default="aiguard.yml", help="Path to aiguard.yml")
    list_p.set_defaults(func=cmd_list)

    # logs
    logs_p = sub.add_parser("logs", help="View access telemetry, byte counts, and blocked audit logs")
    logs_p.add_argument("-n", "--lines", type=int, default=15, help="Number of recent events to display (default: 15)")
    logs_p.add_argument("-f", "--follow", action="store_true", help="Follow real-time telemetry log live (tail -f mode)")
    logs_p.add_argument("--json", action="store_true", help="Output telemetry records as a formatted JSON array")
    logs_p.add_argument("--export", type=str, metavar="FILE", help="Export access logs to a JSON file (e.g. access.json)")
    logs_p.add_argument("-c", "--config", default="aiguard.yml", help="Path to aiguard.yml")
    logs_p.set_defaults(func=cmd_logs)

    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())


