#!/usr/bin/env python3
"""AI Guard Interactive Demonstration and Testing Suite.

Designed for researchers, supervisors, teachers, and team members to test,
demonstrate, and verify AI Guard's filesystem-level protection.
"""

import os
import subprocess
import sys
import time

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
SYS_DIR = os.path.dirname(SCRIPT_DIR)
VENV_PY = os.path.join(SYS_DIR, ".venv", "bin", "python")
CONFIG_PATH = os.path.join(SYS_DIR, "aiguard.yml")


def clear():
    os.system("clear" if os.name == "posix" else "cls")


def print_banner():
    print(r"""
    ===================================================================
     AI GUARD: FILESYSTEM-LEVEL MEDIATION LAYER & TELEMETRY MONITOR
    ===================================================================
     External OS-Level Enforcement for AI Coding Agents
    -------------------------------------------------------------------
    """)


def run_doctor():
    print("\n[INFO] Running AI Guard Doctor (Prerequisites Check)...")
    subprocess.call([VENV_PY, "-m", "aiguard.cli", "doctor"])


def run_auditor():
    print("\n[INFO] Running Compliance & Research Novelty Auditor Agent...")
    subprocess.call([VENV_PY, "-m", "aiguard.cli", "audit-check"])


def run_probe():
    print("\n[INFO] Running Deterministic Probe (Bypass & Leak Prevention)...")
    probe_script = os.path.join(SYS_DIR, "tests", "probe.sh")
    test_proj = os.path.join(SYS_DIR, "test_project")
    os.makedirs(os.path.join(test_proj, "src"), exist_ok=True)
    with open(os.path.join(test_proj, ".env"), "w") as f:
        f.write("CANARY_PROBE_VALUE=secret_token_12345\n")
    with open(os.path.join(test_proj, "src", "app.py"), "w") as f:
        f.write("print('Hello from safe code')\n")
    subprocess.call([VENV_PY, "-m", "aiguard.cli", "run", "-c", CONFIG_PATH, "--", "bash", probe_script])


def run_canary():
    print("\n[INFO] Running End-to-End Canary Security Test...")
    canary_script = os.path.join(SYS_DIR, "tests", "test_canary.sh")
    subprocess.call(["bash", canary_script])


def run_interactive_shell():
    print("\n[INFO] Launching Sandboxed Shell (GuardFS mounted at /workspace)...")
    print("       Type 'exit' to return to this menu.")
    subprocess.call([VENV_PY, "-m", "aiguard.cli", "run", "-c", CONFIG_PATH, "--", "bash"])


def launch_web_dashboard():
    print("\n[INFO] Launching AI Guard Web Dashboard on http://localhost:8080 ...")
    dashboard_script = os.path.join(SCRIPT_DIR, "web_dashboard.py")
    subprocess.call([VENV_PY, dashboard_script])


def run_research_experiments():
    print("\n[INFO] Running Empirical Research Benchmark (Precision, Recall, F1, LaTeX Tables)...")
    exp_script = os.path.join(SYS_DIR, "Research Paper Resource", "run_experiments.py")
    subprocess.call([VENV_PY, exp_script])


def view_logs():
    log_path = os.path.expanduser("~/.aiguard/logs/access.jsonl")
    if not os.path.exists(log_path):
        print("\n[WARN] No access logs found yet. Run an agent or probe first.")
        return
    print(f"\n[INFO] Latest entries from {log_path}:")
    print("-" * 75)
    with open(log_path, "r", encoding="utf-8") as f:
        lines = f.readlines()
        for line in lines[-15:]:
            print(line.strip())
    print("-" * 75)


def run_scan():
    print("\n[INFO] Scanning project for sensitive files and folders...")
    subprocess.call([VENV_PY, "-m", "aiguard.cli", "scan", "-c", CONFIG_PATH])


def run_config():
    print("\n[INFO] Running Protection Configuration Wizard...")
    subprocess.call([VENV_PY, "-m", "aiguard.cli", "config", "-c", CONFIG_PATH])


def main():
    while True:
        clear()
        print_banner()
        print("  [1] System Health Check (aiguard doctor)")
        print("  [2] Scan Project for Sensitive Files & Folders (aiguard scan)")
        print("  [3] Configure Protection Rules / .guardignore (aiguard config)")
        print("  [4] Run Compliance & Novelty Auditor Agent (G1-G7, NFR audit)")
        print("  [5] Run Deterministic Probe (Test symlink bypass, .env hiding, etc.)")
        print("  [6] Run End-to-End Canary Security Verification")
        print("  [7] Launch Sandboxed Terminal Shell (`aiguard run -- bash`)")
        print("  [8] View Access Audit Log Summary (JSONL)")
        print("  [9] Start Interactive Web Dashboard for Supervisor/Teachers")
        print("  [10] Run Research Paper Benchmark & Generate LaTeX Tables (Precision, Recall, F1)")
        print("  [0] Exit")
        print("-" * 67)
        choice = input("Enter option [0-10]: ").strip()

        if choice == "1":
            run_doctor()
        elif choice == "2":
            run_scan()
        elif choice == "3":
            run_config()
        elif choice == "4":
            run_auditor()
        elif choice == "5":
            run_probe()
        elif choice == "6":
            run_canary()
        elif choice == "7":
            run_interactive_shell()
        elif choice == "8":
            view_logs()
        elif choice == "9":
            launch_web_dashboard()
        elif choice == "10":
            run_research_experiments()
        elif choice == "0":
            print("\nExiting AI Guard Demonstration Suite. Goodbye!\n")
            break
        else:
            print("Invalid choice, please select 0-10.")

        input("\nPress Enter to continue...")



if __name__ == "__main__":
    main()
