"""Tests for AI Guard Smart Scanner, .guardignore management, and folder protection."""

import os
import tempfile
import pytest

from aiguard.scanner import (
    scan_project,
    read_guardignore,
    write_guardignore,
    add_to_guardignore,
    remove_from_guardignore,
)
from aiguard.config import load_config
from aiguard.rules import Rules


def test_scan_project_detects_files_and_folders():
    with tempfile.TemporaryDirectory() as tmpdir:
        # Create folders and files
        os.makedirs(os.path.join(tmpdir, "secrets"), exist_ok=True)
        os.makedirs(os.path.join(tmpdir, "src"), exist_ok=True)
        os.makedirs(os.path.join(tmpdir, "docs"), exist_ok=True)

        with open(os.path.join(tmpdir, ".env"), "w") as f:
            f.write("KEY=secret\n")
        with open(os.path.join(tmpdir, "secrets", "token.pem"), "w") as f:
            f.write("KEY\n")
        with open(os.path.join(tmpdir, "docs", "secret.pdf"), "w") as f:
            f.write("PDF\n")
        with open(os.path.join(tmpdir, "src", "main.py"), "w") as f:
            f.write("print(1)\n")

        findings = scan_project(tmpdir)
        paths = [f["path"] for f in findings]
        types = {f["path"]: f["type"] for f in findings}

        # secrets/ folder must be detected as folder
        assert "secrets/" in paths
        assert types["secrets/"] == "folder"

        # files must be detected
        assert ".env" in paths
        assert "secrets/token.pem" in paths
        assert "docs/secret.pdf" in paths

        # benign code should NOT be detected
        assert "src/main.py" not in paths


def test_guardignore_read_write_add_remove():
    with tempfile.TemporaryDirectory() as tmpdir:
        # Write initial rules
        write_guardignore(tmpdir, [".env", "secrets/"])
        rules = read_guardignore(tmpdir)
        assert ".env" in rules
        assert "secrets/" in rules

        # Add rule
        added = add_to_guardignore(tmpdir, "docs/confidential.pdf")
        assert added is True
        rules_after_add = read_guardignore(tmpdir)
        assert "docs/confidential.pdf" in rules_after_add

        # Add duplicate should return False
        assert add_to_guardignore(tmpdir, "docs/confidential.pdf") is False

        # Remove rule
        removed = remove_from_guardignore(tmpdir, ".env")
        assert removed is True
        rules_after_remove = read_guardignore(tmpdir)
        assert ".env" not in rules_after_remove
        assert "docs/confidential.pdf" in rules_after_remove


def test_config_merges_guardignore():
    with tempfile.TemporaryDirectory() as tmpdir:
        # Write .guardignore
        write_guardignore(tmpdir, ["custom_secret.txt", "my_folder/"])

        # Write aiguard.yml
        cfg_file = os.path.join(tmpdir, "aiguard.yml")
        with open(cfg_file, "w") as f:
            f.write(f"""
root: {tmpdir}
mountpoint: {tmpdir}/mnt
log: {tmpdir}/log.jsonl
mode: enforce
deny:
  - ".env"
""")
        cfg = load_config(cfg_file)
        assert ".env" in cfg["deny"]
        assert "custom_secret.txt" in cfg["deny"]
        assert "my_folder/" in cfg["deny"]


def test_rules_block_entire_folder_and_descendants():
    rules = Rules(["secrets/", "private_data"])
    
    # Path is the folder itself
    assert rules.is_denied("secrets") is True
    assert rules.is_denied("secrets/") is True
    assert rules.is_denied("private_data") is True

    # Descendants of the folder
    assert rules.is_denied("secrets/token.pem") is True
    assert rules.is_denied("secrets/nested/deep/key.txt") is True
    assert rules.is_denied("private_data/report.xlsx") is True

    # Unrelated files allowed
    assert rules.is_denied("src/secrets_helper.py") is False
    assert rules.is_denied("public/data.json") is False


def test_init_and_deinit_project():
    from aiguard.scanner import init_project, deinit_project

    with tempfile.TemporaryDirectory() as tmpdir:
        # Create test files
        with open(os.path.join(tmpdir, ".env"), "w") as f:
            f.write("A=B\n")
        os.makedirs(os.path.join(tmpdir, "secrets"), exist_ok=True)
        with open(os.path.join(tmpdir, "secrets", "key.pem"), "w") as f:
            f.write("KEY\n")

        # Run init
        ignore_path, log_script, findings = init_project(tmpdir)
        assert os.path.isfile(ignore_path)
        assert os.path.isfile(log_script)
        assert os.access(log_script, os.X_OK)

        # Config loads automatically from init
        cfg = load_config(os.path.join(tmpdir, "nonexistent.yml"))
        # Should load rules from .aiguardignore
        assert any(".env" in r for r in cfg["deny"])

        # Run deinit
        removed = deinit_project(tmpdir)
        assert ".aiguardignore" in removed or ".guardignore" in removed
        assert "aiguard-log.sh" in removed
        assert not os.path.exists(log_script)


def test_setup_and_remove_shell_aliases():
    from aiguard.scanner import setup_shell_aliases, remove_shell_aliases

    with tempfile.TemporaryDirectory() as tmpdir:
        fake_rc = os.path.join(tmpdir, ".bashrc")
        with open(fake_rc, "w") as f:
            f.write("# existing config\n")

        # Setup aliases
        res = setup_shell_aliases(target_rc=fake_rc, agents=["claude", "custom-agent"])
        assert res["configured"] is True
        assert fake_rc in res["files"]

        with open(fake_rc, "r") as f:
            content = f.read()
        assert "alias claude='aiguard run -- claude'" in content
        assert "alias custom-agent='aiguard run -- custom-agent'" in content

        # Re-running setup should be idempotent (not duplicate)
        res_idempotent = setup_shell_aliases(target_rc=fake_rc, agents=["claude"])
        assert res_idempotent["configured"] is False

        # Remove aliases
        cleaned = remove_shell_aliases(target_rc=fake_rc)
        assert fake_rc in cleaned
        with open(fake_rc, "r") as f:
            clean_content = f.read()
        assert "alias claude=" not in clean_content
        assert "# existing config" in clean_content


def test_update_gitignore_for_aiguard():
    from aiguard.scanner import update_gitignore_for_aiguard

    with tempfile.TemporaryDirectory() as tmpdir:
        # 1. Update on non-existent gitignore
        updated = update_gitignore_for_aiguard(tmpdir)
        assert updated is True

        gitignore_path = os.path.join(tmpdir, ".gitignore")
        assert os.path.isfile(gitignore_path)
        with open(gitignore_path, "r") as f:
            content = f.read()
        assert ".aiguard/" in content
        assert ".aiguardignore" in content
        assert "aiguard-log.sh" in content
        assert "*.jsonl" in content
        assert "access.json" in content

        # 2. Second run should be idempotent
        updated_again = update_gitignore_for_aiguard(tmpdir)
        assert updated_again is False

