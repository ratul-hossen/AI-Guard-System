#!/usr/bin/env bash
# tests/probe.sh: runs INSIDE the sandbox, so /workspace is the guarded view.
# Prerequisite: the real project has a .env containing the text CANARY_PROBE_VALUE
# and a readable src/app.py.
set -u
cd /workspace
fail=0
check() {
  if eval "$2"; then
    echo "[PASS] $1"
  else
    echo "[FAIL] $1"
    fail=1
  fi
}

echo "================ RUNNING DETERMINISTIC PROBE (SANDBOX) ================"
check ".env is not listed"          '! ls -a | grep -qx ".env"'
check "cat .env fails"              '! cat .env 2>/dev/null'
check "recursive grep finds nothing" '! grep -rq --exclude="probe.sh" "CANARY_PROBE_VALUE" . 2>/dev/null'
check "symlink bypass is blocked"   'ln -s .env _probe_link 2>/dev/null; ! cat _probe_link 2>/dev/null; rm -f _probe_link 2>/dev/null'
check "creating .env is blocked"    '! touch .env 2>/dev/null'
check "real home is not visible"    '! ls /home/*/.ssh 2>/dev/null'
check "no secrets in environment"   '! env | grep -qiE "key|token|secret"'
check "allowed file is readable"    'cat src/app.py > /dev/null'
echo "========================================================================"
exit $fail
