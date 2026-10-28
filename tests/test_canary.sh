#!/usr/bin/env bash
# tests/test_canary.sh: End-to-end canary verification script
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SYS_DIR="$(dirname "$SCRIPT_DIR")"
VENV_PY="$SYS_DIR/.venv/bin/python"

CANARY="CANARY_9f3b7a1c_DO_NOT_LEAK"
TEST_PROJ="$SYS_DIR/test_project"
TEST_LOG="/home/ratul/.aiguard/logs/access.jsonl"

echo "================ STARTING CANARY INTEGRATION TEST ================"

# 1. Setup sample project with a canary .env and safe src/app.py
mkdir -p "$TEST_PROJ/src"
mkdir -p "$TEST_PROJ/secrets"
echo "SECRET_API_KEY=$CANARY" > "$TEST_PROJ/.env"
echo "CANARY_IN_SECRETS=$CANARY" > "$TEST_PROJ/secrets/token.pem"
echo 'print("Hello from allowed app.py")' > "$TEST_PROJ/src/app.py"
echo 'CANARY_PROBE_VALUE="CANARY_PROBE_VALUE"' >> "$TEST_PROJ/.env"

# 2. Run an agent / simulated explorer inside the sandbox via aiguard CLI
echo "[Test] Executing simulated agent inside aiguard sandbox..."
AGENT_OUTPUT_FILE=$(mktemp)

# Command that attempts to leak .env, secrets, and reads allowed files
AGENT_CMD='sh -c "echo --- Reading app.py ---; cat src/app.py; echo --- Trying .env ---; cat .env 2>&1 || true; echo --- Trying secrets ---; cat secrets/token.pem 2>&1 || true; echo --- Grepping ---; grep -r CANARY . 2>&1 || true"'

"$VENV_PY" -m aiguard.cli run -c "$SYS_DIR/aiguard.yml" -- bash -c "$AGENT_CMD" > "$AGENT_OUTPUT_FILE" 2>&1 || true

echo "[Test] Sandboxed execution finished."
echo "[Test] Agent Output:"
cat "$AGENT_OUTPUT_FILE"

# 3. Verification step 1: Did canary leak into stdout/stderr?
if grep -q "$CANARY" "$AGENT_OUTPUT_FILE"; then
  echo "FAIL: Canary secret was leaked in the agent output!"
  rm -f "$AGENT_OUTPUT_FILE"
  exit 1
else
  echo "PASS: Canary secret is ABSENT from agent output."
fi

# 4. Verification step 2: Is canary secret absent from the log?
if grep -q "$CANARY" "$TEST_LOG"; then
  echo "FAIL: Canary secret leaked into access log!"
  rm -f "$AGENT_OUTPUT_FILE"
  exit 1
else
  echo "PASS: Access log does not contain canary content (prompt & content-blind)."
fi

# 5. Verification step 3: Does access log contain blocked attempts?
if grep -q '"decision": "blocked"' "$TEST_LOG"; then
  echo "PASS: Access log successfully recorded 'blocked' decision for denied paths."
else
  echo "FAIL: No 'blocked' entries found in log."
  rm -f "$AGENT_OUTPUT_FILE"
  exit 1
fi

rm -f "$AGENT_OUTPUT_FILE"
echo "================ CANARY TEST COMPLETED SUCCESSFULLY ================"
exit 0
