#!/usr/bin/env bash
# ==============================================================================
# AI Guard: Global One-Time System Installer
# ==============================================================================
# Installs `aiguard` as a global system-wide CLI command so you can protect
# any project folder on your entire machine by simply typing `aiguard`.
# ==============================================================================

set -e

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIN_DIR="$HOME/.local/bin"
mkdir -p "$BIN_DIR"

echo "------------------------------------------------------------------"
echo " AI Guard System-Wide CLI Installer"
echo " Source Directory: $DIR"
echo " Target Binary:    $BIN_DIR/aiguard"
echo "------------------------------------------------------------------"

# 1. Check Python
if ! command -v python3 &>/dev/null; then
    echo "[ERROR] Python 3 is not installed. Please install Python 3.10+ first."
    exit 1
fi

# 2. Check FUSE and Bubblewrap dependencies
MISSING_PKGS=()
if ! command -v bwrap &>/dev/null; then
    MISSING_PKGS+=("bubblewrap")
fi
if ! command -v fusermount &>/dev/null && ! command -v fusermount3 &>/dev/null; then
    MISSING_PKGS+=("fuse3")
fi

if [ ${#MISSING_PKGS[@]} -gt 0 ]; then
    echo "[WARN] System packages missing: ${MISSING_PKGS[*]}"
    echo "       Please run: sudo apt update && sudo apt install -y ${MISSING_PKGS[*]} libfuse2t64"
    echo "       (Continuing installation...)"
fi

# 3. Install Python package in user mode or virtualenv
echo "[INFO] Installing AI Guard CLI package..."
if command -v pip &>/dev/null; then
    pip install --user -e "$DIR" --break-system-packages 2>/dev/null || pip install --user -e "$DIR" 2>/dev/null || pip install -e "$DIR"
elif command -v pip3 &>/dev/null; then
    pip3 install --user -e "$DIR" --break-system-packages 2>/dev/null || pip3 install --user -e "$DIR" 2>/dev/null || pip3 install -e "$DIR"
else
    # Direct wrapper script creation if pip user is restricted
    echo "Creating direct binary wrapper in $BIN_DIR/aiguard..."
fi

# 4. Guarantee executable wrapper in ~/.local/bin/aiguard
WRAPPER="$BIN_DIR/aiguard"
cat << 'EOF' > "$WRAPPER"
#!/usr/bin/env bash
# AI Guard Global Launcher

# Locate source install dir
INSTALL_DIR="__INSTALL_DIR__"
VENV_PY="$INSTALL_DIR/.venv/bin/python"

if [ -f "$VENV_PY" ]; then
    exec "$VENV_PY" -m aiguard.cli "$@"
elif command -v python3 &>/dev/null; then
    exec python3 -m aiguard.cli "$@"
else
    echo "Error: Python 3 runtime not found." >&2
    exit 1
fi
EOF

# Substitute actual install directory
sed -i "s|__INSTALL_DIR__|$DIR|g" "$WRAPPER"
chmod +x "$WRAPPER"

# 5. Ensure ~/.local/bin is in PATH
SHELL_RC=""
if [ -n "$BASH_VERSION" ]; then
    SHELL_RC="$HOME/.bashrc"
elif [ -n "$ZSH_VERSION" ]; then
    SHELL_RC="$HOME/.zshrc"
else
    SHELL_RC="$HOME/.profile"
fi

if [[ ":$PATH:" != *":$BIN_DIR:"* ]]; then
    echo "export PATH=\"\$HOME/.local/bin:\$PATH\"" >> "$SHELL_RC"
    export PATH="$BIN_DIR:$PATH"
    echo "Added $BIN_DIR to PATH in $SHELL_RC"
fi

# 6. Configure transparent agent aliases (claude, cursor-agent)
if ! grep -q "alias claude=" "$SHELL_RC" 2>/dev/null; then
    cat << 'EOF' >> "$SHELL_RC"

# >>> AI Guard Transparent Agent Aliases >>>
alias claude='aiguard run -- claude'
alias cursor-agent='aiguard run -- cursor-agent'
# <<< AI Guard Transparent Agent Aliases <<<
EOF
    echo "[INFO] Added transparent AI agent aliases to $SHELL_RC"
fi

echo ""
echo "------------------------------------------------------------------"
echo " [SUCCESS] AI Guard installed successfully"
echo "------------------------------------------------------------------"
echo " Binary location: $BIN_DIR/aiguard"
echo ""
echo " Quick Start Workflow:"
echo "   1. Navigate to target repository:"
echo "      cd ~/my_project"
echo ""
echo "   2. Initialize filesystem mediation:"
echo "      aiguard init"
echo ""
echo "   3. Execute agent transparently:"
echo "      claude"
echo "      (or: aiguard run -- claude)"
echo ""
echo "   4. Monitor real-time access telemetry:"
echo "      ./aiguard-log.sh"
echo "------------------------------------------------------------------"
