#!/usr/bin/env bash
# Build a standalone CyberShield GUI executable for the current platform.
# Windows: cybershield-gui.exe | macOS: cybershield-gui (.app) | Linux: cybershield-gui
#
# Usage:
#   bash build/gui.sh            # build using .venv
#   bash build/gui.sh --install  # create venv + install deps, then build

set -euo pipefail

cd "$(dirname "$0")/.."
PY="python3"
VENV=".venv"

if [[ "${1:-}" == "--install" ]]; then
    echo ">> Creating venv and installing build dependencies..."
    "$PY" -m venv "$VENV"
    "$VENV/bin/python" -m pip install --upgrade pip
    "$VENV/bin/python" -m pip install pyinstaller -r requirements-gui.txt
fi

if [[ ! -x "$VENV/bin/python" ]]; then
    echo "No virtualenv found. Run with --install first, or activate one."
    exit 1
fi

echo ">> Building GUI bundle with PyInstaller..."
"$VENV/bin/python" -m PyInstaller --noconfirm --clean packaging/cybershield-gui.spec

echo
echo ">> Build complete. Artifacts:"
find dist -maxdepth 2 -name "cybershield-gui*" -print