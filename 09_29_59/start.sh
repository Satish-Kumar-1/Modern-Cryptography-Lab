#!/usr/bin/env bash
# CryptoGuard - Ed25519 Desktop Application (Electron)

set -e

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$DIR"

echo "======================================================================"
echo " CryptoGuard - Ed25519 Desktop Application (Electron)"
echo "======================================================================"
echo ""

if ! command -v python3 &> /dev/null && ! command -v python &> /dev/null; then
    echo "[ERROR] Python was not found in PATH."
    echo "Please install Python 3.9+ and try again."
    exit 1
fi

if command -v npm &> /dev/null; then
    echo "Starting Electron desktop application..."
    npm start
else
    echo "[WARNING] npm not found in PATH. Launching in local server mode..."
    PYTHON_CMD="python3"
    if ! command -v python3 &> /dev/null; then
        PYTHON_CMD="python"
    fi
    $PYTHON_CMD server.py 8080
fi
