#!/bin/bash

# Install project dependencies in isolated venv
# Creates venv in /home (native Linux FS) for WSL compatibility

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_DIR="/home/$(whoami)/.venv-netcon-sync"

# Install system dependencies (only if missing)
echo "📦 Checking system dependencies..."
MISSING_PACKAGES=""

if ! apt list --installed 2>/dev/null | grep -q "python3-pip"; then
    MISSING_PACKAGES="$MISSING_PACKAGES python3-pip"
fi

if ! apt list --installed 2>/dev/null | grep -q "python3-venv"; then
    MISSING_PACKAGES="$MISSING_PACKAGES python3-venv"
fi

if ! apt list --installed 2>/dev/null | grep -q "libnss3-tools"; then
    MISSING_PACKAGES="$MISSING_PACKAGES nss-tools"
fi

if ! apt list --installed 2>/dev/null | grep -q "libnss3"; then
    MISSING_PACKAGES="$MISSING_PACKAGES libnss3"
fi

if ! apt list --installed 2>/dev/null | grep -q "libnss3-dev"; then
    MISSING_PACKAGES="$MISSING_PACKAGES libnss3-dev"
fi

if ! apt list --installed 2>/dev/null | grep -q "python3-nss"; then
    MISSING_PACKAGES="$MISSING_PACKAGES python3-nss"
fi

if [ -z "$MISSING_PACKAGES" ]; then
    echo "✅ System dependencies already installed"
else
    echo "📦 Installing missing packages:$MISSING_PACKAGES"
    sudo apt-get update -qq
    sudo apt-get install -y $MISSING_PACKAGES
    echo "✅ System dependencies installed"
fi

# Check if venv already exists
if [ -f "$VENV_DIR/bin/activate" ]; then
    echo "✅ Found existing venv at: $VENV_DIR"
    # Clean up bad nss package if it exists (Windows-only package)
    source "$VENV_DIR/bin/activate"
    pip uninstall -y nss 2>/dev/null || true
    deactivate
else
    echo "📦 Creating new venv at: $VENV_DIR (with system packages enabled)"
    python3 -m venv --system-site-packages "$VENV_DIR"
    echo "✅ Virtual environment created"
fi

# Activate and install from requirements.txt
echo "📦 Installing dependencies from requirements.txt..."
source "$VENV_DIR/bin/activate"
pip install --upgrade pip
pip install -r "$SCRIPT_DIR/requirements.txt"

echo ""
echo "✅ Dependencies installed successfully!"
pip list | grep -E "requests|tenacity"
echo "✅ NSS library available via system packages"
echo ""
echo "💡 To activate the venv, run:"
echo "   source $VENV_DIR/bin/activate"
