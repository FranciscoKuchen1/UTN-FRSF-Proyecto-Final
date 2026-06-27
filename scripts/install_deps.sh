#!/usr/bin/env bash
set -euo pipefail

# install_deps.sh — Install system dependencies for Guardian FS on Ubuntu 24.04
# Idempotent: safe to run multiple times

echo "==> Updating package lists..."
apt-get update -qq

declare -a PACKAGES=(
    build-essential
    cmake
    pkg-config
    libfuse3-dev
    zfsutils-linux
    python3
    python3-pip
    python3-venv
    git
    curl
)

echo "==> Installing required system packages..."
for pkg in "${PACKAGES[@]}"; do
    if dpkg -s "$pkg" &>/dev/null; then
        echo "  [OK] $pkg already installed"
    else
        echo "  [++] Installing $pkg..."
        apt-get install -y "$pkg"
    fi
done

echo ""
echo "==> All system dependencies installed."
echo "    Next: run scripts/zfs_setup.sh to create the ZFS pool"
echo "          then scripts/mount.sh to mount the FUSE filesystem"
