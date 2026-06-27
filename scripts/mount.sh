#!/usr/bin/env bash
set -euo pipefail

# mount.sh — Mount the Guardian FUSE filesystem
# Usage: mount.sh <source_dir> <mountpoint>
# Example: mount.sh /zpool/data /mnt/protected

usage() {
    echo "Usage: $0 <source_dir> <mountpoint>"
    echo "  source_dir   Real backend path (must exist)"
    echo "  mountpoint   FUSE mount target"
    exit 1
}

SOURCE="${1:-}"
MOUNTPOINT="${2:-}"

if [[ -z "$SOURCE" || -z "$MOUNTPOINT" ]]; then
    echo "ERROR: Missing arguments"
    usage
fi

GUARDIAN_BIN="$(dirname "$0")/../build/guardian_fs"

if [[ ! -x "$GUARDIAN_BIN" ]]; then
    echo "ERROR: guardian_fs binary not found at $GUARDIAN_BIN"
    echo "       Build it first with cmake in the build/ directory"
    exit 1
fi

if [[ ! -d "$SOURCE" ]]; then
    echo "ERROR: Source directory does not exist: $SOURCE"
    exit 1
fi

# Create mountpoint if it doesn't exist
mkdir -p "$MOUNTPOINT"

# Unmount if already mounted
if mountpoint -q "$MOUNTPOINT" 2>/dev/null; then
    echo "==> Unmounting existing mount at $MOUNTPOINT..."
    fusermount -u "$MOUNTPOINT" || true
    sleep 1
fi

echo "==> Mounting guardian_fs: $SOURCE -> $MOUNTPOINT"
"$GUARDIAN_BIN" -f -o allow_other,default_permissions "$SOURCE" "$MOUNTPOINT"

echo ""
echo "==> Mounted successfully."
echo "    FUSE mount:   $MOUNTPOINT"
echo "    Backing store: $SOURCE"
