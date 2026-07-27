#!/usr/bin/env bash
set -euo pipefail

# mount.sh — Mount the Guardian FUSE filesystem
# Usage: mount.sh <source_dir> <mountpoint> [zfs_dataset]
# Example: mount.sh /mnt/guardian_real /mnt/protected tank/data

usage() {
    echo "Usage: $0 <source_dir> <mountpoint> [zfs_dataset]"
    echo "  source_dir    Real backend path — must exist"
    echo "  mountpoint    FUSE mount target"
    echo "  zfs_dataset   ZFS dataset name (default: tank/data)"
    exit 1
}

SOURCE="${1:-}"
MOUNTPOINT="${2:-}"
ZFS_DATASET="${3:-tank/data}"

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

# Resolve source to absolute path (FUSE requires absolute paths)
SOURCE="$(realpath "$SOURCE")"
MOUNTPOINT="$(realpath -m "$MOUNTPOINT")"

# Create mountpoint if it doesn't exist
mkdir -p "$MOUNTPOINT"

# Unmount if already mounted
if mountpoint -q "$MOUNTPOINT" 2>/dev/null; then
    echo "==> Unmounting existing mount at $MOUNTPOINT..."
    fusermount -u "$MOUNTPOINT" || true
    sleep 1
fi

# Ensure log directory exists
LOG_DIR="${GUARDIAN_LOG_PATH%/*}"
if [[ -n "${GUARDIAN_LOG_PATH:-}" && ! -d "$LOG_DIR" ]]; then
    mkdir -p "$LOG_DIR"
fi

echo "==> Mounting guardian_fs: $SOURCE -> $MOUNTPOINT"
echo "    ZFS dataset:    $ZFS_DATASET"
echo "    Log:            ${GUARDIAN_LOG_PATH:-/var/log/guardian/events.jsonl}"

# Pass configuration via environment (guardian_fs reads these with getenv)
export GUARDIAN_REAL_ROOT="$SOURCE"
export GUARDIAN_ZFS_DATASET="$ZFS_DATASET"

# FUSE expects: binary [options] mountpoint
exec "$GUARDIAN_BIN" -f -o allow_other,default_permissions "$MOUNTPOINT"
