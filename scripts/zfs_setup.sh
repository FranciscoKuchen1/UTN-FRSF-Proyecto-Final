#!/usr/bin/env bash
set -euo pipefail

# zfs_setup.sh — Create ZFS pool and datasets for Guardian FS PoC/testing
# Usage: zfs_setup.sh [dataset_name] [mountpoint]
# Defaults: dataset=tank/data, mountpoint=/mnt/guardian_real
# Idempotent: skips creation if zpool/dataset already exists

DATASET="${1:-tank/data}"
MOUNTPOINT="${2:-/mnt/guardian_real}"
POOL="${DATASET%%/*}"          # "tank" from "tank/data"
ZPOOL_DISK="/tmp/zpool_disk.img"
DISK_SIZE_MB=2048              # 2 GB file-backed pool for testing

echo "==> Guardian FS — ZFS Setup"
echo "    Pool:     $POOL"
echo "    Dataset:  $DATASET"
echo "    Mount:    $MOUNTPOINT"
echo ""

# --- 1. Create file-backed zpool if it doesn't exist ---
if zpool list "$POOL" &>/dev/null; then
    echo "==> Zpool '$POOL' already exists — skipping creation"
else
    echo "==> Creating file-backed disk image ($DISK_SIZE_MB MB)..."
    if [[ ! -f "$ZPOOL_DISK" ]]; then
        truncate -s "${DISK_SIZE_MB}M" "$ZPOOL_DISK"
    fi
    echo "==> Creating zpool '$POOL'..."
    zpool create -f -m none "$POOL" "$ZPOOL_DISK"
    echo "    Zpool '$POOL' created successfully"
fi

# --- 2. Create dataset if it doesn't exist ---
if zfs list "$DATASET" &>/dev/null; then
    echo "==> Dataset '$DATASET' already exists — skipping creation"
else
    echo "==> Creating dataset '$DATASET'..."
    zfs create "$DATASET"
    zfs set mountpoint="$MOUNTPOINT" "$DATASET"
    echo "    Dataset '$DATASET' created"
fi

# --- 3. Configure dataset properties ---
echo "==> Configuring dataset properties..."
zfs set compression=lz4  "$DATASET"
zfs set atime=off        "$DATASET"

echo ""
echo "==> Setup complete!"
echo ""
echo "    Pool:      $(zpool list -o name,size,health -H "$POOL" 2>/dev/null || echo 'N/A')"
echo "    Dataset:"
zfs list -o name,used,available,mountpoint,compression,atime "$DATASET" 2>/dev/null || true
echo ""
echo "    Next: run scripts/mount.sh $MOUNTPOINT <mountpoint>"
