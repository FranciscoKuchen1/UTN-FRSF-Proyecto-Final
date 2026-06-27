#!/usr/bin/env bash
set -euo pipefail

# rollback.sh — Rollback a ZFS dataset to a named snapshot (or latest)
# Usage: rollback.sh <dataset> <snapshot_name|latest>
# Example:
#   rollback.sh tank/data guardian-auto-20250101T120000Z
#   rollback.sh tank/data latest

usage() {
    echo "Usage: $0 <dataset> <snapshot_name|latest>"
    echo "  dataset        ZFS dataset (e.g. tank/data)"
    echo "  snapshot_name  Snapshot name or 'latest' for most recent"
    exit 1
}

DATASET="${1:-}"
SNAPSHOT_ARG="${2:-}"

if [[ -z "$DATASET" || -z "$SNAPSHOT_ARG" ]]; then
    echo "ERROR: Missing arguments"
    usage
fi

echo "==> Current state for $DATASET"
zfs list -o name,used,available,mountpoint "$DATASET" 2>/dev/null || {
    echo "ERROR: Dataset $DATASET not found"
    exit 1
}

echo ""

if [[ "$SNAPSHOT_ARG" == "latest" ]]; then
    echo "==> Finding latest snapshot for $DATASET..."
    SNAPSHOT=$(zfs list -t snapshot -o name -s creation "$DATASET" 2>/dev/null | tail -1)
    if [[ -z "$SNAPSHOT" ]]; then
        echo "ERROR: No snapshots found for $DATASET"
        exit 1
    fi
    echo "    Latest: $SNAPSHOT"
else
    SNAPSHOT="${DATASET}@${SNAPSHOT_ARG}"
    if ! zfs list -t snapshot -o name "$SNAPSHOT" &>/dev/null; then
        echo "ERROR: Snapshot $SNAPSHOT not found"
        echo "Available snapshots:"
        zfs list -t snapshot -o name -s creation "$DATASET" 2>/dev/null || true
        exit 1
    fi
fi

echo "==> Rolling back to: $SNAPSHOT"
zfs rollback -r "$SNAPSHOT"

echo ""
echo "==> Rollback complete. Current state:"
zfs list -o name,used,available,mountpoint "$DATASET"
