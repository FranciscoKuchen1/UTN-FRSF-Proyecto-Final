#!/usr/bin/env bash
set -euo pipefail

# cleanup_test.sh — Cleanup ML pipeline test artifacts
# Usage: ./scripts/cleanup_test.sh

RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info() { echo -e "${BLUE}[INFO]${NC} $*"; }
log_success() { echo -e "${GREEN}[SUCCESS]${NC} $*"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $*"; }

MOUNTPOINT="/tmp/guardian_test_mount"
REAL_ROOT="/tmp/guardian_test_real"
LOG_DIR="/tmp/guardian_test_logs"

# Kill any running guardian processes
log_info "Stopping guardian processes..."
pkill -f "guardian_fs.*$MOUNTPOINT" 2>/dev/null && log_info "Stopped FUSE" || log_warn "No FUSE process found"
pkill -f "ml_proxy.py" 2>/dev/null && log_info "Stopped ml_proxy" || log_warn "No ml_proxy process found"
pkill -f "ml_server.py" 2>/dev/null && log_info "Stopped ml_server" || log_warn "No ml_server process found"

# Unmount FUSE
if mountpoint -q "$MOUNTPOINT" 2>/dev/null; then
    log_info "Unmounting FUSE..."
    fusermount -u "$MOUNTPOINT" 2>/dev/null || true
    sleep 1
    log_success "FUSE unmounted"
else
    log_warn "FUSE not mounted at $MOUNTPOINT"
fi

# Remove test directories
log_info "Removing test directories..."
rm -rf "$REAL_ROOT" "$MOUNTPOINT" "$LOG_DIR"
log_success "Test directories removed"

# Remove sockets
log_info "Removing sockets..."
rm -f /tmp/guardian_ml.sock /tmp/guardian_ml_proxy.sock
log_success "Sockets removed"

echo
log_success "Cleanup complete!"
echo
log_info "To remove training data: rm -f data/training_data.csv"
