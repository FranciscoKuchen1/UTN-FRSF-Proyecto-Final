#!/usr/bin/env bash
set -euo pipefail

# quick_test_ml.sh — Quick ML pipeline test (assumes project is already built)
# Usage: ./scripts/quick_test_ml.sh [label]
#   label: 1=ransomware (default), 0=benign

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
BUILD_DIR="$PROJECT_ROOT/build"
LOG_DIR="/tmp/guardian_test_logs"
REAL_ROOT="/tmp/guardian_test_real"
MOUNTPOINT="/tmp/guardian_test_mount"
OUTPUT_CSV="$PROJECT_ROOT/data/training_data.csv"
LABEL="${1:-1}"

ML_SERVER_PID=""
ML_PROXY_PID=""
FUSE_PID=""

log_info() { echo -e "${BLUE}[INFO]${NC} $*"; }
log_success() { echo -e "${GREEN}[SUCCESS]${NC} $*"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $*"; }
log_error() { echo -e "${RED}[ERROR]${NC} $*"; }

cleanup() {
    log_info "Cleaning up..."
    [[ -n "$FUSE_PID" ]] && kill "$FUSE_PID" 2>/dev/null
    [[ -n "$ML_PROXY_PID" ]] && kill "$ML_PROXY_PID" 2>/dev/null
    [[ -n "$ML_SERVER_PID" ]] && kill "$ML_SERVER_PID" 2>/dev/null
    
    mountpoint -q "$MOUNTPOINT" 2>/dev/null && fusermount -u "$MOUNTPOINT" 2>/dev/null
    rm -rf "$REAL_ROOT" "$MOUNTPOINT"
    
    log_success "Cleanup complete"
    log_info "Logs preserved in: $LOG_DIR"
}

trap cleanup EXIT

# Check if binary exists
if [[ ! -x "$BUILD_DIR/guardian_fs" ]]; then
    log_error "guardian_fs binary not found at $BUILD_DIR/guardian_fs"
    log_error "Build it first with: cd build && cmake .. && make"
    exit 1
fi

# Setup Python environment
log_info "Setting up Python environment..."
VENV_DIR="$PROJECT_ROOT/.venv"
PYTHON="$VENV_DIR/bin/python"

if [[ ! -d "$VENV_DIR" ]]; then
    log_info "Creating virtual environment..."
    python3 -m venv "$VENV_DIR" || {
        log_error "Failed to create venv. Install python3-venv: sudo apt install python3-venv"
        exit 1
    }
fi

if ! "$PYTHON" -c "import numpy, sklearn, xgboost, joblib" 2>/dev/null; then
    log_info "Installing Python dependencies..."
    "$VENV_DIR/bin/pip" install --quiet numpy scikit-learn xgboost joblib || {
        log_error "Failed to install dependencies"
        exit 1
    }
fi
log_success "Python environment ready"

# Setup
mkdir -p "$REAL_ROOT" "$MOUNTPOINT" "$LOG_DIR"
for i in {1..5}; do echo "Test file $i" > "$REAL_ROOT/test_$i.txt"; done

echo
echo "=========================================="
echo "Guardian FS — Quick ML Test"
echo "=========================================="
echo

# Start components
log_info "Starting ML server..."
"$PYTHON" "$PROJECT_ROOT/src/ml_server.py" > "$LOG_DIR/ml_server.log" 2>&1 &
ML_SERVER_PID=$!
sleep 2

log_info "Starting ML proxy (label: $LABEL)..."
"$PYTHON" "$SCRIPT_DIR/ml_proxy.py" --label "$LABEL" --backend-socket /tmp/guardian_ml.sock --output "$OUTPUT_CSV" > "$LOG_DIR/ml_proxy.log" 2>&1 &
ML_PROXY_PID=$!
sleep 1

log_info "Starting FUSE..."
export GUARDIAN_REAL_ROOT="$REAL_ROOT"
export GUARDIAN_ZFS_DATASET="tank/data"
"$BUILD_DIR/guardian_fs" -f -o allow_other,default_permissions "$MOUNTPOINT" > "$LOG_DIR/fuse.log" 2>&1 &
FUSE_PID=$!
sleep 2

if ! mountpoint -q "$MOUNTPOINT"; then
    log_error "FUSE failed to mount. Check: $LOG_DIR/fuse.log"
    exit 1
fi

# Run simulator or benign workload based on label
if [[ "$LABEL" == "1" ]]; then
    log_info "Running ransomware simulator..."
    "$PYTHON" "$SCRIPT_DIR/simulate_ransomware.py" --target-dir "$MOUNTPOINT" --file-count 50 --no-cleanup
else
    log_info "Running benign workload..."
    # Benign workload: normal file operations (create, read, modify, delete)
    for i in {1..20}; do
        echo "Normal document content $i" > "$MOUNTPOINT/doc_$i.txt"
        cat "$MOUNTPOINT/doc_$i.txt" > /dev/null
        echo "Updated content $i" >> "$MOUNTPOINT/doc_$i.txt"
    done
    log_success "Benign workload completed"
fi

# Wait for processing
log_info "Waiting for analyzer..."
sleep 6

# Results
echo
if [[ -f "$OUTPUT_CSV" ]]; then
    lines=$(wc -l < "$OUTPUT_CSV")
    features=$((lines - 1))
    if [[ $features -gt 0 ]]; then
        log_success "Features logged: $features"
        echo
        head -3 "$OUTPUT_CSV"
    else
        log_warn "CSV exists but no features logged"
        log_info "Check analyzer logs: $LOG_DIR/fuse.log"
    fi
else
    log_error "No CSV file created"
fi

echo
log_info "Logs: $LOG_DIR"
log_success "Test complete!"
