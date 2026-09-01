#!/usr/bin/env bash
set -euo pipefail

# test_ml_pipeline.sh — Automated ML feature logging test
# Runs the complete pipeline: ml_server -> ml_proxy -> FUSE -> simulator

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
BUILD_DIR="$PROJECT_ROOT/build"
LOG_DIR="/tmp/guardian_test_logs"
REAL_ROOT="/tmp/guardian_test_real"
MOUNTPOINT="/tmp/guardian_test_mount"
OUTPUT_CSV="$PROJECT_ROOT/data/training_data.csv"
LABEL="${1:-1}"  # Default: ransomware (1)

# PIDs for cleanup
ML_SERVER_PID=""
ML_PROXY_PID=""
FUSE_PID=""

# ── Helper functions ──
log_info() { echo -e "${BLUE}[INFO]${NC} $*"; }
log_success() { echo -e "${GREEN}[SUCCESS]${NC} $*"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $*"; }
log_error() { echo -e "${RED}[ERROR]${NC} $*"; }

cleanup() {
    log_info "Cleaning up..."
    
    # Kill background processes
    [[ -n "$FUSE_PID" ]] && kill "$FUSE_PID" 2>/dev/null && log_info "Stopped FUSE (PID: $FUSE_PID)"
    [[ -n "$ML_PROXY_PID" ]] && kill "$ML_PROXY_PID" 2>/dev/null && log_info "Stopped ml_proxy (PID: $ML_PROXY_PID)"
    [[ -n "$ML_SERVER_PID" ]] && kill "$ML_SERVER_PID" 2>/dev/null && log_info "Stopped ml_server (PID: $ML_SERVER_PID)"
    
    # Unmount FUSE
    if mountpoint -q "$MOUNTPOINT" 2>/dev/null; then
        fusermount -u "$MOUNTPOINT" 2>/dev/null || true
        sleep 1
    fi
    
    # Remove test directories (but keep logs for debugging)
    rm -rf "$REAL_ROOT" "$MOUNTPOINT"
    
    log_success "Cleanup complete"
    log_info "Logs preserved in: $LOG_DIR"
}

trap cleanup EXIT

check_requirements() {
    log_info "Checking system requirements..."
    
    # Check Python 3
    if ! command -v python3 &> /dev/null; then
        log_error "python3 not found. Install with: sudo apt install python3"
        exit 1
    fi
    
    # Check Python packages
    if ! python3 -c "import numpy, sklearn, xgboost, joblib" 2>/dev/null; then
        log_warn "Missing Python packages. Install with:"
        echo "  pip3 install numpy scikit-learn xgboost joblib"
        exit 1
    fi
    
    # Check FUSE
    if ! command -v fusermount3 &> /dev/null; then
        log_error "FUSE3 not found. Install with: sudo apt install libfuse3-dev"
        exit 1
    fi
    
    # Check cmake and build tools
    if ! command -v cmake &> /dev/null || ! command -v gcc &> /dev/null; then
        log_error "Build tools not found. Install with: sudo apt install cmake build-essential"
        exit 1
    fi
    
    log_success "All requirements met"
}

build_project() {
    log_info "Building project..."
    
    mkdir -p "$BUILD_DIR"
    cd "$BUILD_DIR"
    
    if cmake .. && make -j$(nproc); then
        log_success "Build successful"
    else
        log_error "Build failed"
        exit 1
    fi
    
    cd "$PROJECT_ROOT"
}

prepare_directories() {
    log_info "Preparing test directories..."
    
    mkdir -p "$REAL_ROOT" "$MOUNTPOINT" "$LOG_DIR"
    
    # Create some test files in real root
    for i in {1..10}; do
        echo "Test file $i content" > "$REAL_ROOT/test_file_$i.txt"
    done
    
    log_success "Directories prepared"
}

start_ml_server() {
    log_info "Starting ML server..."
    
    python3 "$PROJECT_ROOT/src/ml_server.py" > "$LOG_DIR/ml_server.log" 2>&1 &
    ML_SERVER_PID=$!
    
    # Wait for socket to be created
    for i in {1..10}; do
        if [[ -S /tmp/guardian_ml.sock ]]; then
            log_success "ML server started (PID: $ML_SERVER_PID)"
            return 0
        fi
        sleep 0.5
    done
    
    log_error "ML server failed to start. Check: $LOG_DIR/ml_server.log"
    cat "$LOG_DIR/ml_server.log"
    exit 1
}

start_ml_proxy() {
    log_info "Starting ML proxy (label: $LABEL)..."
    
    python3 "$SCRIPT_DIR/ml_proxy.py" \
        --label "$LABEL" \
        --backend-socket /tmp/guardian_ml.sock \
        --output "$OUTPUT_CSV" \
        > "$LOG_DIR/ml_proxy.log" 2>&1 &
    ML_PROXY_PID=$!
    
    # Wait for socket to be created
    for i in {1..10}; do
        if [[ -S /tmp/guardian_ml_proxy.sock ]]; then
            log_success "ML proxy started (PID: $ML_PROXY_PID)"
            return 0
        fi
        sleep 0.5
    done
    
    log_error "ML proxy failed to start. Check: $LOG_DIR/ml_proxy.log"
    cat "$LOG_DIR/ml_proxy.log"
    exit 1
}

start_fuse() {
    log_info "Starting FUSE filesystem..."
    
    export GUARDIAN_REAL_ROOT="$REAL_ROOT"
    export GUARDIAN_ZFS_DATASET="tank/data"
    
    "$BUILD_DIR/guardian_fs" -f -o allow_other,default_permissions "$MOUNTPOINT" \
        > "$LOG_DIR/fuse.log" 2>&1 &
    FUSE_PID=$!
    
    # Wait for mountpoint to be ready
    for i in {1..10}; do
        if mountpoint -q "$MOUNTPOINT" 2>/dev/null; then
            log_success "FUSE mounted (PID: $FUSE_PID)"
            return 0
        fi
        sleep 0.5
    done
    
    log_error "FUSE failed to mount. Check: $LOG_DIR/fuse.log"
    cat "$LOG_DIR/fuse.log"
    exit 1
}

run_simulator() {
    if [[ "$LABEL" == "1" ]]; then
        log_info "Running ransomware simulator..."
        log_info "Target: $MOUNTPOINT (FUSE mountpoint)"
        log_info "File count: 50"
        echo
        
        python3 "$SCRIPT_DIR/simulate_ransomware.py" \
            --target-dir "$MOUNTPOINT" \
            --file-count 50 \
            --no-cleanup
        
        log_success "Simulator completed"
    else
        log_info "Running benign workload..."
        log_info "Target: $MOUNTPOINT (FUSE mountpoint)"
        echo
        
        # Benign workload: normal file operations
        for i in {1..20}; do
            echo "Normal document content $i" > "$MOUNTPOINT/doc_$i.txt"
            cat "$MOUNTPOINT/doc_$i.txt" > /dev/null
            echo "Updated content $i" >> "$MOUNTPOINT/doc_$i.txt"
        done
        
        log_success "Benign workload completed"
    fi
}

verify_results() {
    log_info "Verifying results..."
    echo
    
    # Check CSV file
    if [[ -f "$OUTPUT_CSV" ]]; then
        local lines=$(wc -l < "$OUTPUT_CSV")
        local features=$((lines - 1))  # Subtract header
        
        if [[ $features -gt 0 ]]; then
            log_success "Features logged: $features"
            echo
            log_info "First 5 lines of $OUTPUT_CSV:"
            head -5 "$OUTPUT_CSV"
        else
            log_warn "CSV exists but contains no features (only header)"
        fi
    else
        log_error "CSV file not found: $OUTPUT_CSV"
    fi
    
    echo
    log_info "Logs available in: $LOG_DIR"
    log_info "ML server log: $LOG_DIR/ml_server.log"
    log_info "ML proxy log: $LOG_DIR/ml_proxy.log"
    log_info "FUSE log: $LOG_DIR/fuse.log"
}

# ── Main execution ──
main() {
    echo
    echo "=========================================="
    echo "Guardian FS — ML Pipeline Test"
    echo "=========================================="
    echo
    
    check_requirements
    build_project
    prepare_directories
    start_ml_server
    start_ml_proxy
    start_fuse
    run_simulator
    
    # Give analyzer time to process events
    log_info "Waiting for analyzer to process events..."
    sleep 6
    
    verify_results
    
    echo
    log_success "Test completed successfully!"
    echo
}

main
