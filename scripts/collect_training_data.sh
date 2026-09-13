#!/usr/bin/env bash
set -euo pipefail

# collect_training_data.sh — Recolecta datos de entrenamiento ML etiquetados
# Uso: ./scripts/collect_training_data.sh [rounds]
#   rounds: iteraciones por fase (default: 10)
#   Fase 1 (label 1): simulador de ransomware con parámetros variados
#   Fase 2 (label 0): workloads benignos (copias, tar, appends, binarios)
# Todo dentro de /tmp/guardian_collect_* — no toca datos reales.

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
BUILD_DIR="$PROJECT_ROOT/build"
VENV_DIR="$PROJECT_ROOT/.venv"
PYTHON="$VENV_DIR/bin/python"
LOG_DIR="$PROJECT_ROOT/logs"
REAL_ROOT="/tmp/guardian_collect_real"
MOUNTPOINT="/tmp/guardian_collect_mount"
OUTPUT_CSV="$PROJECT_ROOT/data/training_data.csv"
ROUNDS="${1:-10}"

ML_SERVER_PID=""
ML_PROXY_PID=""
FUSE_PID=""

log_info() { echo -e "${BLUE}[INFO]${NC} $*"; }
log_success() { echo -e "${GREEN}[SUCCESS]${NC} $*"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $*"; }
log_error() { echo -e "${RED}[ERROR]${NC} $*"; }

csv_rows() {
    if [[ -f "$OUTPUT_CSV" ]]; then
        local n
        n=$(wc -l < "$OUTPUT_CSV")
        echo $((n - 1))
    else
        echo 0
    fi
}

cleanup() {
    log_info "Cleaning up..."
    if [[ -n "$FUSE_PID" ]]; then kill "$FUSE_PID" 2>/dev/null || true; FUSE_PID=""; fi
    if [[ -n "$ML_PROXY_PID" ]]; then kill "$ML_PROXY_PID" 2>/dev/null || true; ML_PROXY_PID=""; fi
    if [[ -n "$ML_SERVER_PID" ]]; then kill "$ML_SERVER_PID" 2>/dev/null || true; ML_SERVER_PID=""; fi

    if mountpoint -q "$MOUNTPOINT" 2>/dev/null; then
        fusermount -u "$MOUNTPOINT" 2>/dev/null || true
        sleep 1
    fi

    rm -rf "$REAL_ROOT" "$MOUNTPOINT"
    rm -f /tmp/guardian_ml.sock /tmp/guardian_ml_proxy.sock

    log_success "Cleanup complete"
    log_info "Logs preserved in: $LOG_DIR"
}
trap cleanup EXIT

require_built() {
    if [[ ! -x "$BUILD_DIR/guardian_fs" ]]; then
        log_error "guardian_fs not built. Run ./scripts/test_ml_pipeline.sh once first."
        exit 1
    fi
    if [[ ! -x "$PYTHON" ]]; then
        log_error "venv not found. Run ./scripts/test_ml_pipeline.sh once first."
        exit 1
    fi
}

start_server() {
    log_info "Starting ML server..."
    rm -f /tmp/guardian_ml.sock
    "$PYTHON" "$PROJECT_ROOT/src/ml_server.py" > "$LOG_DIR/collect_ml_server.log" 2>&1 &
    ML_SERVER_PID=$!
    for _ in {1..10}; do
        if ! kill -0 "$ML_SERVER_PID" 2>/dev/null; then
            log_error "ML server died. Check: $LOG_DIR/collect_ml_server.log"
            cat "$LOG_DIR/collect_ml_server.log"
            exit 1
        fi
        if [[ -S /tmp/guardian_ml.sock ]]; then
            log_success "ML server started (PID: $ML_SERVER_PID)"
            return 0
        fi
        sleep 0.5
    done
    log_error "ML server failed to create socket. Check: $LOG_DIR/collect_ml_server.log"
    exit 1
}

start_proxy() {
    local label=$1
    log_info "Starting ML proxy (label: $label)..."
    rm -f /tmp/guardian_ml_proxy.sock
    "$PYTHON" "$SCRIPT_DIR/ml_proxy.py" \
        --label "$label" \
        --backend-socket /tmp/guardian_ml.sock \
        --output "$OUTPUT_CSV" \
        > "$LOG_DIR/collect_ml_proxy_label$label.log" 2>&1 &
    ML_PROXY_PID=$!
    for _ in {1..10}; do
        if ! kill -0 "$ML_PROXY_PID" 2>/dev/null; then
            log_error "ML proxy died. Check: $LOG_DIR/collect_ml_proxy_label$label.log"
            cat "$LOG_DIR/collect_ml_proxy_label$label.log"
            exit 1
        fi
        if [[ -S /tmp/guardian_ml_proxy.sock ]]; then
            log_success "ML proxy started (PID: $ML_PROXY_PID)"
            return 0
        fi
        sleep 0.5
    done
    log_error "ML proxy failed to create socket. Check: $LOG_DIR/collect_ml_proxy_label$label.log"
    exit 1
}

stop_proxy() {
    if [[ -n "$ML_PROXY_PID" ]]; then
        kill "$ML_PROXY_PID" 2>/dev/null || true
        wait "$ML_PROXY_PID" 2>/dev/null || true
        ML_PROXY_PID=""
    fi
    rm -f /tmp/guardian_ml_proxy.sock
}

start_fuse() {
    log_info "Starting FUSE filesystem..."
    export GUARDIAN_REAL_ROOT="$REAL_ROOT"
    export GUARDIAN_ZFS_DATASET="tank/data"

    local FUSE_OPTS="default_permissions"
    if grep -qE '^[[:space:]]*user_allow_other' /etc/fuse.conf 2>/dev/null; then
        FUSE_OPTS="allow_other,default_permissions"
    else
        log_warn "user_allow_other not set in /etc/fuse.conf — mounting without allow_other"
    fi

    "$BUILD_DIR/guardian_fs" -f -o "$FUSE_OPTS" "$MOUNTPOINT" \
        > "$LOG_DIR/collect_fuse.log" 2>&1 &
    FUSE_PID=$!
    for _ in {1..10}; do
        if mountpoint -q "$MOUNTPOINT" 2>/dev/null; then
            log_success "FUSE mounted (PID: $FUSE_PID)"
            return 0
        fi
        sleep 0.5
    done
    log_error "FUSE failed to mount. Check: $LOG_DIR/collect_fuse.log"
    cat "$LOG_DIR/collect_fuse.log"
    exit 1
}

attack_round() {
    local r=$1
    local modes=(full fast stealth)
    local mode="${modes[$((r % 3))]}"
    local count=$((30 + (r * 13) % 50))
    local pause=$(((r % 3) * 20))

    local args=(--target-dir "$MOUNTPOINT" --mode "$mode"
                --file-count "$count" --pause-ms "$pause"
                --no-cleanup --avoid-canary)
    if ((r % 4 == 3)); then
        args+=(--no-rename --canary-hunt)
    fi

    log_info "  Attack round $r/$ROUNDS (mode=$mode, files=$count, pause=${pause}ms)"
    "$PYTHON" "$SCRIPT_DIR/simulate_ransomware.py" "${args[@]}" \
        > "$LOG_DIR/collect_attack_round$r.log" 2>&1 || true
    sleep 6
}

benign_round() {
    local r=$1
    local wd="$MOUNTPOINT/work_$r"
    log_info "  Benign round $r/$ROUNDS"
    mkdir -p "$wd"

    cp -r "$PROJECT_ROOT/src" "$wd/src" 2>/dev/null || true
    cp -r "$PROJECT_ROOT/docs" "$wd/docs" 2>/dev/null || true
    tar czf "$wd/backup.tar.gz" -C "$PROJECT_ROOT" README.md 2>/dev/null || true

    local i
    for i in $(seq 1 40); do
        echo "$(date +%s%N) INFO processing record $i batch $r" >> "$wd/app.log"
    done
    for i in $(seq 1 20); do
        printf 'id,name,value,note\n%d,item_%d,%d,some text %d\n' "$i" "$i" "$((i * 37))" "$i" >> "$wd/data.csv"
    done

    cat "$wd/app.log" > /dev/null 2>&1 || true
    head -5 "$wd/data.csv" > /dev/null 2>&1 || true

    cp /usr/bin/bash "$wd/bash_copy" 2>/dev/null || true
    sleep 6
}

main() {
    echo
    echo "=========================================="
    echo "Guardian FS — Training Data Collection"
    echo "=========================================="
    echo

    require_built
    mkdir -p "$REAL_ROOT" "$MOUNTPOINT" "$LOG_DIR" "$PROJECT_ROOT/data"
    for i in {1..5}; do echo "Seed file $i" > "$REAL_ROOT/seed_$i.txt"; done

    local rows_before
    rows_before=$(csv_rows)
    log_info "CSV rows before: $rows_before ($OUTPUT_CSV)"
    log_info "Rounds per phase: $ROUNDS"

    start_server
    start_proxy 1
    start_fuse

    echo
    log_info "Phase 1/2 — Attack runs (label 1)..."
    local r
    for r in $(seq 1 "$ROUNDS"); do
        attack_round "$r"
    done
    local rows_attack
    rows_attack=$(csv_rows)
    log_success "Attack phase done — CSV rows: $rows_attack (+$((rows_attack - rows_before)))"

    echo
    log_info "Switching proxy to label 0 (analyzer reconnects within ~5s)..."
    stop_proxy
    start_proxy 0
    sleep 6

    log_info "Phase 2/2 — Benign workloads (label 0)..."
    for r in $(seq 1 "$ROUNDS"); do
        benign_round "$r"
    done
    local rows_final
    rows_final=$(csv_rows)
    log_success "Benign phase done — CSV rows: $rows_final (+$((rows_final - rows_attack)))"

    echo
    log_success "Collection complete: $((rows_final - rows_before)) new rows (total: $rows_final)"
    log_info "CSV: $OUTPUT_CSV"
    log_info "Logs: $LOG_DIR"
    echo
}

main
