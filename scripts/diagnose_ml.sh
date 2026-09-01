#!/usr/bin/env bash
set -euo pipefail

# diagnose_ml.sh — Diagnose ML pipeline issues
# Usage: ./scripts/diagnose_ml.sh

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

log_info() { echo -e "${BLUE}[INFO]${NC} $*"; }
log_success() { echo -e "${GREEN}[OK]${NC} $*"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $*"; }
log_error() { echo -e "${RED}[ERROR]${NC} $*"; }

echo
echo "=========================================="
echo "Guardian FS — ML Pipeline Diagnostic"
echo "=========================================="
echo

# Check Python
log_info "Checking Python..."
if command -v python3 &> /dev/null; then
    log_success "python3 found: $(python3 --version)"
else
    log_error "python3 not found"
    exit 1
fi

# Check venv
log_info "Checking virtual environment..."
VENV_DIR="$PROJECT_ROOT/.venv"
if [[ -d "$VENV_DIR" ]]; then
    log_success "Venv exists: $VENV_DIR"
    PYTHON="$VENV_DIR/bin/python"
else
    log_warn "Venv not found. Creating..."
    python3 -m venv "$VENV_DIR" || {
        log_error "Failed to create venv. Install: sudo apt install python3-venv"
        exit 1
    }
    PYTHON="$VENV_DIR/bin/python"
fi

# Check dependencies
log_info "Checking Python dependencies..."
if "$PYTHON" -c "import numpy, sklearn, xgboost, joblib" 2>/dev/null; then
    log_success "All dependencies installed"
else
    log_warn "Installing dependencies..."
    "$VENV_DIR/bin/pip" install --quiet numpy scikit-learn xgboost joblib || {
        log_error "Failed to install dependencies"
        exit 1
    }
    log_success "Dependencies installed"
fi

# Test ml_server.py
log_info "Testing ml_server.py..."
rm -f /tmp/guardian_ml.sock /tmp/guardian_ml_proxy.sock

"$PYTHON" "$PROJECT_ROOT/src/ml_server.py" > /tmp/test_ml_server.log 2>&1 &
SERVER_PID=$!
sleep 2

if ! kill -0 "$SERVER_PID" 2>/dev/null; then
    log_error "ml_server.py died immediately"
    log_info "Output:"
    cat /tmp/test_ml_server.log
    exit 1
fi

if [[ -S /tmp/guardian_ml.sock ]]; then
    log_success "ml_server.py running (PID: $SERVER_PID)"
else
    log_error "ml_server.py socket not created"
    log_info "Output:"
    cat /tmp/test_ml_server.log
    kill "$SERVER_PID" 2>/dev/null || true
    exit 1
fi

# Test ml_proxy.py
log_info "Testing ml_proxy.py..."
"$PYTHON" "$SCRIPT_DIR/ml_proxy.py" --label 1 --backend-socket /tmp/guardian_ml.sock --output /tmp/test_diag.csv > /tmp/test_ml_proxy.log 2>&1 &
PROXY_PID=$!
sleep 2

if ! kill -0 "$PROXY_PID" 2>/dev/null; then
    log_error "ml_proxy.py died immediately"
    log_info "Output:"
    cat /tmp/test_ml_proxy.log
    kill "$SERVER_PID" 2>/dev/null || true
    exit 1
fi

if [[ -S /tmp/guardian_ml_proxy.sock ]]; then
    log_success "ml_proxy.py running (PID: $PROXY_PID)"
else
    log_error "ml_proxy.py socket not created"
    log_info "Output:"
    cat /tmp/test_ml_proxy.log
    kill "$SERVER_PID" "$PROXY_PID" 2>/dev/null || true
    exit 1
fi

# Test feature logging
log_info "Testing feature logging..."
"$PYTHON" -c "
import socket, json
sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
sock.connect('/tmp/guardian_ml_proxy.sock')
data = {'pid': 1234, 'features': {'entropy_mean': 7.5, 'entropy_max': 8.0, 'entropy_std': 0.5, 'entropy_autocorr': 0.1, 'write_rate': 50.0, 'bytes_written_rate': 10000.0, 'rename_rate': 20.0, 'unlink_rate': 5.0, 'read_write_ratio': 0.3, 'chi2_stat': 100.0, 'ext_change_rate': 0.8, 'canary_accessed': 1, 'unique_dirs': 5, 'file_type_variety': 3}}
sock.sendall((json.dumps(data) + '\n').encode())
response = sock.recv(4096).decode()
sock.close()
print('Response:', response[:50])
" 2>&1 || {
    log_error "Failed to send test feature"
    kill "$SERVER_PID" "$PROXY_PID" 2>/dev/null || true
    exit 1
}

sleep 1

if [[ -f /tmp/test_diag.csv ]]; then
    lines=$(wc -l < /tmp/test_diag.csv)
    if [[ $lines -gt 1 ]]; then
        log_success "Feature logged successfully ($((lines - 1)) features)"
    else
        log_error "CSV exists but no features logged"
    fi
else
    log_error "CSV not created"
fi

# Cleanup
kill "$SERVER_PID" "$PROXY_PID" 2>/dev/null || true
rm -f /tmp/guardian_ml*.sock /tmp/test_diag.csv /tmp/test_ml_*.log

echo
log_success "Diagnostic complete!"
echo
