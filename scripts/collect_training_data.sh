#!/usr/bin/env bash
set -euo pipefail

# Logs de ml_server/ml_proxy en tiempo real (ver test_ml_pipeline.sh)
export PYTHONUNBUFFERED=1

# collect_training_data.sh — Recolecta datos de entrenamiento ML etiquetados
# Uso: ./scripts/collect_training_data.sh [rounds]
#   rounds: iteraciones por fase (default: 10)
#   Fase 1 (label 1): simulador con modo/velocidad/workers/cifrado parcial
#                     variados (perfiles calibrados de familias reales)
#   Fase 2 (label 0): workloads benignos (copias, tar, appends, binarios)
#   Proxy por ronda con --tag atk_rN/ben_rN → columna session del CSV:
#   train_model.py evalúa agrupado por sesión (StratifiedGroupKFold, sin
#   leakage de ventanas contiguas entre train y test).
#   Corre en shadow mode por defecto (GUARDIAN_SHADOW_MODE=1): sin kill →
#   cada ataque aporta features de TODAS sus ventanas. Override:
#   GUARDIAN_SHADOW_MODE=0 ./scripts/collect_training_data.sh [rounds]
#   Todo dentro de /tmp/guardian_collect_* — no toca datos reales.

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
    # 15s: con modelos entrenados el server importa sklearn+xgboost y
    # carga los .pkl antes de bindear (~4-5s en VM chica, más bajo carga);
    # con 5s el poll perdía la carrera y abortaba la recolección entera.
    for _ in $(seq 1 30); do
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
    local tag=${2:-s0}
    log_info "Starting ML proxy (label: $label, session: $tag)..."
    rm -f /tmp/guardian_ml_proxy.sock
    "$PYTHON" "$SCRIPT_DIR/ml_proxy.py" \
        --label "$label" \
        --tag "$tag" \
        --backend-socket /tmp/guardian_ml.sock \
        --output "$OUTPUT_CSV" \
        > "$LOG_DIR/collect_ml_proxy_${tag}.log" 2>&1 &
    ML_PROXY_PID=$!
    for _ in {1..10}; do
        if ! kill -0 "$ML_PROXY_PID" 2>/dev/null; then
            log_error "ML proxy died. Check: $LOG_DIR/collect_ml_proxy_${tag}.log"
            cat "$LOG_DIR/collect_ml_proxy_${tag}.log"
            exit 1
        fi
        if [[ -S /tmp/guardian_ml_proxy.sock ]]; then
            log_success "ML proxy started (PID: $ML_PROXY_PID, session: $tag)"
            return 0
        fi
        sleep 0.5
    done
    log_error "ML proxy failed to create socket. Check: $LOG_DIR/collect_ml_proxy_${tag}.log"
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
    # Shadow mode por defecto: registra veredictos SIN bloquear/kill →
    # los ataques generan features de todas sus ventanas (no mueren en
    # la 1ra). Override: GUARDIAN_SHADOW_MODE=0
    export GUARDIAN_SHADOW_MODE="${GUARDIAN_SHADOW_MODE:-1}"
    if [[ "$GUARDIAN_SHADOW_MODE" == "1" ]]; then
        log_info "Shadow mode ON (log-only, sin bloqueos)"
    else
        log_info "Shadow mode OFF (enforce: bloqueo + kill)"
    fi

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

    # Variedad realista: workers paralelos (PIDs propios → dilución del
    # scoring per-PID), cifrado parcial/intermitente y perfil realista
    local workers=$((1 + (r % 4)))              # 1..4 workers
    local partials=(100 100 75 100 50)         # % del archivo cifrado
    local partial="${partials[$((r % 5))]}"

    local args=(--target-dir "$MOUNTPOINT" --mode "$mode"
                --file-count "$count" --pause-ms "$pause"
                --no-cleanup --avoid-canary
                --workers "$workers" --partial-encrypt "$partial")
    if ((r % 4 == 3)); then
        args+=(--no-rename --canary-hunt)
    fi
    if ((r % 2 == 1)); then
        args+=(--realistic)
    fi

    # Proxy por ronda con tag de sesión: las filas de esta ronda quedan
    # agrupadas (StratifiedGroupKFold sin leakage en train_model.py)
    stop_proxy
    start_proxy 1 "atk_r${r}"

    log_info "  Attack round $r/$ROUNDS (mode=$mode, files=$count, pause=${pause}ms, workers=$workers, partial=${partial}%)"
    "$PYTHON" "$SCRIPT_DIR/simulate_ransomware.py" "${args[@]}" \
        > "$LOG_DIR/collect_attack_round$r.log" 2>&1 || true
    # 12s: las ventanas del ataque (incl. workers ya muertos) experan a
    # +5s del último write; 6s las dejaba en la frontera del swap de
    # proxy y se perdían las últimas ventanas de cada ronda.
    sleep 12
}

benign_round() {
    local r=$1
    local wd="$MOUNTPOINT/work_$r"
    log_info "  Benign round $r/$ROUNDS"
    stop_proxy
    start_proxy 0 "ben_r${r}"
    mkdir -p "$wd"

    # Copias y backup (lecturas + escrituras secuenciales de bytes
    # estructurados — texto/ELF, entropía baja-media)
    cp -r "$PROJECT_ROOT/src" "$wd/src" 2>/dev/null || true
    cp -r "$PROJECT_ROOT/docs" "$wd/docs" 2>/dev/null || true
    tar czf "$wd/backup.tar.gz" -C "$PROJECT_ROOT" README.md 2>/dev/null || true
    cp /usr/bin/bash "$wd/bash_copy" 2>/dev/null || true

    # Variedad de workloads benignos (docs/ml-architecture.md §6.3):
    # cada uno corre con PIDs propios → más ventanas/features por ronda
    # y cobertura de los patrones que generan FPs en el detector C.
    local i

    # 1) Compilación: gcc escribe .o/binarios — entropía media-alta,
    #    el clásico "entropía alta ≠ ataque"
    cat > "$wd/hello.c" <<'EOF'
#include <stdio.h>
#include <string.h>
int main(void) {
    char msg[] = "hello guardian";
    for (int i = 0; msg[i]; i++) msg[i] += 1;
    puts(msg);
    return 0;
}
EOF
    gcc -O2 -o "$wd/hello" "$wd/hello.c" 2>/dev/null || true

    # 2) Git: init/add/commit → ráfagas de writes chicos, renames y
    #    unlinks internos en .git (reorganización de archivos, benigna)
    mkdir -p "$wd/repo"
    git -C "$wd/repo" init -q 2>/dev/null || true
    cp "$PROJECT_ROOT/README.md" "$wd/repo/" 2>/dev/null || true
    printf 'lab note round %s\n' "$r" > "$wd/repo/note.txt"
    git -C "$wd/repo" add . 2>/dev/null || true
    git -C "$wd/repo" -c user.email=lab@guardian -c user.name=lab \
        commit -qm "round $r" 2>/dev/null || true

    # 3) rsync: sincronización de directorio (reads+writes balanceados)
    rsync -a --quiet "$wd/src" "$wd/src_mirror" 2>/dev/null || true

    # 4) Appenders tipo apps reales: logs/csv en ráfaga
    for i in $(seq 1 40); do
        echo "$(date +%s%N) INFO processing record $i batch $r" >> "$wd/app.log"
    done
    for i in $(seq 1 20); do
        printf 'id,name,value,note\n%d,item_%d,%d,some text %d\n' "$i" "$i" "$((i * 37))" "$i" >> "$wd/data.csv"
    done

    # 5) Appenders paralelos (PIDs propios → más ventanas por ronda)
    local ap1 ap2
    ( for i in $(seq 1 30); do \
        printf '%s metric_%s=%s\n' "$(date +%s%N)" "$i" "$((RANDOM % 100))" >> "$wd/metrics.log"; \
      done ) & ap1=$!
    ( for i in $(seq 1 30); do \
        printf 'event,%s,type_%s\n' "$i" "$((i % 7))" >> "$wd/events.csv"; \
      done ) & ap2=$!
    wait "$ap1" "$ap2"

    # Lecturas (alimentan read_write_ratio)
    cat "$wd/app.log" > /dev/null 2>&1 || true
    head -5 "$wd/data.csv" > /dev/null 2>&1 || true

    # 6) Compresión/backup de datos POCO comprimibles: entropía ALTA
    #    benigna con muchas escrituras por ventana. Ojo con el input: si
    #    el contenido es repetitivo (p.ej. 40 copies del mismo source),
    #    gzip lo comprime 40:1 y hace 1-2 writes → nunca supera los 10
    #    writes/ventana y la clase no llega al dataset (0 rows benignas
    #    con entropy_mean>7 → FP con bulk writers de media/comprimidos).
    #    base64(urandom) simula copiar/archivar .jpg/.zip/.mp4/backup
    #    ya cifrado: ~3MB que gzip apenas puede comprimir.
    head -c 3145728 /dev/urandom | base64 > "$wd/big_rand.txt" 2>/dev/null || true
    gzip -c "$wd/big_rand.txt" > "$wd/big_rand.gz" 2>/dev/null || true
    tar czf "$wd/backup.tar.gz" -C "$wd" big_rand.txt src docs 2>/dev/null || true
    gzip -c "$wd/app.log" > "$wd/app.log.gz" 2>/dev/null || true

    # 7) Escritores de entropía CONSTANTE benigna (autocorr≈1): en el
    #    dataset original esa firma temporal sólo aparecía en ataques y
    #    el modelo daba FP con procesos que escriben bloques idénticos
    #    (heartbeats, páginas de DB, padding de imágenes). Casos reales
    #    benignos con entropía uniforme en el tiempo:
    "$PYTHON" -c "
import sys, os
wd = sys.argv[1]
data = b'heartbeat ok ' * 298
for i in range(30):
    with open(os.path.join(wd, 'const_%02d.bin' % i), 'wb') as f:
        f.write(data)
" "$wd" 2>/dev/null || true

    # 8) zero-filled (dd): entropía 0 constante — archivos sparse/padding
    dd if=/dev/zero of="$wd/zerofill.bin" bs=64k count=30 2>/dev/null || true

    # 9) Reescritura del mismo archivo con contenido idéntico: alto
    #    write_rate + autocorr 1.0, sin renames ni cambio de extensión
    "$PYTHON" -c "
import sys, os
wd = sys.argv[1]
data = b'x' * 262144
for i in range(20):
    with open(os.path.join(wd, 'rewrite.bin'), 'wb') as f:
        f.write(data)
" "$wd" 2>/dev/null || true

    # 12s: margen para que las ventanas del final de la ronda (experan a
    # +5s del último write) flusheen ANTES del swap de proxy de la ronda
    # siguiente — con 6s quedaban justo en la frontera y se perdían.
    sleep 12
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
    start_fuse

    echo
    log_info "Phase 1/2 — Attack runs (label 1, proxy por ronda con tag)..."
    local r
    for r in $(seq 1 "$ROUNDS"); do
        attack_round "$r"
    done
    local rows_attack
    rows_attack=$(csv_rows)
    log_success "Attack phase done — CSV rows: $rows_attack (+$((rows_attack - rows_before)))"

    echo
    log_info "Phase 2/2 — Benign workloads (label 0, proxy por ronda con tag)..."
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
