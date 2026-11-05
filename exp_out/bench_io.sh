#!/usr/bin/env bash
# bench_io.sh v2 — overhead de E/S: directo sobre ZFS vs a través de Guardian FS
# Datos: base64(urandom) ~40MB — incomprimible para lz4, entropía ~6 bits/byte
# y distribución NO uniforme (χ² alto) → no dispara la firma de cifrado del
# freno global; mide throughput, no comportamiento de bloqueo.
set -u
SRC=/tmp/opencode/bench_src
DIRECT=/mnt/guardian_real/bench
VIA=/mnt/protected/bench
REPS=5

[ -f "$SRC" ] || { head -c 30M /dev/urandom | base64 > "$SRC"; }

timed() { # $1=csv_label  $2...=cmd
    sync; echo 3 > /proc/sys/vm/drop_caches 2>/dev/null
    local t0=$(date +%s%N); "${@:2}"; local t1=$(date +%s%N)
    echo "$1,$(( (t1-t0)/1000000 ))"
}

small_files() { # $1=destino
    python3 - "$1" "$SRC" <<'PYEOF'
import sys, os
dest, src = sys.argv[1], sys.argv[2]
data = open(src, 'rb').read()
for i in range(300):
    off = (i * 65536) % (len(data) - 65536)
    with open(os.path.join(dest, 'f_%03d.txt' % i), 'wb') as f:
        f.write(data[off:off+65536])
PYEOF
}

echo "workload,ruta,rep,ms"
for rep in $(seq 1 $REPS); do
    timed "escritura_grande,directo,$rep" dd if="$SRC" of="$DIRECT/ddfile" bs=1M 2>/dev/null
    timed "escritura_grande,guardian,$rep" dd if="$SRC" of="$VIA/ddfile" bs=1M 2>/dev/null
    timed "archivos_chicos,directo,$rep"   small_files "$DIRECT"
    timed "archivos_chicos,guardian,$rep"  small_files "$VIA"
    timed "lectura,directo,$rep"           cat "$DIRECT/ddfile" > /dev/null
    timed "lectura,guardian,$rep"          cat "$VIA/ddfile" > /dev/null
done
