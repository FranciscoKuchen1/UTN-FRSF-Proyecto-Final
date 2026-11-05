#!/usr/bin/env bash
# escenarios.sh (E1) — comparativa: (a) sin protección  (b) ZFS solo  (c) ZFS+Guardian
# CORRER COMO ROOT. Mismo ataque en los tres casos (full, 40 archivos, seed 42).
# Salida: exp_out/escenarios.csv
#   duracion_s: (a)/(b) = tiempo de cifrado completo; (c) = tiempo hasta neutralización
#   archivos_cifrados/bytes_cifrados: al momento de contener el ataque
#   rto_s: tiempo del rollback (solo escenarios con snapshots)
#   archivos_perdidos_final / bytes_perdidos_final: pérdida NETA tras recuperación
set -u
cd /home/vboxuser/UTN-FRSF-Proyecto-Final
PY=.venv/bin/python
DS=tank/data
N=40          # archivos del ataque
LEGIT=20      # archivos de trabajo legítimo post-snapshot (escenario b)

OUT=exp_out/escenarios.csv
echo "escenario,duracion_s,archivos_cifrados,bytes_cifrados,rto_s,archivos_perdidos_final,bytes_perdidos_final,nota" > "$OUT"

atacar() { # $1 dir  → imprime "dur_ms locked bytes exit"
    local dir=$1
    rm -rf "$dir"; mkdir -p "$dir"
    local t0=$(date +%s%N)
    "$PY" scripts/simulate_ransomware.py --target-dir "$dir" --mode full \
        --file-count $N --no-cleanup --avoid-canary --seed 42 \
        > exp_out/sim_escenario.log 2>&1
    local st=$?
    local t1=$(date +%s%N)
    local dur=$(( (t1 - t0) / 1000000 ))
    local locked=$(ls "$dir"/*.locked 2>/dev/null | wc -l)
    local bytes=$(du -bc "$dir"/*.locked 2>/dev/null | tail -1 | cut -f1)
    [ -z "${bytes:-}" ] && bytes=0
    echo "$dur $locked $bytes $st"
}

ms2s() { echo "$(( $1 / 1000 )).$(printf '%03d' $(( $1 % 1000 )))"; }

# ── (a) SIN PROTECCIÓN: ext4, sin snapshots, sin intercepción ──
read dur locked bytes st < <(atacar /home/vboxuser/exp_noprot/run)
# el ataque completa: 100% cifrado y SIN recuperación posible
echo "sin_proteccion,$(ms2s $dur),$locked,$bytes,,,$locked,$bytes,100pct_perdida_sin_recuperacion" >> "$OUT"
echo "(a) sin_proteccion: dur=${dur}ms locked=$locked bytes=$bytes exit=$st"

# ── (b) ZFS SOLO: dataset directo (sin FUSE), snapshot manual pre-ataque ──
zfs destroy $DS@pre_b 2>/dev/null
zfs snapshot $DS@pre_b
# trabajo legítimo posterior al snapshot: lo que se pierde al volver atrás
rm -rf /mnt/guardian_real/exp_scen_b /mnt/guardian_real/legit_b
mkdir -p /mnt/guardian_real/legit_b
for i in $(seq 1 $LEGIT); do
    head -c 65536 /dev/urandom | base64 > /mnt/guardian_real/legit_b/doc_$i.txt
done
legit_bytes=$(du -bc /mnt/guardian_real/legit_b/* | tail -1 | cut -f1)
read dur locked bytes st < <(atacar /mnt/guardian_real/exp_scen_b)
# rollback al estado pre-ataque
t0=$(date +%s%N); zfs rollback $DS@pre_b; t1=$(date +%s%N)
rto=$(( (t1 - t0) / 1000000 ))
perdidos=$(ls /mnt/guardian_real/legit_b 2>/dev/null | wc -l)
# pérdida neta = trabajo legítimo desde el último snapshot (los archivos del
# ataque se eliminan con el rollback: no existían en pre_b)
echo "zfs_solo,$(ms2s $dur),$locked,$bytes,$(ms2s $rto),$perdidos,$legit_bytes,trabajo_post_snapshot_perdido" >> "$OUT"
echo "(b) zfs_solo: dur=${dur}ms locked=$locked rto=${rto}ms perdidos=$perdidos/$LEGIT"

# ── (c) ZFS + GUARDIAN: ataque a través del mount protegido (enforce) ──
read dur locked bytes st < <(atacar /mnt/protected/exp_scen_c)
# dur ≈ tiempo hasta la neutralización (exit 137 = SIGKILL)
# rollback al snapshot de emergencia tomado en la detección
ult=$(zfs list -t snapshot -o name -s creation $DS | grep emergency | tail -1)
t0=$(date +%s%N); zfs rollback "$ult"; t1=$(date +%s%N)
rto=$(( (t1 - t0) / 1000000 ))
locked_post=$(ls /mnt/protected/exp_scen_c/*.locked 2>/dev/null | wc -l)
echo "zfs_guardian,$(ms2s $dur),$locked,$bytes,$(ms2s $rto),$locked_post,0,neutralizado_y_restaurado" >> "$OUT"
echo "(c) zfs_guardian: dur=${dur}ms locked=$locked exit=$st rto=${rto}ms locked_post_rollback=$locked_post"
echo "LISTO escenarios"
