#!/usr/bin/env bash
# attack_campaign.sh (E2) — tasa de detección y pérdida por perfil de ataque
# CORRER COMO ROOT (sudo bash). Modo ENFORCE sobre /mnt/protected.
# Métricas por corrida: wall_ms, exit (137=SIGKILL=detectado),
# .locked (archivos cifrados+renombrados), bytes, eventos de bloqueo/kill.
set -u
cd /home/vboxuser/UTN-FRSF-Proyecto-Final
PY=.venv/bin/python
BASE=/mnt/protected/exp
EVT=/var/log/guardian/events.jsonl
LOG=exp_out/attack_results.csv

# perfil|modo|files|flags_extra
PROFILES=(
  "full|full|40|"
  "fast|fast|40|"
  "stealth|stealth|40|--pause-ms 200"
  "workers4|full|40|--workers 4"
  "partial50|full|40|--partial-encrypt 50"
  "realistic|full|12|--realistic"
)

echo "perfil,rep,wall_ms,exit,locked_files,locked_bytes,blocked_events,killed_events" > "$LOG"

for entry in "${PROFILES[@]}"; do
    IFS='|' read -r prof mode count extra <<< "$entry"
    for rep in 1 2 3; do
        dir="$BASE/${prof}_${rep}"
        rm -rf "$dir"; mkdir -p "$dir"
        ev0=$(wc -l < "$EVT" 2>/dev/null || echo 0)
        t0=$(date +%s%N)
        "$PY" scripts/simulate_ransomware.py \
            --target-dir "$dir" --mode "$mode" --file-count "$count" \
            --no-cleanup --avoid-canary --seed $((42 + rep)) $extra \
            > "exp_out/sim_${prof}_${rep}.log" 2>&1
        st=$?
        t1=$(date +%s%N)
        wall=$(( (t1 - t0) / 1000000 ))
        locked=$(ls "$dir"/*.locked 2>/dev/null | wc -l)
        bytes=$(du -bc "$dir"/*.locked 2>/dev/null | tail -1 | cut -f1)
        [ -z "${bytes:-}" ] && bytes=0
        ev1=$(wc -l < "$EVT" 2>/dev/null || echo 0)
        blocked=$(sed -n "$((ev0 + 1)),${ev1}p" "$EVT" 2>/dev/null | grep -c -E '"event":"(write|rename|unlink)_blocked"' || true)
        killed=$(sed -n "$((ev0 + 1)),${ev1}p" "$EVT" 2>/dev/null | grep -c '"event":"process_killed"' || true)
        echo "$prof,$rep,$wall,$st,$locked,$bytes,$blocked,$killed" | tee -a "$LOG"
        rm -rf "$dir"   # los snapshots retienen los bloques un rato (retención)
    done
done
echo "LISTO attack_campaign"
