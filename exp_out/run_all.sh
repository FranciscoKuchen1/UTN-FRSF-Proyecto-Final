#!/usr/bin/env bash
# run_all.sh — orquestador de la campaña experimental del Informe de Avance 3
# CORRER COMO ROOT. Espera a que el sistema esté quieto (sin unattended-upgrades
# y load < 2.0) y ejecuta en cadena: benchmark E/S → perfiles de ataque →
# escenarios comparativos → campaña de falsos positivos.
set -u
cd /home/vboxuser/UTN-FRSF-Proyecto-Final
LOG=exp_out/campaign.log
: > "$LOG"

echo "[$(date +%H:%M:%S)] esperando sistema quieto..." | tee -a "$LOG"
quieto=0
for i in $(seq 1 60); do           # hasta 30 minutos de espera
    if ! pgrep -f "unattended-upgrade$" >/dev/null 2>&1; then
        load=$(cut -d' ' -f1 /proc/loadavg)
        if awk "BEGIN{exit !($load < 2.0)}"; then quieto=1; break; fi
    fi
    sleep 30
done
if [ "$quieto" = "0" ]; then
    echo "[$(date +%H:%M:%S)] AVISO: timeout de espera, corriendo igual (load $(cut -d' ' -f1 /proc/loadavg))" | tee -a "$LOG"
fi
sleep 20                            # asentamiento

echo "[$(date +%H:%M:%S)] === BENCH E/S ===" | tee -a "$LOG"
bash exp_out/bench_io.sh > exp_out/bench_results.csv 2>>"$LOG"

echo "[$(date +%H:%M:%S)] === PERFILES DE ATAQUE (E2) ===" | tee -a "$LOG"
bash exp_out/attack_campaign.sh >> "$LOG" 2>&1

echo "[$(date +%H:%M:%S)] === ESCENARIOS (E1) ===" | tee -a "$LOG"
bash exp_out/escenarios.sh >> "$LOG" 2>&1

echo "[$(date +%H:%M:%S)] === FALSOS POSITIVOS (E6) ===" | tee -a "$LOG"
bash exp_out/fp_campaign.sh >> "$LOG" 2>&1

echo "[$(date +%H:%M:%S)] CAMPAÑA COMPLETA" | tee -a "$LOG"
