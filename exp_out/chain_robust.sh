#!/usr/bin/env bash
set -u
cd /home/vboxuser/UTN-FRSF-Proyecto-Final
echo "[$(date +%H:%M:%S)] === PERFILES (E2) ==="
bash exp_out/attack_campaign.sh 2>&1
echo "[$(date +%H:%M:%S)] === ESCENARIOS (E1) ==="
bash exp_out/escenarios.sh 2>&1
echo "[$(date +%H:%M:%S)] === FP (E6) ==="
bash exp_out/fp_campaign.sh 2>&1
echo "[$(date +%H:%M:%S)] CHAIN ROBUSTA COMPLETA"
