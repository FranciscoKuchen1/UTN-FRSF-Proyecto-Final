#!/usr/bin/env bash
# watchdog.sh — desatasca la campaña: si un simulador (o sus workers)
# supera los 150 s se considera colgado y se lo mata para avanzar.
while pgrep -f "attack_campaig[n]" >/dev/null 2>&1; do
    for pid in $(pgrep -f "scripts/simulate_ransomwar[e].py"); do
        et=$(ps -o etimes= -p "$pid" 2>/dev/null | tr -d ' ')
        if [ -n "$et" ] && [ "$et" -gt 150 ]; then
            echo "[$(date +%H:%M:%S)] watchdog: sim colgado PID $pid (${et}s)" \
                >> exp_out/watchdog.log
            kill -9 "$pid" 2>/dev/null
        fi
    done
    sleep 10
done
echo "[$(date +%H:%M:%S)] watchdog: campaign terminada" >> exp_out/watchdog.log
