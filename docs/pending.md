# Pendientes — Guardian FS

Lo necesario para una prueba funcional en VM. Actualizado: 2026-11-04.

## Infraestructura

- [x] VM con ZFS (`tank/data`) y `libfuse3-dev`
- [x] Compilar: `cmake -S . -B build && cmake --build build --parallel`
- [x] Montar: `sudo ./scripts/mount.sh /mnt/guardian_real /mnt/protected tank/data`
- [ ] Leer `configs/guardian.conf` en el binario (hoy paths vía env / defaults)
- [ ] Handler SIGTERM/SIGINT para shutdown graceful

## ML

Código base ya existe en `src/` (`ml_server.py`, `train_model.py`, cliente en `analyzer.c`).

- [x] Generar dataset de features (CSV): `scripts/collect_training_data.sh [rounds]` — dos fases (label 1: ataques variados / label 0: workloads benignos), integrado en `test_ml_pipeline.sh`; shadow mode por defecto (ataques completos sin kill) + workers paralelos, cifrado parcial y perfil realista en las rondas de ataque
- [x] Export FUSE/analyzer → CSV de 14 features — `ml_proxy.py` loggea en `data/training_data.csv`; `analyzer.c` las calcula todas
- [x] Entrenar: `python3 src/train_model.py` con `data/training_data.csv` — dataset 1805 muestras (1541 benignas / 264 ataques, 127 sesiones): RF ROC-AUC 1.0000 (CV agrupado y holdout, FPR/FNR 0), XGBoost 0.9997. Modelos en `/var/lib/guardian/models/` y `ml_server` levantado
- [x] Modelos en `/var/lib/guardian/models/` y levantar `python3 src/ml_server.py` antes/junto al mount
- [x] Completar features en `analyzer.c` — 14/14 reales desde 12/09/2026 (std, autocorr, chi2 ≥256B, rw_ratio, ext_change, canary, unique_dirs, file_type_variety)
- [x] Liberar slots de `pid_table` cuando mueren procesos — ventana vencida con <10 writes libera el slot (y warning si la tabla se llena); el detector además acota su tabla a 256 PIDs con expiración por inactividad (30s)

## Testing

- [x] Smoke en VM: `scripts/simulate_ransomware.py --target-dir /mnt/protected` (**solo VM**) — E2E validado: `write_suspicious` (entropía 7.99) → `rename_blocked` → `process_killed` → snapshot de emergencia + confirmación ML (`ML verdict=ATTACK` del analyzer)
- [x] Validar bloqueo por entropía, canaries y snapshot de emergencia — snapshot `guardian_emergency_*` creado por el daemon root; los snapshots programados (`guardian_auto_*`, cada 60s) también verificados
- [ ] Validar freno global: `--workers 4` → eventos `"brake":1` + caída de todos los workers
- [ ] Verificar empíricamente la evasión mmap (`--mmap`): si los writes llegan como `write()` de 4KB (flush de páginas sucias), la entropía se detecta igual; si no llegan, documentar el gap (los canaries O_RDWR y los renames siguen viendo al atacante)
- [x] Validar rollback: `sudo ./scripts/rollback.sh tank/data latest` — OK, RTO ~1s (objetivo < 30s)
- [ ] Integration tests FUSE+ZFS (hoy unitarios en `tests/unit/`; `tests/test_analyzer.c` no está en CMake)
- [ ] Agregación por UID/sesión (hoy el freno global agrega todo el dataset; un umbral por UID reduciría FPs en sistemas multiusuario)
- [ ] FP residual del detector C (no del ML) en enforce: un `rsync` masivo dentro del mount dispara la regla de renames (≥50 con cambio de extensión por ventana, por los temporales `.file.XXXX` → `file`) y sería bloqueado/muerto aunque el ML lo clasifique normal — el ML confirma ataques pero no puede vetar un bloqueo del detector C. Evaluar umbral de rename o whitelist de patrones tmp (`.XXXXXX` sufix)

## Pulido

- [ ] `get_env_or()`: leak menor de startup (daemon long-running)
- [ ] Systemd unit opcional para `guardian_fs` + `ml_server`
