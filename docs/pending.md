# Pendientes — Guardian FS

Lo necesario para una prueba funcional en VM. Actualizado: 2026-08-08.

## Infraestructura

- [ ] VM con ZFS (`tank/data`) y `libfuse3-dev`
- [ ] Compilar: `cmake -S . -B build && cmake --build build --parallel`
- [ ] Montar: `sudo ./scripts/mount.sh /mnt/guardian_real /mnt/protected tank/data`
- [ ] Leer `configs/guardian.conf` en el binario (hoy paths vía env / defaults)
- [ ] Handler SIGTERM/SIGINT para shutdown graceful

## ML

Código base ya existe en `src/` (`ml_server.py`, `train_model.py`, cliente en `analyzer.c`).

- [x] Generar dataset de features (CSV): `scripts/collect_training_data.sh [rounds]` — dos fases (label 1: ataques variados / label 0: workloads benignos), integrado en `test_ml_pipeline.sh`
- [x] Export FUSE/analyzer → CSV de 14 features — `ml_proxy.py` loggea en `data/training_data.csv`; `analyzer.c` las calcula todas
- [ ] Entrenar: `python3 src/train_model.py` con `data/training_data.csv` (recolectar ≥100 rondas por clase primero)
- [ ] Modelos en `/var/lib/guardian/models/` (requiere sudo) y levantar `python3 src/ml_server.py` antes/junto al mount
- [x] Completar features en `analyzer.c` — 14/14 reales desde 12/09/2026 (std, autocorr, chi2 ≥256B, rw_ratio, ext_change, canary, unique_dirs, file_type_variety)
- [ ] Liberar slots de `pid_table` cuando mueren procesos (tope 128)

## Testing

- [ ] Smoke en VM: `scripts/simulate_ransomware.py --target-dir /mnt/protected` (**solo VM**)
- [ ] Validar bloqueo por entropía, canaries y snapshot de emergencia
- [ ] Validar rollback: `sudo ./scripts/rollback.sh tank/data latest`
- [ ] Integration tests FUSE+ZFS (hoy unitarios en `tests/unit/`; `tests/test_analyzer.c` no está en CMake)

## Pulido

- [ ] `get_env_or()`: leak menor de startup (daemon long-running)
- [ ] Systemd unit opcional para `guardian_fs` + `ml_server`
