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

- [x] Generar dataset de features (CSV): `scripts/collect_training_data.sh [rounds]` — dos fases (label 1: ataques variados / label 0: workloads benignos), integrado en `test_ml_pipeline.sh`; shadow mode por defecto (ataques completos sin kill) + workers paralelos, cifrado parcial y perfil realista en las rondas de ataque
- [x] Export FUSE/analyzer → CSV de 14 features — `ml_proxy.py` loggea en `data/training_data.csv`; `analyzer.c` las calcula todas
- [ ] Entrenar: `python3 src/train_model.py` con `data/training_data.csv` (recolectar ≥100 rondas por clase primero; evaluación honesta: CV agrupado por sesión, sin SMOTE, scaler por fold — entrenamiento unificado con `RansomwareDetector`)
- [ ] Modelos en `/var/lib/guardian/models/` (requiere sudo) y levantar `python3 src/ml_server.py` antes/junto al mount
- [x] Completar features en `analyzer.c` — 14/14 reales desde 12/09/2026 (std, autocorr, chi2 ≥256B, rw_ratio, ext_change, canary, unique_dirs, file_type_variety)
- [x] Liberar slots de `pid_table` cuando mueren procesos — ventana vencida con <10 writes libera el slot (y warning si la tabla se llena); el detector además acota su tabla a 256 PIDs con expiración por inactividad (30s)

## Testing

- [ ] Smoke en VM: `scripts/simulate_ransomware.py --target-dir /mnt/protected` (**solo VM**)
- [ ] Validar bloqueo por entropía, canaries y snapshot de emergencia
- [ ] Validar freno global: `--workers 4` → eventos `"brake":1` + caída de todos los workers
- [ ] Verificar empíricamente la evasión mmap (`--mmap`): si los writes llegan como `write()` de 4KB (flush de páginas sucias), la entropía se detecta igual; si no llegan, documentar el gap (los canaries O_RDWR y los renames siguen viendo al atacante)
- [ ] Validar rollback: `sudo ./scripts/rollback.sh tank/data latest`
- [ ] Integration tests FUSE+ZFS (hoy unitarios en `tests/unit/`; `tests/test_analyzer.c` no está en CMake)
- [ ] Agregación por UID/sesión (hoy el freno global agrega todo el dataset; un umbral por UID reduciría FPs en sistemas multiusuario)

## Pulido

- [ ] `get_env_or()`: leak menor de startup (daemon long-running)
- [ ] Systemd unit opcional para `guardian_fs` + `ml_server`
