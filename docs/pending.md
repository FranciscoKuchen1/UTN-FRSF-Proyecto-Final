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

- [ ] Generar dataset de features (CSV): ventanas benignas `label=0`; ataques solo para eval
- [ ] Export FUSE/analyzer → CSV de 14 features (hoy no hay exporter)
- [ ] Entrenar: `python3 src/train_model.py` con `data/features_labeled.csv`
- [ ] Modelos en `/var/lib/guardian/models/` y levantar `python3 src/ml_server.py` antes/junto al mount
- [ ] Completar features parciales en `analyzer.c` (varias van en 0.0 hoy: std, autocorr, chi2, etc.)
- [ ] Liberar slots de `pid_table` cuando mueren procesos (tope 128)

## Testing

- [ ] Smoke en VM: `scripts/simulate_ransomware.py --target-dir /mnt/protected` (**solo VM**)
- [ ] Validar bloqueo por entropía, canaries y snapshot de emergencia
- [ ] Validar rollback: `sudo ./scripts/rollback.sh tank/data latest`
- [ ] Integration tests FUSE+ZFS (hoy unitarios en `tests/unit/`; `tests/test_analyzer.c` no está en CMake)

## Pulido

- [ ] `get_env_or()`: leak menor de startup (daemon long-running)
- [ ] Systemd unit opcional para `guardian_fs` + `ml_server`
