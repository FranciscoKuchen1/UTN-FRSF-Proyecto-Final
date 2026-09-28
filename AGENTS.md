# AGENTS.md — Guardian FS

Proxy de filesystem FUSE (C17) que detecta ransomware por entropía/comportamiento y mitiga con bloqueo + SIGKILL + snapshots ZFS. PoC académica (UTN FRSF 2026). Docs y comentarios mayormente en español.

## Plataforma

- **Target: Ubuntu 24.04 (kernel 6.8+, libfuse3, OpenZFS).** En macOS no se puede compilar el daemon ni correr nada que use FUSE/ZFS/mountpoint. Verificar cambios de C en la VM de lab.
- Los unit tests (`tests/unit/`) solo necesitan C17 + pthread + m (sin FUSE), pero los scripts asumen tools de Linux.
- **Nunca** ejecutar `scripts/simulate_ransomware.py` ni muestras reales fuera de una VM aislada.

## Comandos

```bash
cmake -DCMAKE_BUILD_TYPE=Release -S . -B build && cmake --build build --parallel
./scripts/run_tests.sh                    # configura, compila y corre ctest (tests/unit)
./build/tests/unit/test_entropy           # correr un solo test directamente
cd build && ctest --output-on-failure -R test_detector --test-dir tests/unit   # un test vía ctest
```

- No hay CI, linter ni formatter configurados; `run_tests.sh` es la verificación. Compilación con `-Wall -Wextra` y `_GNU_SOURCE`.
- Cada test es un programa C standalone con macros de aserción propias (ver `docs/testing-guide.md` para deps exactas por módulo y compilación manual con gcc).
- Pila completa ML (build + ml_server + ml_proxy + FUSE + workload): `./scripts/test_ml_pipeline.sh` (usa `quick_test_ml.sh` si ya está compilado).

## Gotchas de build/tests

- `analyzer.c` queda **fuera** de la OBJECT lib `guardian_obj` porque referencia los externs `evbuf`/`detector` definidos en `guardian_fs.c`; `tests/test_analyzer.c` trae sus propios stubs y se compila aparte (sí está registrado en CTest, aunque `docs/pending.md` diga lo contrario — fiarse de `tests/unit/CMakeLists.txt`).
- `configs/guardian.conf` es **referencia, no se lee**: el binario se configura por env (`GUARDIAN_REAL_ROOT`, `GUARDIAN_ZFS_DATASET`, `GUARDIAN_LOG_PATH`, `GUARDIAN_SHADOW_MODE`=log-only sin bloquear) y umbrales hardcodeados (`#define` en `src/guardian_fs.c`).
- En `mitigation`/tests: jamás usar PIDs que queden negativos al castear a `pid_t` (`kill(-1, SIGKILL)` broadcastea).
- `scripts/mount.sh <source_dir> <mountpoint> [dataset]` exige `build/guardian_fs` ya compilado y hace `exec` en foreground (`-f -o allow_other,default_permissions`).

## Pipeline ML (opcional, segunda opinión async)

- Flujo: `analyzer.c` (calcula 14 features por ventana/PID) → Unix socket `/tmp/guardian_ml.sock` → `src/ml_server.py`. `scripts/ml_proxy.py` se interpone para loggear features a `data/training_data.csv`.
- Sin modelos en `/var/lib/guardian/models/`, `ml_server.py` cae a reglas estadísticas y responde igual.
- Entrenar: `python3 src/train_model.py` con CSV etiquetado (`label` 0/1); requiere venv con `python/requirements.txt`. Dataset se genera con `scripts/collect_training_data.sh [rounds]` (todo en `/tmp/guardian_collect_*`).
- CSVs de datos, modelos y logs están gitignoreados — no commitearlos.

## Repo

- Rama de trabajo: `develop` (default en origin).
- Estructura: `src/` (módulos C + Python ML), `include/` (headers), `tests/unit/` (+ `tests/test_analyzer.c`), `scripts/` (ops y testing), `docs/` (guías; `docs/pending.md` = pendientes vivos, puede tener ítems stale).
