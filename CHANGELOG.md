# Changelog

Todos los cambios notables del proyecto se documentan en este archivo.

El formato está basado en [Keep a Changelog](https://keepachangelog.com/es/1.0.0/),
y el proyecto adhiere a [Versionado Semántico](https://semver.org/lang/es/).

Los mensajes de commit siguen [Conventional Commits](https://www.conventionalcommits.org/).

---

## [Unreleased]

### Added
- **Freno global anti-evasión multiproceso (detector.c)**: un ransomware que
  forkea N workers diluye el scoring per-PID (cada worker queda bajo todos los
  umbrales). El detector agrega por ventana las escrituras con **firma de
  cifrado** (entropía > umbral **y** χ² < 300 — uniforme; un `.jpg`/`.zip`
  comprimido tiene alta entropía pero χ² alto y no cuenta) de todos los PIDs:
  ≥100 arma el freno y los escritores con firma de cifrado reciben
  `VERDICT_BLOCK` aunque su score individual sea bajo. Un writer benigno de
  baja entropía nunca es bloqueado por el freno. Lo mismo para renames con
  cambio de extensión (≥60/ventana). Los bloqueos se loguean con `"brake":1`
  (`detector_global_brake_armed()`).
- **Señal de caza de backups (análogo Linux del `vssadmin`)**: el `unlink`
  alimenta el score (`detector_check_unlink()`, peso 0.10, umbral 40/ventana).
  Sola no bloquea (`make clean`/`rm -rf` benignos aportan máximo 0.10 < 0.65);
  combinada con cifrado sí (cifrar + borrar los backups originales).
  Pesos recalibrados: entropy 0.35, write 0.20, rename 0.15, chi2 0.20,
  unlink 0.10.
- **Canary entropy-gated (anti-FP de edición del señuelo)**: la señal armada
  por abrir un canary para escritura ahora bloquea solo escrituras con firma
  de cifrado. Antes, un usuario editando el señuelo (baja entropía: autosave,
  temporales del editor) moría con SIGKILL al guardar. El bump directo de
  score (+0.8/+0.5) se eliminó (la regla directa decide, no el score).
- **Anti-FP de canaries por intención de acceso (guardian_fs.c)**: `gfs_open`
  discrimina por `O_ACCMODE` — abrir un canary para **escritura**
  (`O_WRONLY`/`O_RDWR`, comportamiento de ransomware) arma el bloqueo; abrirlo
  **read-only** (tar, `cp -r`, rsync, thumbnailers, AV) solo deja señal leve
  (`detector_note_canary_read`, +0.05/read tope +0.15 por ventana). Antes, un
  `cp -r` dentro del mount que tocaba un canary moría con SIGKILL en su
  primera escritura. `gfs_rename` agrega detección de rename-de-canary con la
  misma discriminación (cambio de extensión → señal fuerte).
- **Verificación de identidad antes del SIGKILL (mitigation.c)**:
  `mitigation_kill_process(pid, expected_starttime)` compara el `starttime`
  actual del PID (campo 22 de `/proc/<pid>/stat`) con el registrado por el
  detector al crear la entrada. Si el PID fue reutilizado → kill omitido
  (`MIT_PID_REUSED`) y el estado envenenado se descarta (`detector_reset_pid`).
  Resultados al log estructurado (`process_killed`/`kill_skipped`). El
  detector registra el starttime de cada PID y expone
  `detector_pid_starttime()`.
- **Snapshot de emergencia asíncrono con dedup + disparo temprano
  (zfs_snap.c, guardian_fs.c)**: `zfs_snapshot_emergency()` ya no ejecuta
  `zfs snapshot` síncrono dentro del handler FUSE (~100-300ms de
  fork+shell+zfs por write bloqueado) — señaliza a un worker thread (µs) con
  cooldown de 10s contra ráfagas. Además se dispara en el primer
  VERDICT_SUSPICIOUS (pre-daño), no solo en el bloqueo, y retiene los últimos
  10 snapshots de emergencia.
- **zfs_snap.c sin shell**: todas las invocaciones de `zfs(8)` van por
  `posix_spawnp` con argv directo (antes `system()`/`popen` con strings
  interpolados → riesgo de inyección + costo de fork+shell).
- **Modo shadow (`GUARDIAN_SHADOW_MODE`) en guardian_fs.c**: registrar veredictos
  BLOCK sin ejecutar la mitigación (sin EPERM, sin SIGKILL, sin snapshot de
  emergencia). Para recolección de datos (los ataques generan features de todas
  sus ventanas, no mueren en la primera) y medición de falsos positivos sin
  riesgo. Los eventos llevan `"mode":"shadow"`; nuevo evento `daemon_start`
  con modo y umbrales (provenance del dataset).
- **Perfiles de realismo en el simulador (scripts/simulate_ransomware.py)**,
  calibrados con comportamiento documentado de familias reales:
  - `--workers N`: procesos paralelos con PID propio → diluye el scoring
    per-PID del detector (evasión real de ransomware multi-proceso).
  - `--partial-encrypt PCT`: cifrado intermitente estilo LockBit (solo los
    primeros PCT% de cada archivo, escritura en chunks de 256KB).
  - `--realistic`: tamaños log-uniformes 16KB–8MB, jitter de pausas, ~5% de
    archivos salteados.
  - `--mmap`: prueba de bypass (mmap no pasa por `write()` → el detector no ve
    entropía). Advertido: no usar para datos de entrenamiento.
  - `--seed N`: corridas reproducibles.
- **`collect_training_data.sh` en shadow mode con rondas variadas**: FUSE
  corre por defecto con `GUARDIAN_SHADOW_MODE=1` (override: `=0`); las rondas
  de ataque varían workers (1–4), % de cifrado parcial (50–100%) y perfil
  realista, generando un dataset de ataques más rico y diverso.
- **Analizador asíncrono (analyzer.c, analyzer.h)**: Hilo dedicado que consume eventos del
  ring buffer, agrega estadísticas por PID en ventanas de 5 segundos y opcionalmente
  consulta un servidor ML via Unix Domain Socket para clasificar procesos como benignos,
  sospechosos o maliciosos.
  - Tabla de agregación per-PID (`pid_table`) con 128 slots y rotación automática de
    ventanas temporales.
  - Conexión persistente con reintento automático al servidor ML (`/tmp/guardian_ml.sock`).
  - Protocolo JSON bidireccional para enviar features y recibir veredictos.
  - Fallback a rotación sin ML cuando el servidor no está disponible.
- **Logging estructurado JSONL (guardian_fs.c)**: Todos los eventos relevantes (escrituras
  bloqueadas, canary accedidos, renombrados bloqueados) se registran en formato JSON Lines
  en `/var/log/guardian/events.jsonl` o la ruta definida por `GUARDIAN_LOG_PATH`.
  - Campos: timestamp con nanosegundos, tipo de evento, PID, ruta y payload JSON adicional.
  - Buffer desactivado (`_IONBF`) para inmediatez en logs de seguridad.
  - Thread-safe mediante mutex dedicado (`log_mutex`).
- **Script simulador de ransomware (scripts/simulate_ransomware.py)**: Herramienta de
  testing que genera patrones de E/S maliciosos sin usar malware real.
  - Soporta modos de ataque: `full` (cifra + renombra), `fast` (alta velocidad),
    `stealth` (bajo volumen con pausas).
  - Generación de datos de alta entropía (`os.urandom`) simulando cifrado real (H ≈ 8.0).
  - Simulación de cambio de extensiones (`.locked`, `.enc`, `.crypt`, `.ransom`,
    `.encrypted`).
  - Modo cacería de canaries (`--canary-hunt`) para probar detección de acceso a archivos
    señuelo.
  - Cleanup automático de archivos de prueba (`--no-cleanup` para inspección).
- **Tests unitarios del analyzer (tests/test_analyzer.c)**: Tests para `get_slot()` y
  lógica de rotación de ventanas.
  - Asignación y reutilización de slots, tabla llena, preservación de identidad.
  - Rotación de ventanas: expirada, activa, doble rotación, borde exacto.
  - Tracking de entropía máxima.

### Changed
- **Script de montaje mejorado (scripts/mount.sh)**: Validación de argumentos, resolución
  de rutas absolutas, unmount automático si ya montado, creación de directorio de logs,
  export de variables de entorno `GUARDIAN_REAL_ROOT` y `GUARDIAN_ZFS_DATASET`.
- **Integración guardian_fs.c con analyzer**: Se crea el hilo analizador en `main()`,
  se exponen `evbuf` y `detector` como variables globales para uso cross-module.
  Los eventos del ring buffer ahora alimentan tanto la detección sincrónica (umbrales)
  como el análisis asíncrono (ML + agregación temporal).
- **Protección contra redefinición de `_GNU_SOURCE`**: Todos los archivos fuente ahora
  usan `#ifndef _GNU_SOURCE` / `#define _GNU_SOURCE` / `#endif` para evitar warnings
  cuando el build system también define la macro (ej. `cmake` con
  `target_compile_definitions`).

### Fixed
- **Leakage en la evaluación ML (train_model.py)**: SMOTE y StandardScaler se
  aplicaban a TODO el dataset antes del CV → ROC-AUC inflado (muestras
  sintéticas derivadas del fold de test dentro del propio fold; estadísticos
  del scaler globales). Ahora: `StratifiedGroupKFold` por **sesión de
  recolección** (las ventanas contiguas de un mismo ataque no se reparten
  entre train y test), scaler dentro del `Pipeline` del fold, y holdout
  agrupado (`GroupShuffleSplit`).
- **SMOTE eliminado**: interpolaba features binarias/count
  (`canary_accessed=0.37` no significa nada). El desbalance se maneja con
  `class_weight="balanced"` (RF) + `scale_pos_weight` (XGBoost) — ya estaba.
  `imbalanced-learn` sale de `python/requirements.txt`.
- **LSTM sin entrenar con peso en el ensemble (ml_server.py)**: con torch
  instalado se construía una LSTM con pesos ALEATORIOS y participaba del
  ensemble con peso 0.15 → ruido. Ahora solo se usa si existe un checkpoint
  entrenado (`/var/lib/guardian/models/lstm.pt`). El ensemble renormaliza los
  pesos con los modelos realmente disponibles (un peso muerto sesga el umbral).
- **Entrenamiento unificado con inferencia (train_model.py)**: `train_model.py`
  entrenaba con hiperparámetros duplicados respecto de `RansomwareDetector`
  (dos rutas divergentes). Ahora importa y entrena la misma clase que sirve
  inferencia — lo evaluado es lo desplegado — y guarda los 4 artefactos.
- **Columna `session` en el CSV (ml_proxy.py)**: nuevo flag `--tag` (ronda de
  recolección) escrito como columna `session`; `collect_training_data.sh`
  reinicia el proxy por ronda con tags `atk_rN`/`ben_rN`. CSVs viejos: la
  sesión se deriva por gaps de timestamp (con aviso).
- **Veredicto ML sin poder de bloqueo**: `detector_confirm_attack()` seteaba
  `attack_confirmed` pero ninguna ruta de decisión lo leía — la "segunda opinión"
  ML era puramente decorativa. Ahora `detector_check_write()` y
  `detector_check_rename()` devuelven `VERDICT_BLOCK` directo para PIDs con
  ataque confirmado.
- **χ² síncrono muerto**: `pid_state_t.byte_hist[256]` se limpiaba y leía pero
  nunca se llenaba, así que el 20% del score era siempre 0 (y sin él, un ataque
  de solo-entropía sin renames/canary jamás alcanzaba el umbral de bloqueo:
  score máx 0.617 < 0.65). Se reemplaza el histograma acumulado por
  `chi2_sum`/`chi2_samples` (χ² por escritura con muestra válida, pasada desde
  `gfs_write`). Pesos recalibrados: entropy 0.40, write 0.20, rename 0.15,
  chi2 0.25. El término de ratio lectura/escritura se quitó del score síncrono
  (los `EV_READ` no llegan al detector; esa señal vive en las features ML async).
- **`ml_server.py` crasheaba tras entrenar**: `train_model.py` no guardaba
  `iso_forest.pkl` pero `load()` lo exigía → `FileNotFoundError` al iniciar.
  Ahora `train_model.py` entrena y guarda el Isolation Forest, y `load()` es
  defensivo (sin el archivo, sigue sin él y redistribuye el peso del ensemble).
- **Tabla de 128 slots del analyzer se llenaba para siempre**: `reset_window()`
  mantenía `active=1`, así que tras 128 PIDs distintos las features ML se
  perdían en silencio (incluido un atacante nuevo). Ahora las ventanas vencidas
  con <10 writes liberan el slot, y se loguea cuando la tabla está llena.
- **Tabla PID del detector sin acotar**: crecía por siempre (~2.3KB/PID por el
  histograma) y el estado (p.ej. `canary_triggered`) sobrevivía al reuso de
  PIDs → riesgo de matar a un inocente. Tope de 256 entradas, barrido de
  inactivos (>30s sin eventos) y reciclado de la entrada más vieja si persiste
  la presión. Con el histograma eliminado, cada entrada pesa ~120 bytes.
- **`canary_deploy(ctx, 20)` desplegaba solo 7**: el loop cortaba en
  `N_CANARY_NAMES` y todo quedaba en la raíz. Ahora despliega la cantidad
  pedida, con sufijos `_N` para nombres únicos y distribuyendo entre la raíz
  y los subdirectorios `docs/`, `finanzas/`, `backup/` (como ya prometía el
  comentario de estrategia). Tests actualizados al layout nuevo.
- **Dead code en reconexión ML del analyzer**: `ring_buf_pop()` es bloqueante vía
  `pthread_cond_wait` y siempre retorna 0, haciendo que la lógica de reconexión al
  servidor ML nunca se ejecutara. Se agregó `ring_buf_try_pop()` no bloqueante (retorna -1
  con buffer vacío) y se actualizó `analyzer_thread()` para usarla, permitiendo que el
  hilo analizador reintente la conexión ML cada 5 segundos mientras no haya eventos.
- **Warning de parámetro no usado**: `gfs_readdir()` ahora castea `fi` a `(void)`.
- **Inclusión explícita de `<stdint.h>` en analyzer.c**: Aunque los tipos `uint32_t`/
  `uint64_t` ya estaban disponibles via headers transitivos, se agregó la inclusión
  directa para robustez.

---

## [0.1.0] — 2026-01-01

### Added
- Inicialización del proyecto
- Definición de arquitectura FUSE + ZFS
- Configuración de herramientas de desarrollo

[Unreleased]: https://github.com/UTN-FRSF/UTN-FRSF-Proyecto-Final/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/UTN-FRSF/UTN-FRSF-Proyecto-Final/releases/tag/v0.1.0
