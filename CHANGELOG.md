# Changelog

Todos los cambios notables del proyecto se documentan en este archivo.

El formato está basado en [Keep a Changelog](https://keepachangelog.com/es/1.0.0/),
y el proyecto adhiere a [Versionado Semántico](https://semver.org/lang/es/).

Los mensajes de commit siguen [Conventional Commits](https://www.conventionalcommits.org/).

---

## [Unreleased]

### Added
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
