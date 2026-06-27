# Guardian FS — Guía para Desarrolladores y Dirección

> Proyecto Final UTN FRSF 2026  
> Gómez Enrico, Ivo · Kuchen, Francisco  
> Director: Dr. Pablo Pessolani · Codirector: Ing. David Harispe  
> Versión: v0.2.0-dev | Junio 2026

---

## Índice

1. [El Problema](#1-el-problema)
2. [Nuestra Solución — Visión General](#2-nuestra-solución--visión-general)
3. [Arquitectura: Cómo se Conecta Todo](#3-arquitectura-cómo-se-conecta-todo)
4. [Módulo por Módulo](#4-módulo-por-módulo)
   - [4.1 guardian_fs.c — El Proxy FUSE](#41-guardian_fsc--el-proxy-fuse)
   - [4.2 entropy.c — Análisis Estadístico de Bytes](#42-entropyc--análisis-estadístico-de-bytes)
   - [4.3 detector.c — Motor de Scoring por Comportamiento](#43-detectorc--motor-de-scoring-por-comportamiento)
   - [4.4 canary.c — Archivos Señuelo](#44-canaryc--archivos-señuelo)
   - [4.5 zfs_snap.c — Recuperación vía Snapshots ZFS](#45-zfs_snapc--recuperación-vía-snapshots-zfs)
   - [4.6 ring_buffer.c — Buffer Circular Thread-Safe](#46-ring_bufferc--buffer-circular-thread-safe)
   - [4.7 mitigation.c — Terminación del Proceso Atacante](#47-mitigationc--terminación-del-proceso-atacante)
   - [4.8 analyzer.c — Hilo de Análisis Asíncrono](#48-analyzerc--hilo-de-análisis-asíncrono)
5. [Flujo de Datos — El Camino Completo](#5-flujo-de-datos--el-camino-completo)
6. [Build, Test y Deploy](#6-build-test-y-deploy)
7. [Decisiones de Diseño y Trade-offs](#7-decisiones-de-diseño-y-trade-offs)
8. [Trabajo Pendiente](#8-trabajo-pendiente)

---

## 1. El Problema

### ¿Qué hace el ransomware?

Un ransomware cifrador opera en tres fases:

1. **Enumera** archivos del filesystem (orden alfabético, por extensión, o recursivo).
2. **Lee** cada archivo y **escribe** una versión cifrada con alta entropía.
3. **Renombra** — cambia `.docx` → `.docx.locked`, `.pdf` → `.pdf.enc`.

La escritura de datos cifrados es la **huella digital inconfundible**: los bytes cifrados tienen entropía cercana a 8.0 bits/byte (el máximo teórico) y una distribución estadísticamente uniforme (test χ² bajo). Ningún archivo legítimo —ni siquiera un `.zip` o `.jpg`— alcanza sistemáticamente 7.8+ de entropía en escrituras consecutivas.

### ¿Por qué los antivirus tradicionales fallan?

| Técnica tradicional | Por qué falla contra ransomware moderno |
|---|---|
| **Firma de archivo** (hash del binario) | El ransomware muta su binario (polimorfismo). |
| **Heurísticas de proceso** (API calls) | El ransomware moderno ofusca sus llamadas al sistema. |
| **Análisis post-ejecución** | Cuando se detecta, los archivos ya están cifrados. |
| **Backups periódicos** | El ransomware moderno también cifra las copias de seguridad. |

La única ventana de detección efectiva es **en tiempo real, durante la syscall de escritura**, antes de que los bytes cifrados toquen el disco.

---

## 2. Nuestra Solución — Visión General

Guardian FS es un **proxy de filesystem transparente** que se interpone entre las aplicaciones y el almacenamiento real. Cada syscall de escritura pasa por nuestro código **antes** de llegar al disco:

```
Aplicación → write() → [GUARDIAN FS] → ¿bloquear o permitir? → Disco ZFS
```

Cuando detecta comportamiento de ransomware, Guardian FS:
1. **Bloquea** la escritura (el ransomware recibe `-EPERM`).
2. **Toma un snapshot ZFS** del estado previo al ataque.
3. **Mata** el proceso atacante con `SIGKILL`.

**Ventajas de resolverlo así:**

| Ventaja | Explicación |
|---|---|
| **Detección en tiempo real** | La decisión se toma dentro de la misma syscall, antes del write real. Latencia < 1ms. |
| **Independiente del binario** | No importa qué ransomware es — detectamos el **comportamiento**, no la firma. |
| **Recuperación instantánea** | Snapshots ZFS CoW: rollback en O(1) a metadatos. |
| **Zero trust en el usuario** | No depende de que el usuario no abra adjuntos. La protección es sistémica. |
| **Defensa en profundidad** | 3 capas: canary → scoring estadístico → ML ensemble. |
| **Sin falsos positivos catastróficos** | El "bloqueo" es `EPERM`, no pérdida de datos; hay snapshot de respaldo. |

---

## 3. Arquitectura: Cómo se Conecta Todo

```
Aplicación (usuario o ransomware)
        │
        │ syscall: write(path, buf, size)
        ▼
┌───────────────────────────────────────────────────┐
│              guardian_fs.c (FUSE proxy)            │
│                                                    │
│  gfs_write() {                                     │
│    1. entropy_shannon(buf)           ← entropy.c   │
│    2. ring_buf_push(ev)              ← ring_buffer │
│    3. detector_check_write(...)      ← detector.c  │
│       │                                            │
│       ├─ VERDICT_BLOCK:                            │
│       │   ├─ zfs_snapshot_emergency() ← zfs_snap.c │
│       │   ├─ mitigation_kill_process() ← mitigation│
│       │   └─ return -EPERM                         │
│       │                                            │
│       └─ VERDICT_NORMAL:                           │
│           └─ pwrite() → disco ZFS real             │
│  }                                                 │
│                                                    │
│  gfs_open()  → canary_is_canary()    ← canary.c    │
│  gfs_rename()→ detector_check_rename()← detector.c │
│  gfs_unlink()→ canary detection + bloqueo          │
└───────────────────────────────────────────────────┘
        │
        │ (background thread)
        ▼
┌───────────────────────────────────────────────────┐
│              analyzer.c (async thread)             │
│  - Consume ring_buffer                             │
│  - Actual: loguea eventos a stderr                 │
│  - Futuro: envía features a ml_server.py           │
└───────────────────────────────────────────────────┘
        │
        │ (background thread, cada 60s)
        ▼
┌───────────────────────────────────────────────────┐
│           zfs_snap.c (snapshot scheduler)          │
│  - zfs snapshot tank/data@guardian_auto_<ts>      │
│  - Retiene últimos 20, destruye el resto           │
└───────────────────────────────────────────────────┘
```

**Hilos activos durante la ejecución:**

| Hilo | Origen | Rol |
|---|---|---|
| Principal | `fuse_main()` | Atiende syscalls FUSE. Bloqueante. |
| Analyzer | `pthread_create` en `main()` | Consume ring buffer en background. |
| Snapshots | `zfs_snapshot_schedule()` | Dispara `zfs snapshot` cada N segundos. |

---

## 4. Módulo por Módulo

### 4.1 guardian_fs.c — El Proxy FUSE

**Archivo:** `src/guardian_fs.c` (281 líneas)  
**Rol:** Punto de entrada del sistema. Intercepta 11 operaciones FUSE.

**¿Qué problema resuelve?** Es el "hombre en el medio" entre cualquier aplicación y el filesystem real. Sin esto, el ransomware escribe directamente en ZFS sin pasar por nuestro detector.

**¿Por qué FUSE y no un módulo de kernel?**
- Un bug en userspace no paniquea el kernel.
- Desarrollo y debugging mucho más rápido (GDB, printf).
- Fácil integración con Python/ML vía Unix socket.
- La latencia extra (~2μs por syscall) es insignificante comparada con el I/O a disco.

**Operaciones implementadas:**

| Syscall | Handler | Qué hace |
|---|---|---|
| `write` | `gfs_write` | Calcula entropía → detector → bloquea o permite |
| `rename` | `gfs_rename` | Detecta cambio de extensión → scoring |
| `unlink` | `gfs_unlink` | Si es canary → bloqueo inmediato |
| `open` | `gfs_open` | Si es canary → alerta |
| `read` | `gfs_read` | Registra evento (para ratio R/W) |
| `getattr`, `readdir`, `mkdir`, `create`, `release`, `truncate` | Proxy directo | Pasan al filesystem subyacente sin análisis |

**Pipeline de `gfs_write` en detalle:**

```
1. entropy_shannon(buf, size)
   └─ Calcula H ∈ [0, 8] bits/byte.
      Bytes cifrados → H ≈ 7.8+
      Texto/imagen → H ≈ 4–6

2. ring_buf_push(ev)
   └─ Encola evento {EV_WRITE, pid, path, entropy, size, timestamp}
      para que analyzer_thread lo procese en background.

3. detector_check_write(ctx, pid, path, entropy, size)
   └─ Evalúa scoring local (ver 4.3) → VERDICT_NORMAL | BLOCK

4. Si BLOCK:
   ├─ zfs_snapshot_emergency()  → preserva estado pre-ataque
   ├─ mitigation_kill_process() → SIGKILL al atacante
   └─ return -EPERM             → la escritura NUNCA llega a disco

5. Si NORMAL:
   └─ pwrite() → datos persisten en ZFS
```

### 4.2 entropy.c — Análisis Estadístico de Bytes

**Archivo:** `src/entropy.c` (97 líneas)  
**Rol:** Caja de herramientas estadísticas para caracterizar buffers de bytes.

**¿Qué problema resuelve?** Necesitamos decidir si un buffer "parece cifrado" o "parece datos normales". Esto no se puede hacer con pattern matching — se necesitan tests estadísticos.

**Funciones:**

| Función | Qué mide | Interpretación |
|---|---|---|
| `entropy_shannon(buf, len)` | Entropía de Shannon. Mide la "sorpresa" promedio de cada byte. | **0** = todos los bytes iguales. **8.0** = distribución perfectamente uniforme (cifrado). |
| `entropy_chi_square(buf, len)` | Test χ² de bondad de ajuste a distribución uniforme. | **Cercano a 0** = muy uniforme → cifrado. **Alto** = distribución sesgada → datos normales. |
| `entropy_sliding_window(buf, len, block_sz)` | Entropía por bloques de N bytes. | Detecta cifrado parcial (ransomware que solo cifra los primeros KB de cada archivo). |
| `entropy_autocorrelation(H[], n)` | Correlación de Pearson lag-1 entre entropías consecutivas. | **Baja** = cada bloque es independiente → cifrado. **Alta** = datos con estructura → normal. |
| `entropy_chi2_from_hist(hist[256], total)` | χ² desde histograma precomputado. | Igual que `entropy_chi_square` pero trabajando sobre un histograma acumulado por PID (ventana de tiempo). |

**¿Por qué estas 5 y no otras?**

- **Shannon + χ²** cubren el 95% de los casos: si la entropía es alta **y** la distribución es uniforme, es cifrado con muy alta probabilidad.
- **Sliding window** ataca el caso de ransomware "rápido" que cifra solo los primeros N bytes de cada archivo (para no disparar alarmas por volumen).
- **Autocorrelación** distingue archivos comprimidos (`.zip`, `.jpg`) que tienen alta entropía pero **correlacionada**, del cifrado que tiene entropía alta y **descorrelacionada**.
- **Chi² from hist** permite evaluar uniformidad sobre una **ventana de tiempo** (muchas escrituras), no sobre un solo buffer.

**Complejidad:** O(n) en todos los casos. Un buffer de 4KB se procesa en < 1μs.

### 4.3 detector.c — Motor de Scoring por Comportamiento

**Archivo:** `src/detector.c` (248 líneas)  
**Rol:** El cerebro de la operación. Mantiene estado por PID, calcula un score de riesgo agregado, y emite veredictos.

**¿Qué problema resuelve?** La entropía sola no alcanza. Un backup comprimiendo archivos produce alta entropía pero es legítimo. Necesitamos **combinar múltiples señales** y seguirlas en el tiempo **por proceso**.

**Arquitectura interna:**

```
detector_ctx
├── pids[] → pid_state_t    (uno por cada PID observado)
│   ├── Métricas de escritura: write_count, bytes_written
│   ├── Métricas de entropía: entropy_sum, entropy_max, entropy_samples
│   ├── Métricas de rename:  rename_count, ext_change_count
│   ├── Métricas de lectura: read_count, bytes_read
│   ├── Canary:              canary_triggered
│   ├── Histograma χ²:       byte_hist[256], byte_hist_total
│   ├── Ventana temporal:    window_start_ns
│   └── Veredicto actual:    score, verdict
├── lock (pthread_mutex_t)  → thread-safe
└── Configuración:
    ├── Pesos: w_entropy=0.35, w_write=0.20, w_rename=0.15,
    │          w_chi2=0.20, w_rw_ratio=0.10
    ├── Umbrales: score_thresh=0.65 (BLOCK), warn=0.45 (SUSPICIOUS)
    └── Parámetros: window_secs, entropy_thresh, write_thresh, rename_thresh
```

**Ecuación de scoring — 5 señales normalizadas a [0, 1]:**

```
score = 0.35 · f(entropía media)
      + 0.20 · f(tasa de escrituras/ventana)
      + 0.15 · f(tasa de renombrados/ventana)
      + 0.20 · f(test χ² de uniformidad)
      + 0.10 · f(ratio lectura/escritura)
```

Cada `f(x)` es una función de normalización que mapea la señal cruda al rango [0, 1]. Por ejemplo, entropía se normaliza como `(H - 5.0) / 3.0` (5.0→0, 8.0→1).

**¿Por qué estos pesos?**

| Señal | Peso | Justificación |
|---|---|---|
| Entropía | 0.35 | Es la señal más fuerte — el cifrado siempre produce alta entropía. |
| Tasa escrituras | 0.20 | Ransomware escribe agresivamente; un proceso normal no escribe 500+ veces en 5 segundos. |
| χ² uniformidad | 0.20 | Compresión también tiene alta entropía, pero su distribución NO es perfectamente uniforme. χ² bajo = cifrado real. |
| Renombrados | 0.15 | Cambiar `.docx` → `.locked` es comportamiento clásico de ransomware. |
| Ratio R/W | 0.10 | Ransomware lee y luego escribe (encrypt-in-place). Un backup solo lee. |

**Regla rápida adicional:** Si `entropy > umbral` **Y** `write_count > 20` en la misma ventana → `VERDICT_SUSPICIOUS` inmediato. Esto atrapa ransomware agresivo en los primeros 20 archivos, sin esperar a que el score acumulado cruce 0.65.

**Veredictos y acciones:**

| Veredicto | Score | Acción en guardian_fs.c |
|---|---|---|
| `VERDICT_NORMAL` (0) | < 0.45 | La escritura pasa a ZFS normalmente. |
| `VERDICT_SUSPICIOUS` (1) | ≥ 0.45 | La escritura pasa pero se loguea. El analyzer thread intensifica monitoreo. |
| `VERDICT_BLOCK` (2) | ≥ 0.65 o canary tocado | Bloqueo: snapshot + kill + EPERM. |

**Ventanas temporales:** Cada PID tiene una ventana de N segundos (default 5s). Al expirar, los contadores se resetean. Esto evita que un proceso legítimo acumule "falsos positivos" por escribir mucho a lo largo de horas.

### 4.4 canary.c — Archivos Señuelo

**Archivo:** `src/canary.c` (80 líneas)  
**Rol:** Despliega archivos falsos con nombres atractivos para que el ransomware los procese. Si un canary es tocado → ataque confirmado.

**¿Qué problema resuelve?** El scoring estadístico tiene falsos positivos potenciales (backups, compresión). Tocar un canary es **evidencia irrefutable** de ransomware — ningún proceso legítimo modifica `A_important_report.docx` y luego `ZZ_backup_keys.txt` en secuencia.

**Estrategia de nombres:**

| Nombre | ¿Por qué? |
|---|---|
| `A_important_report.docx` | Prefijo `A_` → primero en orden alfabético. Mayoría del ransomware procesa A→Z. |
| `A_financials_2025.xlsx` | Contenido financiero falso → muy atractivo para cifrar. |
| `ZZ_backup_keys.txt` | Prefijo `ZZ_` → último en orden alfabético. Cubre ransomware que procesa Z→A. |
| `.hidden_canary_01.dat` | Archivo oculto (prefijo `.`) — si el ransomware procesa hidden files, cae. |
| `resume_final_v3.docx` | Nombre neutral, extensión `.docx` (la más atacada). |
| `family_photos_2024.jpg` | Simula fotos personales — objetivo de ransomware doméstico. |

**Contenido:** Los archivos contienen ~4 KB de texto plano falso (reportes financieros ficticios) con baja entropía. Esto es deliberado: si un canary tuviera alta entropía, el ransomware podría confundirlo con un archivo ya cifrado y saltearlo.

**Detección en varias capas:**
- `gfs_open()` — si el proceso abre un canary → `detector_signal_canary()` (score +0.8).
- `gfs_write()` — si el canary fue señalizado antes → bloqueo inmediato.
- `gfs_unlink()` — si el proceso **elimina** un canary → bloqueo inmediato sin esperar scoring.

### 4.5 zfs_snap.c — Recuperación vía Snapshots ZFS

**Archivo:** `src/zfs_snap.c` (96 líneas)  
**Rol:** Gestión de snapshots ZFS para recuperación post-ataque.

**¿Qué problema resuelve?** Sin snapshots, aunque bloqueemos al ransomware, los archivos que YA cifró están perdidos. ZFS nos da la capacidad de "viajar en el tiempo" al estado pre-ataque.

**¿Por qué ZFS?**
- **Snapshots instantáneos (O(1))**: ZFS es Copy-on-Write. Un snapshot no copia datos, solo marca metadatos.
- **Inmutables**: Ni siquiera root puede modificar un snapshot sin `zfs destroy`. El ransomware no puede cifrar retroactivamente.
- **Rollback instantáneo**: `zfs rollback` es O(1) — solo revierte punteros de metadatos.
- **Compresión lz4**: Reduce el overhead de almacenamiento de los snapshots.

**Tres funciones, tres momentos:**

| Función | Cuándo se usa | Qué hace |
|---|---|---|
| `zfs_snapshot_emergency()` | En el instante del bloqueo | Snapshot inmediato etiquetado `@guardian_emergency_<timestamp>`. Preserva el estado pre-ataque. |
| `zfs_snapshot_schedule()` | Hilo background, cada 60s | Snapshots periódicos `@guardian_auto_<timestamp>`. Retiene los últimos 20. |
| `zfs_rollback_latest()` | Manual (administrador) | Recupera el filesystem al snapshot más reciente con el prefijo dado. |

**Nota de implementación:** Para la PoC usamos `system()` y `popen()` invocando el binario `zfs`. En producción se recomienda usar `libzfs` directamente para mejor manejo de errores y performance.

### 4.6 ring_buffer.c — Buffer Circular Thread-Safe

**Archivo:** `src/ring_buffer.c` (65 líneas)  
**Rol:** Cola de comunicación entre el hilo principal (FUSE) y el hilo de análisis (analyzer).

**¿Qué problema resuelve?** En `gfs_write`, no podemos hacer análisis pesados (ML) porque la syscall del usuario está bloqueada esperando. La solución es **productor-consumidor**: el hilo FUSE produce eventos y los encola rápido; el hilo analyzer los consume en background sin bloquear al usuario.

**¿Por qué ring buffer y no una cola del SO?**
- **Latencia mínima**: `memcpy` + incrementar punteros. Sin syscalls.
- **Thread-safe con mutex + condition variables**: Sin busy-waiting. El productor duerme si está lleno, el consumidor duerme si está vacío.
- **Tamaño fijo en memoria**: 64K eventos de ~4128 bytes c/u ≈ 256 MB en el peor caso. Controlado.

**API:**
```c
struct ring_buf *ring_buf_create(capacity, elem_size);
int ring_buf_push(rb, &event);   // bloquea si lleno
int ring_buf_pop(rb, &event);    // bloquea si vacío
void ring_buf_destroy(rb);
```

### 4.7 mitigation.c — Terminación del Proceso Atacante

**Archivo:** `src/mitigation.c` (14 líneas)  
**Rol:** Envía `SIGKILL` al PID del proceso que disparó el bloqueo.

**¿Por qué SIGKILL y no SIGTERM?** SIGTERM es "por favor, terminale". El ransomware puede ignorarlo o tener un handler que cifre todo antes de salir. SIGKILL es inapelable — el kernel destruye el proceso inmediatamente sin darle oportunidad de ejecutar más código.

**¿Por qué matar el proceso?** Bloquear la syscall con `-EPERM` detiene **esa** escritura, pero el ransomware va a reintentar o pasar al siguiente archivo. Matar el proceso corta el ataque de raíz.

### 4.8 analyzer.c — Hilo de Análisis Asíncrono

**Archivo:** `src/analyzer.c` (49 líneas)  
**Rol:** Hilo background que consume el ring buffer. Actualmente es un stub.

**Estado actual:** Loggea cada evento (tipo, PID, path) a stderr. Tiene preparada una función `ml_connect()` para conectarse vía Unix socket a `/tmp/guardian_ml.sock`.

**Futuro:** Cuando el servidor ML (Python) esté implementado, este hilo:
1. Acumulará eventos por PID.
2. Calculará un feature vector de 14 dimensiones.
3. Enviará el vector al servidor ML.
4. Recibirá un veredicto (`attack`/`suspicious`/`normal`).
5. Si `p_attack ≥ 0.75`, modificará el score del detector para forzar bloqueo.

**¿Por qué un hilo separado?** La inferencia ML (aunque sea vía socket local) tiene latencia de 1–5ms. No podemos bloquear la syscall del usuario ese tiempo. El analyzer opera en background: la detección rápida (detector.c) frena el ataque inmediato; el ML da una segunda opinión para refinar.

---

## 5. Flujo de Datos — El Camino Completo

### 5.1 Ataque de ransomware cifrador (happy path de detección)

```
Momento T0: Ransomware ejecuta write("documento.docx", bytes_cifrados, 4096)

T0 + 0μs:  FUSE redirige a gfs_write()
T0 + 1μs:  entropy_shannon(bytes_cifrados, 4096) → 7.94 bits/byte
T0 + 2μs:  ring_buf_push(ev) → evento encolado para analyzer
T0 + 3μs:  detector_check_write(pid=1234, path="...docx", entropy=7.94, size=4096)
              ├─ get_or_create_pid(1234)
              ├─ maybe_rotate_window() → ventana aún vigente (2s transcurridos de 5s)
              ├─ write_count: 18 → 19, entropy_samples++
              ├─ compute_score():
              │    f_entropy = (7.94-5.0)/3.0 = 0.98
              │    f_write   = 19/500 = 0.038
              │    score = 0.35·0.98 + 0.20·0.038 = 0.35
              ├─ score(0.35) < 0.45 → VERDICT_NORMAL
              └─ return VERDICT_NORMAL
T0 + 4μs:  pwrite(fd, bytes_cifrados, 4096) → disco ZFS

... (19 escrituras más, score subiendo) ...

Momento T0+800ms: Write #39 — score cruza 0.65

T0+800ms + 3μs: detector_check_write() → score = 0.72 ≥ 0.65
                   → VERDICT_BLOCK
T0+800ms + 4μs: zfs_snapshot_emergency("tank/data")
                   → "zfs snapshot tank/data@guardian_emergency_20260627T143022Z"
T0+800ms + 5μs: mitigation_kill_process(1234)
                   → kill(1234, SIGKILL)
T0+800ms + 6μs: return -EPERM
                   → El ransomware ve "Permission denied"
                   → Los archivos escritos antes del bloqueo están en ZFS
                   → El snapshot de emergencia preserva el estado pre-ataque
                   → Rollback manual: zfs rollback tank/data@guardian_emergency_...
```

### 5.2 Escritura legítima (no bloquea)

```
Aplicación escribe reporte_q4.pdf (bytes de PDF, H ≈ 5.2)

gfs_write() → entropy = 5.2 → score ≈ 0.12 → VERDICT_NORMAL → pwrite() OK
```

### 5.3 Canary tocado (bloqueo inmediato)

```
Ransomware abre A_important_report.docx → gfs_open()
  → canary_is_canary() → TRUE
  → detector_signal_canary() → score += 0.8 → score ≥ 1.0
  → siguiente write() del mismo PID → VERDICT_BLOCK inmediato
```

---

## 6. Build, Test y Deploy

### Compilación

```bash
# Requisitos: gcc (C17), cmake 3.22+, libfuse3-dev
sudo bash scripts/install_deps.sh
cmake -S . -B build && cmake --build build --parallel
```

**Opciones de compilación:** `-std=c17 -Wall -Wextra -Wpedantic` — cero warnings.

### Tests unitarios

```bash
# Todos los tests (28 tests, 83 assertions)
bash scripts/run_tests.sh

# Individual
gcc -std=c17 tests/unit/test_entropy.c src/entropy.c -Iinclude -lm -o /tmp/t && /tmp/t
```

**Cobertura:** 5/8 módulos con tests dedicados. Los módulos sin tests directos (zfs_snap, analyzer, guardian_fs) requieren ZFS real para testearse — planeados como integration tests.

### Deploy en VM

```bash
# 1. Pool ZFS para testing (2 GB file-backed)
sudo bash scripts/zfs_setup.sh

# 2. Montar el proxy FUSE
sudo bash scripts/mount.sh /mnt/guardian_real /mnt/protected

# 3. Probar — cualquier escritura con alta entropía dispara el detector
```

---

## 7. Decisiones de Diseño y Trade-offs

| Decisión | Alternativa considerada | Por qué esta |
|---|---|---|
| **FUSE userspace** | Módulo de kernel Linux | Seguridad (un bug no paniquea), velocidad de desarrollo, integración con Python. |
| **ZFS** | btrfs, LVM snapshots | Snapshots atómicos CoW, inmutables, compresión lz4, rollback O(1). |
| **Scoring ponderado** | Árbol de decisión, reglas fijas | Pesos calibrables sin recompilar ML, interpretable, cada señal independiente. |
| **C17 para detección** | Python para todo | Latencia < 1ms en la syscall. Python tarda > 1ms solo en iniciar el intérprete. |
| **Ring buffer propio** | Colas POSIX (mq), pipes | Sin syscalls en el productor. Control total de memoria y bloqueo. |
| **system() para ZFS** | libzfs | Simplicidad para PoC. libzfs requiere linkear contra bibliotecas no estándar de OpenZFS. |
| **Ventanas por PID** | Scoring global | Un atacante no debe "esconderse" detrás de la actividad de otros procesos. |
| **Pesos actuales** | ML desde el principio | La PoC necesita funcionar sin datos de entrenamiento. Los pesos se calibraron con razonamiento de dominio y se pueden refinar con ML. |

---

## 8. Trabajo Pendiente

Ver `docs/architecture/README.md` sección 7.2 para la lista completa priorizada. Resumen rápido:

| Prioridad | Tarea | Esfuerzo |
|---|---|---|
| 🔴 Alta | Leer config dinámica en vez de paths hardcodeados | 30 min |
| 🔴 Alta | Shutdown graceful (SIGTERM/SIGINT) | 20 min |
| 🟡 Media | Integration test (simular ransomware) | 1–2 h |
| 🟡 Media | Implementar `ml_server.py` | 4–6 h |
| 🟢 Baja | Systemd unit file | 15 min |

---

*Documento generado para acompañar la defensa del Proyecto Final. Cualquier duda técnica, consultar `docs/architecture/README.md` y `docs/testing-guide.md`.*
