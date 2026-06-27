# Guardian FS — Documentación de Arquitectura

> Proyecto Final UTN FRSF 2026 — Gómez Enrico, Ivo · Kuchen, Francisco  
> Director: Dr. Pablo Pessolani · Codirector: Ing. David Harispe  
> Versión: v0.1.0 (unreleased) | Licencia: MIT

---

## Índice

1. [Visión General](#1-visión-general)
2. [Arquitectura del Sistema](#2-arquitectura-del-sistema)
3. [Módulos](#3-módulos)
4. [Flujo de Detección y Mitigación](#4-flujo-de-detección-y-mitigación)
5. [Modelo de Amenazas](#5-modelo-de-amenazas)
6. [Decisiones Técnicas](#6-decisiones-técnicas)
7. [Estado Actual y Trabajo Pendiente](#7-estado-actual-y-trabajo-pendiente)

---

## 1. Visión General

Guardian FS es un sistema de detección y mitigación de ransomware cifrador (cryptoware) en Linux. Opera como un **proxy FUSE transparente** entre las aplicaciones y el sistema de archivos ZFS, interceptando syscalls de E/S para analizar patrones en tiempo real mediante:

- **Análisis estadístico local** (entropía Shannon, test χ², correlación de Pearson) dentro del módulo C, con latencia < 1ms.
- **Inferencia remota por ML** (Random Forest, XGBoost, Isolation Forest, LSTM) vía Unix socket, para segunda opinión asíncrona.
- **Recuperación por snapshots ZFS** inmutables (Copy-on-Write) con rollback al estado pre-ataque.

**Objetivos cuantitativos:**

| Métrica | Objetivo |
|---|---|
| Pérdida de datos | < 1 MB antes del bloqueo |
| RTO (rollback) | < 30 segundos |
| Overhead snapshots | < 5% del dataset |
| Falsos positivos (FPR) | < 1% |
| Latencia de E/S inducida | < 2ms por operación |

---

## 2. Arquitectura del Sistema

### 2.1 Diagrama de Capas

```
                      ┌─────────────────────────────────────┐
                      │        Aplicaciones / Procesos        │
                      │  (syscalls: open, read, write,       │
                      │   rename, unlink, truncate)          │
                      └──────────────┬──────────────────────┘
                                     │
                                     ▼
         ┌─────────────────────────────────────────────────────┐
         │               guardian_fs (FUSE 3.16+)              │
         │    ┌───────────────────────────────────────────┐   │
         │    │         gfs_write → entropy_shannon()      │   │
         │    │         gfs_read → ring_buf_push()         │   │
         │    │         gfs_rename → ext_change_check      │   │
         │    │         gfs_unlink → canary_is_canary()    │   │
         │    │         gfs_open → canary detection         │   │
         │    └──────────────────┬────────────────────────┘   │
         │                       │                            │
         │    ┌──────────────────▼────────────────────────┐   │
         │    │         detector.c (scoring local)          │   │
         │    │  - Ventanas por PID (default 5s)           │   │
         │    │  - Score ponderado (6 señales, umbral 0.65)│   │
         │    │  - Thread-safe con mutex                   │   │
         │    └──────────────────┬────────────────────────┘   │
         │                       │                            │
         │    ┌──────────────────▼────────────────────────┐   │
         │    │       analyzer_thread (asíncrono)          │   │
         │    │  - Envía features vía Unix socket          │   │
         │    │  - Recibe veredicto del ML server          │   │
         │    └───────────────────────────────────────────┘   │
         └──────────────────┬─────────────────────────────────┘
                            │
                 ┌──────────┴──────────┐
                 ▼                     ▼
     ┌──────────────────┐   ┌──────────────────────┐
     │  VERDICT_BLOCK    │   │  VERDICT_NORMAL      │
     │                   │   │                      │
     │  zfs_snapshot_    │   │  pwrite() en ZFS     │
     │    emergency()    │   │  real → continua     │
     │  mitigation_kill  │   │                      │
     │    _process(pid)  │   │                      │
     │  return -EPERM    │   │                      │
     └────────┬─────────┘   └──────────────────────┘
              │
              ▼
     ┌────────────────────────────────────────────────────┐
     │              ZFS (tank/data)                        │
     │  - Snapshot periódico cada 60s (@guardian_auto_*)  │
     │  - Snapshot de emergencia (@guardian_emergency_*)  │
     │  - Rollback al snapshot más reciente                │
     │  - Compresión lz4, checksums sha256, atime off     │
     └────────────────────────────────────────────────────┘

              ▼
     ┌────────────────────────────────────────────────────┐
     │         ml_server.py (Unix Domain Socket)           │
     │  ┌──────────┐ ┌──────────┐ ┌──────┐ ┌──────────┐ │
     │  │ Random   │ │ Isolation│ │XGBoost│ │ LSTM     │ │
     │  │ Forest   │ │ Forest   │ │ 0.30  │ │ 0.15     │ │
     │  │ 0.35     │ │ 0.20     │ │       │ │(PyTorch) │ │
     │  └──────────┘ └──────────┘ └──────┘ └──────────┘ │
     │  Ensemble voting → p_attack ≥ 0.75 → "attack"    │
     └────────────────────────────────────────────────────┘
```

### 2.2 Modelo de Hilos

| Hilo | Origen | Propósito |
|---|---|---|
| **Principal** | `fuse_main()` | Atiende syscalls FUSE sincrónicamente |
| **Analizador** | `pthread_create` en `main()` | Procesa ring buffer, envía a ML server (no implementado) |
| **Snapshots** | `zfs_snapshot_schedule()` | Snapshots periódicos cada N segundos (default 60) |

### 2.3 Comunicación entre Procesos

```
┌─────────────────┐     Unix Domain Socket      ┌──────────────────┐
│  guardian_fs (C) │ ──────────────────────────→  │  ml_server.py    │
│  (analyzer_thread)│   /run/guardian_ml.sock     │  (Python 3.11+)  │
└─────────────────┘   JSON-lines bidireccional   └──────────────────┘
                        Request: {features, pid}
                        Response: {p_attack, verdict, scores, flags}
```

---

## 3. Módulos

### 3.1 `entropy.c` — Análisis Estadístico de Bytes

**Ubicación:** `src/entropy.c` (167 líneas)  
**Dependencias:** `entropy.h` (no existe en disco)

| Función | Señal | Complejidad | Rango |
|---|---|---|---|
| `entropy_shannon()` | Entropía de Shannon | O(n), 256 buckets | [0.0, 8.0] bits/byte |
| `entropy_chi_square()` | Test χ² de uniformidad | O(n) | χ² ≥ 0 (bajo = uniforme) |
| `entropy_sliding_window()` | Entropía por bloques | O(n) | array de doubles |
| `entropy_autocorrelation()` | Correlación de Pearson | O(n) | [-1.0, 1.0] |

**Interpretación:** Datos cifrados → alta entropía (≈7.8 bits/byte), distribución uniforme (χ² < 300), baja autocorrelación.

**⚠️ Problema conocido:** El archivo tiene las 4 funciones duplicadas (líneas 1–84 y 84–167). Impide la compilación.

### 3.2 `detector.c` — Motor de Scoring Local

**Ubicación:** `src/detector.c` (185 líneas)  
**Dependencias:** `detector.h`, `entropy.h` (no existen en disco)

**Arquitectura interna:**

```
detector_ctx
├── pids[] → pid_state_t
│   ├── pid, write_count, bytes_written
│   ├── rename_count, unlink_count, read_count
│   ├── entropy_sum, entropy_max, entropy_samples
│   ├── canary_triggered, ext_change_count
│   ├── byte_hist[256], byte_hist_total
│   ├── score (último calculado)
│   ├── window_start_ns
│   └── verdict
├── lock (pthread_mutex_t)
├── umbrales (entropy_thresh, write_rate_thresh, ...)
├── pesos (w_entropy=0.35, w_write=0.20, ...)
└── score_thresh = 0.65
```

**Ecuación de score:**

```
score = 0.35 · f(entropy) + 0.20 · f(write_rate) + 0.15 · f(rename_rate)
      + 0.20 · f(χ²) + 0.10 · f(rw_ratio)
      + (0.50 si canary_triggered)
```

**Veredictos:**

| Valor | Constante | Acción |
|---|---|---|
| 0 | `VERDICT_NORMAL` | Pasar la syscall |
| 1 | `VERDICT_SUSPICIOUS` | Monitorear (log + analizador asíncrono) |
| 2 | `VERDICT_BLOCK` | Bloquear + snapshot + kill |

### 3.3 `canary.c` — Archivos Señuelo

**Ubicación:** `src/canary.c` (78 líneas)  
**Dependencias:** `canary.h` (no existe en disco)

**Estrategia de despliegue:**

- Nombres con prefijos `A_` y `ZZ_` para explotar orden alfabético.
- Extensiones objetivo: `.docx`, `.pdf`, `.jpg`, `.xlsx`.
- Contenido simulado de baja entropía (texto plano con datos financieros ficticios).
- Distribución en subdirectorios a distintas profundidades.
- Hasta 20 canaries desplegados (configurable vía `canary_deploy(ctx, count)`).

**Canary names definidos:**

```
A_important_report.docx
A_financials_2025.xlsx
ZZ_backup_keys.txt
ZZ_passwords_old.pdf
.hidden_canary_01.dat
resume_final_v3.docx
family_photos_2024.jpg
```

### 3.4 `zfs_snap.c` — Interfaz ZFS

**Ubicación:** `src/zfs_snap.c` (96 líneas)  
**Dependencias:** `zfs_snap.h` (no existe en disco)

| Función | Propósito | Método |
|---|---|---|
| `zfs_snapshot_emergency()` | Snapshot inmediato en ataque | `system("zfs snapshot ...@guardian_emergency_<timestamp>")` |
| `zfs_snapshot_schedule()` | Hilo de snapshots periódicos | `pthread_create` + `sleep(interval)` |
| `zfs_rollback_latest()` | Rollback al snapshot pre-ataque | `popen("zfs list ... grep ... | tail -1")` + `zfs rollback -r` |

**Política de retención:** Últimos 20 snapshots automáticos; el resto se destruyen.

### 3.5 `guardian_fs.c` — Proxy FUSE

**Ubicación:** `src/guardian_fs.c` (203 líneas)  
**Dependencias:** `entropy.h`, `detector.h`, `canary.h`, `zfs_snap.h`, `ring_buffer.h`, `fuse3/fuse.h`

**Operaciones hookeadas:**

| Operación FUSE | Handler | Comportamiento de seguridad |
|---|---|---|
| `getattr` | `gfs_getattr` | Proxy directo a `lstat()` |
| `open` | `gfs_open` | Detecta apertura de canary → `detector_signal_canary()` |
| `read` | `gfs_read` | Registra evento de lectura (para ratio R/W) |
| `write` | `gfs_write` | Calcula entropía, evalúa detector, bloquea si es necesario |
| `rename` | `gfs_rename` | Detecta cambio de extensión (`.doc` → `.locked`) |
| `unlink` | `gfs_unlink` | Si es canary → bloqueo inmediato |
| `readdir` | `gfs_readdir` | No implementado (proxy directo necesario) |
| `mkdir` | `gfs_mkdir` | No implementado |
| `create` | `gfs_create` | No implementado |
| `release` | `gfs_release` | No implementado |
| `truncate` | `gfs_truncate` | No implementado |

**Pipeline de escritura (`gfs_write`):**

```
write(path, buf, size, offset)
  │
  ├─ 1. entropy_shannon(buf, size) → double ent
  │
  ├─ 2. ring_buf_push(evbuf, event{EV_WRITE, pid, size, ent})
  │
  ├─ 3. detector_check_write(ctx, pid, path, ent, size) → verdict
  │      │
  │      ├─ VERDICT_BLOCK:
  │      │   ├─ zfs_snapshot_emergency(zfs_dataset)
  │      │   ├─ mitigation_kill_process(pid)
  │      │   └─ return -EPERM
  │      │
  │      └─ VERDICT_NORMAL:
  │          └─ pwrite(fi->fh, buf, size, offset) → ZFS real
  │
  └─ return n (bytes escritos reales)
```

### 3.6 `ml_server.py` — Servidor de Inferencia ML

**Ubicación:** `src/ml_server.py` (297 líneas)  
**Framework:** scikit-learn + XGBoost + PyTorch (opcional)

**Ensemble de 4 modelos con voting ponderado:**

| Modelo | Peso | Naturaleza | Propósito |
|---|---|---|---|
| Random Forest | 0.35 | Supervisado | Clasificación binaria general |
| XGBoost | 0.30 | Supervisado | Gradient boosting, maneja desbalance |
| Isolation Forest | 0.20 | No supervisado | Anomalías (entrenado solo con benignos) |
| LSTM (PyTorch) | 0.15 | Series temporales | Secuencias de 10 ventanas por PID |

**Feature vector (14 características):**

| # | Feature | Descripción |
|---|---|---|
| 1 | `entropy_mean` | H̄ — entropía media de escrituras |
| 2 | `entropy_max` | Máximo de entropía en la ventana |
| 3 | `entropy_std` | Desviación estándar de entropía |
| 4 | `entropy_autocorr` | Autocorrelación entre ventanas |
| 5 | `write_rate` | Escrituras por segundo |
| 6 | `bytes_written_rate` | Bytes/segundo escritos |
| 7 | `rename_rate` | Renombrados por segundo |
| 8 | `unlink_rate` | Eliminaciones por segundo |
| 9 | `read_write_ratio` | Ratio bytes leídos / bytes escritos |
| 10 | `chi2_stat` | Estadístico χ² (uniformidad de bytes) |
| 11 | `ext_change_rate` | Tasa de cambio de extensión |
| 12 | `canary_accessed` | Booleano: accedió a canary |
| 13 | `unique_dirs` | Directorios únicos accedidos |
| 14 | `file_type_variety` | Variedad de extensiones escritas |

**Umbrales de veredicto:**

| p_attack | Veredicto |
|---|---|
| ≥ 0.75 | `"attack"` |
| ≥ 0.50 | `"suspicious"` |
| < 0.50 | `"normal"` |

**Fallback:** Si no hay modelos entrenados (`rf.pkl` no existe), usa `_rule_based()` con reglas estadísticas fijas.

### 3.7 `train_model.py` — Entrenamiento Offline

**Ubicación:** `src/train_model.py` (107 líneas)

**Pipeline:**

```
CSV (features_labeled.csv)
  │
  ├─ SMOTE (balanceo de clases)
  ├─ StandardScaler (normalización)
  ├─ StratifiedKFold k=10 (validación cruzada)
  ├─ RandomForestClassifier (n=200, max_depth=15)
  ├─ XGBClassifier (n=200, max_depth=8, scale_pos_weight=10)
  ├─ Evaluación: ROC-AUC, FPR, FNR, classification_report
  └─ Serialización: scaler.pkl, rf.pkl, xgb.json
```

### 3.8 Módulos Declarados pero No Implementados

| Módulo | Archivo faltante | Uso |
|---|---|---|
| `ring_buffer.h` | `src/include/` | Buffer circular de 64KB para eventos de E/S |
| `mitigation_kill_process()` | `src/mitigation/` | Terminación del proceso atacante vía SIGKILL |
| `analyzer_thread()` | `src/guardian_fs/` | Hilo asíncrono que procesa ring buffer y consulta ML |
| Headers locales | `include/` | `entropy.h`, `detector.h`, `canary.h`, `zfs_snap.h`, `ring_buffer.h` |
| `gfs_readdir()`, `gfs_mkdir()`, `gfs_create()`, `gfs_release()`, `gfs_truncate()` | `src/guardian_fs/` | Operaciones FUSE restantes |
| Build system | `CMakeLists.txt` | No existe en disco |

---

## 4. Flujo de Detección y Mitigación

### 4.1 Flujo Normal (sin ataque)

```
Aplicación escribe archivo normal (baja entropía, tasa normal)
  → gfs_write()
  → entropy_shannon() → H ≈ 4.5 bits/byte
  → detector_check_write() → score ≈ 0.15 → VERDICT_NORMAL
  → pwrite() en ZFS real
  → Éxito
```

### 4.2 Flujo de Ataque (ransomware cifrando)

```
Ransomware escribe bytes cifrados (alta entropía, alta tasa)
  → gfs_write()
  → entropy_shannon() → H ≈ 7.9 bits/byte
  → detector_check_write()
      → score = 0.35 * f(7.9) + 0.20 * f(alta_tasa) + ...
      → score = 0.72 → VERDICT_BLOCK
  → zfs_snapshot_emergency("tank/data")
      → "zfs snapshot tank/data@guardian_emergency_20260415T143022Z"
  → mitigation_kill_process(pid)
      → SIGKILL al proceso atacante
  → return -EPERM (permiso denegado)
  → Escritura NO persiste en ZFS
```

### 4.3 Flujo de Detección por Canary

```
Ransomware renombra A_important_report.docx → A_important_report.locked
  → gfs_rename(".../A_important_report.docx", ".../A_important_report.locked")
  → canary_is_canary() → TRUE
  → zfs_snapshot_emergency()
  → mitigation_kill_process()
  → return -EPERM
```

### 4.4 Flujo de ML Asíncrono (cuando esté implementado)

```
analyzer_thread (segundo plano, cada ~1s):
  ├─ Procesa ring_buffer de eventos
  ├─ Calcula feature vector por PID
  ├─ Conecta a /run/guardian_ml.sock
  ├─ Envía JSON: {"features": {...}, "pid": 1234}
  ├─ Recibe JSON: {"p_attack": 0.89, "verdict": "attack", ...}
  └─ Si p_attack ≥ 0.75 → señaliza al detector para bloquear
```

### 4.5 Flujo de Recuperación (rollback)

```
Administrador detecta ataque (o responde automáticamente):
  → zfs_rollback_latest("tank/data", "guardian_emergency_")
  → popen("zfs list ... | grep guardian_emergency_ | tail -1")
  → "zfs rollback -r tank/data@guardian_emergency_20260415T143022Z"
  → Filesystem restaurado al estado pre-ataque
```

### 4.6 Diagrama de Estados por PID

```
                     ┌──────────┐
                     │  NORMAL  │
                     └────┬─────┘
                          │ write() con entropía alta o tasa elevada
                          ▼
                   ┌──────────────┐
                   │  SUSPICIOUS   │ ← score ≥ 0.50 (ML solo)
                   └──────┬───────┘
                          │ score ≥ 0.65 o canary tocado
                          ▼
                    ┌───────────┐
                    │   BLOCK    │ → snapshot + kill + EPERM
                    └───────────┘
```

---

## 5. Modelo de Amenazas

### 5.1 Activos a Proteger

| Activo | Descripción | Valor |
|---|---|---|
| Datos del usuario | Archivos en `/mnt/protected` | Alto (objetivo del ataque) |
| Integridad del FS | Estructura de directorios y metadatos | Alto |
| Snapshots ZFS | Puntos de recuperación | Muy alto (único mecanismo de rollback) |
| Modelos ML | Archivos `.pkl` y `.json` en `/var/lib/guardian/models/` | Medio |
| Socket ML | `/run/guardian_ml.sock` | Bajo (solo IPC local) |

### 5.2 Perfiles de Atacante

| Perfil | Capacidad | Ejemplo |
|---|---|---|
| **Script Kiddie** | Ejecuta ransomware conocido sin modificaciones | LockBit 3.0 estándar |
| **Atacante evasivo** | Modifica firma, reduce velocidad, cifra parcial | Ransomware con sleeps, cifrado de primeros N bytes |
| **Atacante dirigido** | Conoce Guardian FS, busca bypassear detección | Inyecta tráfico benigno, ataca el socket ML, elimina canaries |

### 5.3 Vector de Ataque y Superficie

```
Superficie de ataque:
  ┌─────────────────────────────────────────┐
  │                                         │
  │   Aplicaciones no confiables en el      │
  │   mismo host (sin sandboxing)           │
  │         │                               │
  │         ▼                               │
  │   ┌─────────────────┐                   │
  │   │  FUSE syscalls   │ ← write, rename,  │
  │   │  (interfaz única)│   unlink, open    │
  │   └────────┬────────┘                   │
  │            │                            │
  │   ┌────────▼────────┐                   │
  │   │  guardian_fs C   │ ← Análisis local  │
  │   └────────┬────────┘                   │
  │            │                            │
  │   ┌────────▼────────┐                   │
  │   │   ml_server.py   │ ← Unix socket     │
  │   └─────────────────┘                   │
  │                                         │
  └─────────────────────────────────────────┘
```

### 5.4 Amenazas Identificadas

| ID | Amenaza | Impacto | Probabilidad | Mitigación |
|---|---|---|---|---|
| **T1** | Ransomware que evita canaries alfabéticamente (procesa en orden inverso o aleatorio) | Alto | Media | Canaries con prefijos `A_` y `ZZ_` cubren ambos extremos; agregar nombres aleatorios |
| **T2** | Ransomware que cifra a baja velocidad para no disparar umbrales de tasa | Alto | Media | El scoring incluye entropía (independiente de tasa) + ML con LSTM para patrones temporales |
| **T3** | Ataque al socket Unix ML (llenado, DoS, conexiones maliciosas) | Medio | Baja | Socket con permisos `0o600`, limit `listen(10)`, autenticación no implementada |
| **T4** | Eliminación de canaries antes de cifrar | Alto | Baja | Canaries ocultos (`.hidden_canary_*`) + detección en `gfs_unlink` bloquea al eliminar |
| **T5** | Falsos positivos que interrumpen trabajo legítimo (backup, compresión, build) | Medio | Media | Score threshold configurable; ML ensemble reduce FPR; modo "suspicious" solo log |
| **T6** | Agotamiento del pool ZFS por snapshots excesivos | Medio | Baja | Retención máxima de 20 automáticos; emergencia manual; configurable |
| **T7** | Rollback que borra datos legítimos post-snapshot | Alto | Baja | El rollback es manual (administrador); registra logs de eventos |
| **T8** | Cifrado de archivos ya en `/zpool/data` sin pasar por FUSE | Muy alto | Media | Depende de configuración de montaje; FUSE debe ser el único punto de entrada |
| **T9** | Bypass del proxy FUSE (montar ZFS directamente) | Muy alto | Baja | `zfs_setup.sh` desmonta `/zpool/data` del namespace público; policy de permisos |
| **T10** | ML server no disponible (caída, no entrenado) | Medio | Media | Fallback a `_rule_based()` en C (detector.c) sin dependencia de Python |
| **T11** | Ransomware que cifra sólo metadatos (nombres de archivo) sin escribir bytes | Medio | Baja | `gfs_rename` detecta cambio de extensión; detector monitorea rename_rate |
| **T12** | Ransomware con firma polimórfica que evade ML entrenado | Alto | Baja | Isolation Forest detecta anomalías no vistas en entrenamiento; reentrenamiento continuo |

### 5.5 Mitigaciones Generales

| Dimensión | Medida |
|---|---|
| **Detección temprana** | Scoring local en C (< 1ms) antes de ML; canaries como trampa inmediata |
| **Defensa en profundidad** | 3 capas: canary → scoring estadístico → ML ensemble |
| **Recuperación** | Snapshots ZFS inmutables (ni el ransomware root puede modificarlos sin `zfs destroy`) |
| **Aislamiento** | FUSE en userspace; ZFS en kernel; comunicación C↔Python por socket Unix local |
| **Degradación graceful** | Sin ML → reglas fijas; sin detector → FUSE proxy puro |
| **Observabilidad** | Logs estructurados en `/var/log/guardian/events.jsonl`; feature importance exportable |

---

## 6. Decisiones Técnicas

### 6.1 ¿Por qué FUSE en vez de kernel module?

| Aspecto | FUSE (userspace) | Módulo kernel |
|---|---|---|
| Seguridad | Fallo no paniquea el kernel | Bug puede tumbar el sistema |
| Desarrollo | Ciclo rápido, debugging con GDB | Depuración más compleja |
| Latencia | ~2–5μs overhead por syscall | ~0.5μs |
| Flexibilidad | Fácil integrar ML vía socket | Necesita comunicación kernel→userspace |
| Portabilidad | Multiples SO (Linux, macOS, BSD) | Específico de kernel |

Para una PoC, FUSE ofrece el mejor balance entre velocidad de desarrollo y performance aceptable.

### 6.2 ¿Por qué ZFS?

- **Snapshots atómicos e inmutables** por CoW — el ransomware no puede cifrar retroactivamente.
- **Compresión lz4** transparente (reduce overhead de CoW en snapshots).
- **Checksums sha256** — integridad de datos verificable.
- **Rollback instantáneo** — operación O(1) en metadatos.

### 6.3 ¿Por qué ensemble de modelos ML?

Ningún modelo solo cubre todos los patrones de ataque:

- **Random Forest**: robusto, interpretable (feature importance), maneja no-linealidades.
- **Isolation Forest**: detecta anomalías no vistas en entrenamiento (ransomware nuevo).
- **XGBoost**: mejor precisión con datos balanceados, maneja desbalance con `scale_pos_weight`.
- **LSTM**: captura evolución temporal del comportamiento por PID.

El voting ponderado (0.35 RF + 0.30 XGB + 0.20 ISO + 0.15 LSTM) maximiza ROC-AUC en evaluación preliminar.

### 6.4 ¿Por qué scoring local en C antes de ML?

La latencia de un socket round-trip a Python es ~1–5ms. Para no bloquear la syscall del usuario, el detector C aplica un filtro rápido (umbrales locales) y el ML corre en un hilo separado como segunda opinión asíncrona.

---

## 7. Estado Actual y Trabajo Pendiente

### 7.1 Implementado (v0.1.0)

- [x] `entropy.c` — funciones estadísticas completas (con duplicado a corregir)
- [x] `detector.c` — motor de scoring por PID con ventanas y thread-safety
- [x] `canary.c` — despliegue y detección de archivos señuelo
- [x] `zfs_snap.c` — snapshots de emergencia, periódicos y rollback
- [x] `guardian_fs.c` — esqueleto FUSE con write/rename/unlink/open hookeados
- [x] `ml_server.py` — servidor ML completo con ensemble y fallback rule-based
- [x] `train_model.py` — pipeline de entrenamiento con SMOTE y validación cruzada
- [x] `zfs_setup.sh` — script de setup de infraestructura

### 7.2 No Implementado (brecha README vs. disco)

- [ ] Headers locales (`entropy.h`, `detector.h`, `canary.h`, `zfs_snap.h`, `ring_buffer.h`)
- [ ] `ring_buffer.c` — buffer circular de 64KB
- [ ] `mitigation_kill_process()` — terminación de procesos
- [ ] `analyzer_thread()` — hilo asíncrono de ML
- [ ] Operaciones FUSE restantes (`readdir`, `mkdir`, `create`, `release`, `truncate`)
- [ ] `CMakeLists.txt` — build system
- [ ] Scripts: `install_deps.sh`, `mount.sh`, `rollback.sh`, `run_tests.sh`
- [ ] Tests unitarios, de integración y fixtures
- [ ] Configs (`guardian.conf`, `logging.conf`)
- [ ] GitHub Actions CI/CD
- [ ] `python/requirements.txt`
- [ ] Feature extractor Python (`feature_extractor.py`)

### 7.3 Problemas Conocidos

1. **`entropy.c` duplicado**: las 4 funciones aparecen dos veces (copy-paste). Impide compilación.
2. **`clock_gettime_ns()`**: no es POSIX estándar. Debe reemplazarse por `clock_gettime()` + conversión a nanosegundos.
3. **Funciones referenciadas sin definición**: `detector_signal_canary()`, `detector_check_rename()`, `detector_confirm_attack()`, `detector_chi2_from_hist()`, `mitigation_kill_process()`, `ring_buf_create()`, `ring_buf_push()`.
4. **Sin build system**: no hay `CMakeLists.txt` en disco — el código C no compila.
5. **Sin requirements.txt**: las dependencias Python deben instalarse manualmente.

---

## Apéndice A: Stack Tecnológico Completo

| Componente | Tecnología | Versión |
|---|---|---|
| Filesystem proxy | FUSE (libfuse3) | 3.16+ |
| Storage | OpenZFS (ZFS on Linux) | 2.2+ |
| Lenguaje C | C11 (GCC/Clang) | 13+ / 17+ |
| Lenguaje Python | Python 3 | 3.11+ |
| ML supervizado | scikit-learn (RF), XGBoost | ≥1.5, ≥2.0 |
| ML no supervisado | scikit-learn (IsolationForest) | ≥1.5 |
| ML series temp. | PyTorch (LSTM) | ≥2.0 (opcional) |
| Balanceo de clases | imbalanced-learn (SMOTE) | ≥0.12 |
| Data processing | NumPy, Pandas | ≥1.24, ≥2.0 |
| Serialización | joblib | ≥1.3 |
| Build system | CMake | 3.22+ |
| OS | Ubuntu LTS (kernel 6.8+) | 24.04 |

## Apéndice B: Convenciones del Proyecto

- **Commits**: Conventional Commits (`feat:`, `fix:`, `chore:`, etc.)
- **Versionado**: semantic-release (CHANGELOG.md + Git tags)
- **Ramas**: `master` (estable), `develop` (integración), `feature/*` (trabajo activo)
- **CI**: GitHub Actions (build, test, lint, release)
- **Licencia**: MIT
