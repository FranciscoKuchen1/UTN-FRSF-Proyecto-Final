<div align="center">

# Guardian FS

### Detección y mitigación de daños frente a ransomware (cryptoware)

**Prueba de Concepto — Proyecto Final UTN FRSF 2026**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Ubuntu%2024.04-orange)](https://ubuntu.com)
[![C standard](https://img.shields.io/badge/C-17-blue.svg)](CMakeLists.txt)

Universidad Tecnológica Nacional — Facultad Regional Santa Fe

| | |
|---|---|
| **Autores** | Gómez Enrico, Ivo · Kuchen, Francisco |
| **Director** | Dr. Pablo Pessolani |
| **Codirector** | Ing. David Harispe |
| **Estado** | v0.2.0-dev — PoC en desarrollo |

</div>

## Qué es

**Guardian FS** es un proxy transparente de filesystem en Linux que intercepta operaciones de E/S con **FUSE**, las evalúa con detección estadística (y ML opcional) y, ante un ataque confirmado, puede **bloquear escrituras**, terminar el proceso y apoyarse en **snapshots ZFS** para recuperar datos.

```
Aplicaciones
    │ syscalls
    ▼
FUSE guardian_fs  ──►  detector (entropía / χ² / scoring por PID)
    │                         │
    │                         ▼
    │                   analyzer (+ ML opcional vía Unix socket)
    │                         │
    └──────── veredicto ──────┤
                              ▼
              NORMAL → deja pasar
              BLOQUEAR → EPERM + SIGKILL + snapshot/rollback ZFS
```

Documentación profunda:

| Doc | Para qué |
|---|---|
| [`docs/developer-guide.md`](docs/developer-guide.md) | Módulos, flujos y decisiones de diseño |
| [`docs/architecture/README.md`](docs/architecture/README.md) | Arquitectura detallada |
| [`docs/ml-architecture.md`](docs/ml-architecture.md) | Pipeline ML, features y dataset |
| [`docs/testing-guide.md`](docs/testing-guide.md) | Tests y scripts operativos |
| [`docs/pending.md`](docs/pending.md) | Pendientes para prueba en VM |

---

## Requisitos

| Dependencia | Mínimo |
|---|---|
| Ubuntu | 24.04 LTS (recomendado) |
| Kernel | 6.8+ |
| libfuse3 / fuse3 | 3.16+ (`libfuse3-dev`) |
| OpenZFS | 2.2+ (`zfsutils-linux`) |
| CMake | 3.22+ |
| GCC | 13+ |
| Python | 3.11+ (solo ML / simulador) |

> **Importante:** montaje, ZFS y pruebas con el simulador van en una **VM de lab**. No ejecutar ransomware ni el simulador agresivo en una PC personal.

---

## Inicio rápido (VM)

### 1. Dependencias y build

```bash
git clone https://github.com/UTN-FRSF/UTN-FRSF-Proyecto-Final.git
cd UTN-FRSF-Proyecto-Final

# Sistema (requiere sudo)
sudo ./scripts/install_deps.sh

# Pool ZFS de prueba (file-backed 2 GB en /tmp/zpool_disk.img)
# Default: dataset tank/data → mountpoint /mnt/guardian_real
sudo ./scripts/zfs_setup.sh

# Compilar guardian_fs + tests
cmake -DCMAKE_BUILD_TYPE=Release -S . -B build
cmake --build build --parallel

# Dependencias Python (ML / simulador)
python3 -m venv .venv
source .venv/bin/activate
pip install -r python/requirements.txt
```

### 2. Montar el filesystem protegido

`scripts/mount.sh` **exige** directorio backend y mountpoint:

```bash
# source_dir = backend real (ZFS)
# mountpoint = vista protegida por FUSE
sudo ./scripts/mount.sh /mnt/guardian_real /mnt/protected tank/data
```

Variables de entorno que usa el daemon:

| Variable | Default | Rol |
|---|---|---|
| `GUARDIAN_REAL_ROOT` | `/zpool/data` | Backend real (la setea `mount.sh`) |
| `GUARDIAN_ZFS_DATASET` | `tank/data` | Dataset para snapshots |
| `GUARDIAN_LOG_PATH` | `/var/log/guardian/events.jsonl` | Log JSONL de eventos |

Verificación:

```bash
mountpoint /mnt/protected
mount | grep fuse
zfs list -t snapshot tank/data
sudo tail -f /var/log/guardian/events.jsonl
```

Desmontar:

```bash
fusermount -u /mnt/protected
# o: sudo umount /mnt/protected
```

### 3. Tests unitarios

```bash
./scripts/run_tests.sh
```

Compila y corre los tests en `tests/unit/` vía CTest (módulos: entropy, detector, canary, ring_buffer, mitigation).

### 4. Rollback ZFS

```bash
sudo ./scripts/rollback.sh tank/data latest
# o snapshot concreto:
sudo ./scripts/rollback.sh tank/data <nombre_snapshot>
```

---

## ML (estado actual y cómo usarlo)

El camino feliz de detección **no depende del ML**: el detector C ya puntúa por PID con entropía, tasas y canaries. El ML es una **segunda opinión asíncrona**.

### Qué hay hoy

| Pieza | Ubicación | Estado |
|---|---|---|
| Servidor de inferencia | `src/ml_server.py` | Implementado (socket `/tmp/guardian_ml.sock`) |
| Entrenamiento offline | `src/train_model.py` | Implementado; espera CSV etiquetado |
| Deps Python | `python/requirements.txt` | Listo |
| Dataset CSV | `data/features_labeled.csv` | **No incluido** — hay que generarlo |
| Export FUSE → CSV de features | — | **Pendiente** (ver `docs/pending.md`) |
| Modelos serializados | `/var/lib/guardian/models/` | Se crean al entrenar |

Si no hay modelos en disco, `ml_server.py` cae a **reglas estadísticas** y sigue respondiendo.

### Levantar el servidor ML (opcional, antes o junto al mount)

```bash
source .venv/bin/activate
python3 src/ml_server.py
# Escucha en /tmp/guardian_ml.sock
```

### Entrenar (cuando exista el CSV)

Formato esperado por `src/train_model.py`:

```text
entropy_mean,entropy_max,entropy_std,entropy_autocorr,
write_rate,bytes_written_rate,rename_rate,unlink_rate,
read_write_ratio,chi2_stat,ext_change_rate,canary_accessed,
unique_dirs,file_type_variety,label
```

`label`: `0` = benigno, `1` = ataque.

```bash
# Desde la raíz del repo, con el CSV en data/features_labeled.csv
mkdir -p data reports
sudo mkdir -p /var/lib/guardian/models
source .venv/bin/activate
python3 src/train_model.py
```

Salida típica: `scaler.pkl`, `rf.pkl`, `xgb.json` en `/var/lib/guardian/models/`, más `reports/feature_importance.png`.

### Cómo obtener el dataset (resumen operativo)

No hay un dataset público listo para este diseño. Las filas son **ventanas de comportamiento de E/S** (14 features por PID), no archivos sueltos.

1. En VM, montar Guardian FS y generar carga **benigna** (editar, compilar, `git`, `tar`/`gzip`, `rsync`, copias).
2. Registrar vectores de features por ventana → CSV con `label=0`.
3. Para **evaluación** (no obligatorio para Isolation Forest): en VM aislada, usar el simulador o muestras controladas y marcar `label=1`.
4. Entrenar con `src/train_model.py`.

Detalle de features, ensemble e Isolation Forest: [`docs/ml-architecture.md`](docs/ml-architecture.md).

---

## Simulador de ransomware (solo VM)

```bash
# Smoke test de patrones de E/S maliciosos — NUNCA en el host personal
python3 scripts/simulate_ransomware.py --target-dir /mnt/protected

python3 scripts/simulate_ransomware.py --target-dir /mnt/protected \
  --mode stealth --file-count 20 --pause-ms 200
```

---

## Estructura real del repositorio

```text
UTN-FRSF-Proyecto-Final/
├── src/
│   ├── guardian_fs.c      # Daemon FUSE (proxy + main)
│   ├── entropy.c          # Shannon, χ², ventana
│   ├── detector.c         # Scoring estadístico por PID
│   ├── canary.c           # Archivos señuelo
│   ├── zfs_snap.c         # Snapshots / rollback (CLI zfs)
│   ├── ring_buffer.c      # Cola lock-friendly de eventos
│   ├── mitigation.c       # Bloqueo / kill
│   ├── analyzer.c         # Hilo async + cliente ML
│   ├── ml_server.py       # Inferencia ML (Unix socket)
│   └── train_model.py     # Entrenamiento offline
├── include/               # Headers públicos de los módulos C
├── tests/
│   ├── unit/              # Tests unitarios + CMakeLists
│   └── test_analyzer.c    # Tests adicionales del analyzer
├── scripts/
│   ├── install_deps.sh
│   ├── zfs_setup.sh
│   ├── mount.sh
│   ├── rollback.sh
│   ├── run_tests.sh
│   └── simulate_ransomware.py
├── python/
│   └── requirements.txt   # Deps ML (el código ML vive en src/)
├── configs/
│   ├── guardian.conf      # Umbrales / rutas (referencia PoC)
│   └── logging.conf
├── docs/                  # Guías y arquitectura
├── CMakeLists.txt
├── CHANGELOG.md
└── README.md
```

---

## Métricas de evaluación (objetivos de la PoC)

| Métrica | Objetivo |
|---|---|
| Pérdida de datos antes del bloqueo | < 1 MB en ataque típico |
| RTO (`zfs rollback`) | < 30 s |
| Overhead de snapshots | < 5% del dataset |
| Detección | TPR / FPR + latencia de E/S inducida por FUSE |

Familias de referencia para evaluación en lab: LockBit 3.0 (Linux), Cl0p, RansomEXX y **simuladores propios**.

> Las muestras reales de malware se ejecutan **solo** en VMs aisladas, sin red al host, según los lineamientos éticos del proyecto.

---

## Scripts — referencia rápida

| Script | Uso correcto |
|---|---|
| `scripts/install_deps.sh` | `sudo ./scripts/install_deps.sh` |
| `scripts/zfs_setup.sh` | `sudo ./scripts/zfs_setup.sh [dataset] [mountpoint]` |
| `scripts/mount.sh` | `sudo ./scripts/mount.sh <source_dir> <mountpoint> [zfs_dataset]` |
| `scripts/rollback.sh` | `sudo ./scripts/rollback.sh <dataset> <snapshot\|latest>` |
| `scripts/run_tests.sh` | `./scripts/run_tests.sh` |
| `scripts/simulate_ransomware.py` | Solo VM; ver `--help` |

---

## Licencia

MIT. Ver [`LICENSE`](LICENSE).

## Referencias principales

- Dakic et al. (2024). *High-Performance Computing Storage Performance — Btrfs and ZFS*. Computers, 13(6).
- O'Kane et al. (2018). *Evolution of ransomware*. IET Networks, 7.
- Beaman et al. (2021). *Ransomware: Recent advances, analysis, challenges*. Computers & Security, 111.
- Lee et al. (2021). *Rcryptect: Real-time detection of cryptographic function in user-space filesystem*. Computers & Security, 112.
