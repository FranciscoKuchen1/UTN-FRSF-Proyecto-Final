<div align="center">

# Guardian FS

### Detección y Mitigación de Daños Frente a Ataques de Ransomware

**Prueba de Concepto — Proyecto Final UTN FRSF 2026**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Build Status](https://github.com/UTN-FRSF/UTN-FRSF-Proyecto-Final/actions/workflows/ci.yml/badge.svg)](https://github.com/UTN-FRSF/UTN-FRSF-Proyecto-Final/actions)
[![semantic-release](https://img.shields.io/badge/%20%20%F0%9F%93%A6%F0%9F%9A%80-semantic--release-e10079.svg)](https://github.com/semantic-release/semantic-release)
[![Conventional Commits](https://img.shields.io/badge/Conventional%20Commits-1.0.0-yellow.svg)](https://conventionalcommits.org)
[![Platform](https://img.shields.io/badge/platform-Ubuntu%2024.04-orange)](https://ubuntu.com)


Universidad Tecnológica Nacional — Facultad Regional Santa Fe

| | |
|---|---|
| **Autores** | Gómez Enrico, Ivo · Kuchen, Francisco |
| **Director** | Dr. Pablo Pessolani |
| **Codirector** | Ing. David Harispe |
| **Año** | 2026 — Primer Cuatrimestre |

</div>


## Descripción

**Guardian FS** es una Prueba de Concepto (PoC) que implementa un sistema de detección y recuperación de datos frente a ataques de *cryptoware* (ransomware cifrador) en sistemas Linux. Combina dos tecnologías complementarias:

- **FUSE (Filesystem in UserSpace)**: intercepción sincrónica de operaciones de E/S para detección temprana mediante análisis estadístico y modelos de aprendizaje automático.
- **ZFS (Zettabyte File System)**: recuperación de datos mediante snapshots inmutables basados en el paradigma Copy-on-Write (CoW).

El sistema actúa como un *proxy transparente* entre las aplicaciones y el sistema de archivos real, evaluando cada operación de escritura antes de dejarla pasar al disco.


## Arquitectura

```
Aplicaciones / Procesos
        │  (syscalls)
        ▼
┌─────────────────────────────────────┐
│     FUSE Guardian (guardian_fs)     │  ← Espacio de usuario
│  fuse_write · fuse_rename · canary  │
└──────────────┬──────────────────────┘
               │  eventos + buffer
               ▼
┌─────────────────────────────────────┐
│       Motor de Análisis             │
│  entropía Shannon · χ² · ratio R/W  │
│  modelo ML (RF + IsolForest + LSTM) │
└──────────────┬──────────────────────┘
               │  veredicto
        ┌──────┴──────┐
        ▼             ▼
  [BLOQUEAR]      [NORMAL]
  EPERM +         continuar
  SIGKILL +
  ZFS snapshot ──► rollback
```

Para más detalles, ver [`docs/architecture/`](docs/architecture/).


## Inicio rápido

### Requisitos

| Dependencia | Versión mínima |
|---|---|
| Ubuntu | 24.04 LTS |
| Linux kernel | 6.8+ |
| libfuse3 / fuse3 | 3.16+ |
| ZFS on Linux (OpenZFS) | 2.2+ |
| CMake | 3.22+ |
| GCC / Clang | 13+ / 17+ |
| Python | 3.11+ |

### Instalación

```bash
# 1. Clonar el repositorio
git clone https://github.com/UTN-FRSF/UTN-FRSF-Proyecto-Final.git
cd UTN-FRSF-Proyecto-Final

# 2. Instalar dependencias del sistema
sudo ./scripts/install_deps.sh

# 3. Configurar entorno ZFS (requiere sudo)
sudo ./scripts/zfs_setup.sh

# 4. Compilar guardian_fs
cmake -DCMAKE_BUILD_TYPE=Release -S . -B build
cmake --build build --parallel

# 5. Instalar dependencias Python
pip install -r python/requirements.txt

# 6. Montar el filesystem protegido
sudo ./scripts/mount.sh
```

### Uso básico

```bash
# Verificar que el filesystem está montado
mount | grep guardian

# Ver snapshots ZFS activos
zfs list -t snapshot tank/data

# Consultar logs de detección en tiempo real
tail -f /var/log/guardian/events.jsonl

# Ejecutar suite de pruebas (entorno virtualizado)
./scripts/run_tests.sh

# Rollback de emergencia al snapshot más reciente
sudo ./scripts/rollback.sh latest
```


## Estructura del proyecto

```
UTN-FRSF-Proyecto-Final/
├── src/
│   ├── guardian_fs/     # Filesystem FUSE principal (proxy transparente)
│   ├── entropy/         # Entropía Shannon, test χ², ventana deslizante
│   ├── detector/        # Motor de detección estadística por PID/ventana
│   ├── canary/          # Archivos señuelo y gestión de alertas
│   ├── zfs_snap/        # Interfaz con ZFS (snapshots, rollback)
│   ├── mitigation/      # Bloqueo de E/S (EPERM) y terminación de proceso
│   └── ml_client/       # Cliente Unix socket → servidor ML Python
├── include/             # Headers compartidos (ring_buffer, stats, types)
├── python/
│   ├── ml_server.py     # Servidor de inferencia (RF + IsolForest + LSTM)
│   ├── train_model.py   # Entrenamiento offline del modelo
│   ├── feature_extractor.py
│   ├── models/          # Modelos entrenados serializados (.pkl, .json)
│   ├── data/            # Datasets de features etiquetados (CSV)
│   └── scripts/         # Utilidades: generación de datasets, evaluación
├── tests/
│   ├── unit/            # Tests unitarios (entropía, detector, canary)
│   ├── integration/     # Tests de integración (FUSE + ZFS end-to-end)
│   └── fixtures/        # Archivos de prueba y simuladores de carga
├── scripts/
│   ├── install_deps.sh  # Instalación de dependencias (Ubuntu 24.04)
│   ├── zfs_setup.sh     # Configuración de zpool y datasets
│   ├── mount.sh         # Montaje del filesystem FUSE
│   ├── rollback.sh      # Rollback a snapshot ZFS
│   └── run_tests.sh     # Ejecución de suite completa de pruebas
├── configs/
│   ├── guardian.conf    # Configuración principal (umbrales, pesos ML)
│   └── logging.conf     # Configuración de logging estructurado (JSON)
├── docs/
│   ├── architecture/    # Diagramas de arquitectura (draw.io / PlantUML)
│   ├── reports/         # Informes de avance y resultados experimentales
│   └── references/      # Bibliografía y papers relacionados
├── .github/
│   ├── workflows/       # CI/CD: build, test, release (GitHub Actions)
│   └── ISSUE_TEMPLATE/  # Templates para bugs y feature requests
├── CMakeLists.txt
├── CHANGELOG.md
├── LICENSE
└── README.md
```


## Métricas de evaluación

El proyecto mide tres variables dependientes principales:

| Métrica | Descripción | Objetivo |
|---|---|---|
| **Pérdida de datos** | Bytes cifrados antes del bloqueo | < 1 MB en ataque típico |
| **RTO** (Recovery Time Objective) | Tiempo de `zfs rollback` | < 30 segundos |
| **Costo de almacenamiento** | Overhead de snapshots ZFS | < 5% del dataset |

Adicionalmente se miden: tasa de detección (TPR), tasa de falsos positivos (FPR), latencia de E/S inducida por el proxy FUSE.


## Familias de ransomware evaluadas

- **LockBit 3.0 (Linux)** — cifrado multihilo, alta velocidad
- **Cl0p (Linux variant)** — evasión de detección, firma parcial
- **RansomEXX** — ataque dirigido a infraestructura crítica
- **Simuladores propios** — scripts de cifrado de archivos en masa (control)

> ⚠️Las muestras reales de malware se ejecutan **exclusivamente** en entornos virtualizados aislados, sin conexión de red, en acuerdo con los lineamientos éticos del proyecto.


## 📄 Licencia

Distribuido bajo la Licencia MIT. Ver [`LICENSE`](LICENSE) para más información.


## 📚 Referencias principales

- Dakic et al. (2024). *High-Performance Computing Storage Performance — Btrfs and ZFS*. Computers, 13(6).
- O'Kane et al. (2018). *Evolution of ransomware*. IET Networks, 7.
- Beaman et al. (2021). *Ransomware: Recent advances, analysis, challenges*. Computers & Security, 111.
- Lee et al. (2021). *Rcryptect: Real-time detection of cryptographic function in user-space filesystem*. Computers & Security, 112.
