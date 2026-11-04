<div align="center">

# Guardian FS

### Un firewall para tus archivos: detecta ransomware mientras cifra, lo frena y deshace el daño

**Prueba de Concepto — Proyecto Final UTN FRSF 2026**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Ubuntu%2024.04-orange)](https://ubuntu.com)

Universidad Tecnológica Nacional — Facultad Regional Santa Fe

| | |
|---|---|
| **Autores** | Gómez Enrico, Ivo · Kuchen, Francisco |
| **Director** | Dr. Pablo Pessolani |
| **Codirector** | Ing. David Harispe |
| **Estado** | v0.2.0-dev — PoC funcional end-to-end |

</div>

---

## La idea en dos minutos

Un ransomware cifra tus archivos: los lee, escribe una versión cifrada y los renombra (`.docx` → `.locked`). Cuando te das cuenta, ya es tarde.

Guardian FS se instala **entre** los programas y el disco. Todos los archivos que se guardan pasan por él, y en una fracción de milisegundo decide: ¿esto parece un archivo normal, o parece datos cifrados por un atacante?

Si decide que es un ataque, hace tres cosas al instante:

1. **Bloquea** la escritura (los bytes cifrados jamás llegan al disco).
2. **Mata** al proceso atacante.
3. **Toma una fotografía del disco** (snapshot de ZFS) del estado previo al daño, para poder volver atrás en segundos.

```
Programas → [Guardian FS revisa cada escritura] → Disco ZFS (con fotos de respaldo)
                     │
             ¿parece ransomware? → bloquear + matar + fotografiar
```

Para decidir, no mira *quién* es el programa (los antivirus de firmas fallan contra ransomware nuevo), sino *cómo se comporta*: datos súper revueltos escritos a velocidad, renombrados masivos de extensión, recorrido de carpetas… y una trampa: archivos señuelo con nombres tentadores que ningún programa honesto modificaría.

**Documentación por interés:**

| Si querés… | Leé |
|---|---|
| Entender cómo funciona (con diagramas) | [`docs/pipeline.md`](docs/pipeline.md) |
| Arrancar el proyecto desde cero | Esta página, sección "Puesta en marcha" |
| Entender el módulo de machine learning | [`docs/ml-architecture.md`](docs/ml-architecture.md) |
| Contribuir código | [`docs/developer-guide.md`](docs/developer-guide.md) |
| Saber qué verifica cada test | [`docs/tests.md`](docs/tests.md) |
| Ver la bitácora de la última puesta en marcha | [`docs/cambios-2026-11-04.md`](docs/cambios-2026-11-04.md) |

---

## Puesta en marcha (en una VM de pruebas)

> **Importante:** montar el filesystem y correr el simulador de ransomware es para una **máquina virtual de laboratorio**, no para tu computadora personal. Todo lo demás (tests, compilación) es inofensivo.

### Requisitos

- Ubuntu 24.04 (probado también en 25.10), kernel 6.8+
- Unos 10 GB libres y 4 GB de RAM

### Paso 1 — Instalar dependencias y compilar

```bash
# Herramientas del sistema (pide contraseña de sudo)
sudo ./scripts/install_deps.sh

# Compilar el daemon y los tests
cmake -DCMAKE_BUILD_TYPE=Release -S . -B build
cmake --build build --parallel

# Comprobar que todo está sano (deben pasar 6/6 suites)
./scripts/run_tests.sh

# Entorno Python para la parte de machine learning
python3 -m venv .venv
source .venv/bin/activate
pip install -r python/requirements.txt
```

### Paso 2 — Crear el disco de pruebas con ZFS

```bash
# Crea un "disco" de 2 GB (un archivo) con ZFS adentro, para poder
# fotografiar y restaurar sin necesidad de hardware extra
sudo ./scripts/zfs_setup.sh          # deja el dataset en /mnt/guardian_real
```

### Paso 3 — Montar el filesystem protegido

```bash
# /mnt/protected es la carpeta "protegida": todo lo que se guarde ahí
# pasa por Guardian FS
sudo ./scripts/mount.sh /mnt/guardian_real /mnt/protected tank/data
```

Cualquier cosa que se escriba en `/mnt/protected` está siendo vigilada. Para desmontar: `sudo umount /mnt/protected`.

Configuración por variables de entorno (todas opcionales):

| Variable | Default | Para qué |
|---|---|---|
| `GUARDIAN_LOG_PATH` | `/var/log/guardian/events.jsonl` | Dónde se anotan los eventos (JSON, una línea por evento) |
| `GUARDIAN_SHADOW_MODE` | off | `1` = modo sombra: anota los veredictos pero **no** bloquea ni mata. Ideal para observar sin interferir |

### Paso 4 (opcional) — Prender la segunda opinión ML

```bash
# En otra terminal (con el venv activo)
python3 src/ml_server.py
```

Sin este servidor el sistema funciona igual (detección estadística pura); con él, cada 5 segundos el sistema consulta a un modelo entrenado que refina los veredictos.

### Paso 5 — Comprobar que la defensa funciona (solo VM)

```bash
# Simula un ransomware cifrando 40 archivos dentro del mount.
# Resultado esperado: el simulador escribe los primeros archivos,
# Guardian lo mata a mitad de camino y queda un snapshot de emergencia.
python3 scripts/simulate_ransomware.py --target-dir /mnt/protected --file-count 40

# La evidencia:
sudo tail /var/log/guardian/events.jsonl        # eventos: sospecha → bloqueo → proceso muerto
sudo zfs list -t snapshot tank/data             # snapshot de emergencia creado
```

Y para volver el disco al estado previo al ataque:

```bash
sudo ./scripts/rollback.sh tank/data latest     # tarda ~1 segundo
```

---

## Los números que persigue la PoC

| Objetivo | Valor | Estado actual |
|---|---|---|
| Datos perdidos antes del freno | < 1 MB | ✔ el ataque muere en el primer archivo en muchos casos |
| Tiempo de recuperación (rollback) | < 30 s | ✔ ~1 s medido |
| Costo de los snapshots | < 5% del dataset | ✔ despreciable (ZFS solo anota cambios) |
| Detección del ML | ver métricas | ✔ ROC-AUC 1.00 / 0.9997 (con datos de simulador — ver [`docs/cambios-2026-11-04.md`](docs/cambios-2026-11-04.md) para la letra chica) |
| Molestia a usuarios legítimos | mínima | ✔ backups, gzip y compilaciones pasan sin bloqueo |

---

## Guía rápida de scripts

| Script | Qué hace | Cuándo usarlo |
|---|---|---|
| `install_deps.sh` | Instala herramientas del sistema | Una sola vez |
| `zfs_setup.sh` | Crea el disco de pruebas ZFS | Una sola vez |
| `mount.sh` | Monta la carpeta protegida | Cada vez que quieras protección activa |
| `rollback.sh` | Vuelve el disco a una foto anterior | Después de un incidente |
| `run_tests.sh` | Compila y corre los 61 tests | Después de cada cambio de código |
| `simulate_ransomware.py` | Simula ataques (modos, velocidad, procesos) | Solo en VM, para probar la defensa |
| `collect_training_data.sh` | Genera datos etiquetados para el ML | Para entrenar/reentrenar el modelo |
| `test_ml_pipeline.sh` | Prueba de humo del circuito ML completo | Después de tocar algo del ML |

---

## Estructura del repositorio

```
├── src/            El sistema en C (capa FUSE, detector, señuelos, snapshots…)
│                   + los dos programas Python del ML
├── include/        Headers de los módulos C
├── tests/          Tests unitarios (uno por módulo)
├── scripts/        Operativa: instalación, montaje, simulador, recolección de datos
├── docs/           Esta documentación
├── configs/        Archivos de referencia (el binario se configura por variables de entorno)
├── data/           El dataset de entrenamiento se genera acá (no se commitea)
└── build/          Salida de compilación
```

---

## Licencia y referencias

Código bajo licencia MIT. Referencias académicas principales:

- O'Kane et al. (2018). *Evolution of ransomware*. IET Networks, 7.
- Beaman et al. (2021). *Ransomware: Recent advances, analysis, challenges*. Computers & Security, 111.
- Lee et al. (2021). *Rcryptect: Real-time detection of cryptographic function in user-space filesystem*. Computers & Security, 112.
- Dakic et al. (2024). *High-Performance Computing Storage Performance — Btrfs and ZFS*. Computers, 13(6).

> Las muestras reales de malware se ejecutan **solo** en VMs aisladas, sin red al host, según los lineamientos éticos del proyecto.
