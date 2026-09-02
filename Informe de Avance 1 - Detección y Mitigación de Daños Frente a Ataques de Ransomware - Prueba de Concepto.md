# **Detección y Mitigación de Daños Frente a Ataques de *Ransomware* \- Prueba de Concepto**

## **Informe de Avance 1**

Gómez Enrico, Ivo (Email: ivogomezenrico2015@gmail.com, Legajo: 28685);
Kuchen, Francisco (Email: franciscokuchen1@gmail.com, Legajo: 27930);
Universidad Tecnológica Nacional, Facultad Regional Santa Fe
Proyecto Final
Director: Dr. Pablo Pessolani
Codirector: Ing. David Harispe

**Fecha de entrega:** 30/08/2026 — Primer Cuatrimestre 2026

---

# 1. Introducción

El presente documento constituye el **Informe de Avance 1** del Proyecto Final *"Detección y Mitigación de Daños Frente a Ataques de Ransomware – Prueba de Concepto"*, conforme al contenido propuesto en el informe del proyecto: presentación de la arquitectura general del entorno, evidencia de la configuración inicial del sistema de archivos ZFS y de las muestras de ransomware, análisis de herramientas de detección con la elección de la alternativa adoptada, y el desarrollo inicial de la herramienta.

El proyecto tiene como objetivo evaluar la efectividad de distintas estrategias y herramientas para la detección de ataques de ransomware y la recuperación de datos, desarrollando una Prueba de Concepto (PoC) que combina la intercepción de operaciones de E/S mediante FUSE (Filesystem in UserSpace) con la recuperación de datos mediante snapshots de ZFS (Zettabyte File System).

# 2. Estado de Avance respecto del Cronograma

La siguiente tabla resume el estado de las etapas metodológicas definidas en el cronograma del proyecto al momento de este informe:

| Etapa (Cronograma) | Tareas Principales | Estado |
| :--- | :--- | :---: |
| **Mes 1** — Relevamiento y Diseño | Estudio del campo, selección de herramientas, diseño de arquitectura, definición de métricas y escenarios. | ✅ Completado |
| **Mes 2** — Preparación paralela | Despliegue de VMs y volúmenes ZFS. Búsqueda y recolección de muestras de ransomware (Linux). | ✅ Completado |
| **Mes 3** — Análisis, elección y desarrollo de la herramienta de detección | Análisis y elección de herramientas de detección. Desarrollo inicial de la herramienta elegida. | ✅ Completado |
| **Mes 4** — Implementación avanzada | Mejora de la lógica de detección de anomalías e interrupción del proceso maligno. | 🔄 En curso |
| **Mes 5** — Integración de modelo de Machine Learning | Elaboración del modelo de ML e incorporación a la herramienta. | 🔄 Adelantado: infraestructura del pipeline implementada |

**Síntesis:** al cierre de este informe se encuentran completas las etapas de relevamiento y diseño, la infraestructura del entorno de pruebas (VM aislada con ZFS), el análisis y elección de la estrategia de detección, y una primera implementación funcional de la herramienta —denominada **Guardian FS**— que compila en su totalidad y cuenta con pruebas unitarias automatizadas. Adicionalmente, se ha adelantado trabajo correspondiente a la integración de Machine Learning (servidor de inferencia, script de entrenamiento y registro de features), previsto originalmente para el Mes 5.

# 3. Arquitectura General del Entorno

## 3.1. Visión general de la solución

**Guardian FS** es un proxy transparente de sistema de archivos para Linux que intercepta las operaciones de E/S mediante FUSE, las evalúa con detección estadística (y, opcionalmente, con modelos de Machine Learning) y, ante un ataque confirmado, bloquea las escrituras, termina el proceso atacante y se apoya en snapshots de ZFS para la recuperación de los datos.

```
 Aplicaciones (incluye ransomware / simulador)
     │ syscalls (open, write, rename, unlink, ...)
     ▼
 FUSE guardian_fs  ──►  detector (entropía / χ² / tasas / scoring por PID / canaries)
     │                         │
     │                         ▼
     │                   analyzer (hilo asíncrono + ML opcional vía Unix socket)
     │                         │
     └──────── veredicto ──────┤
                               ▼
               NORMAL   → deja pasar la operación
               BLOQUEAR → EPERM + SIGKILL al proceso + snapshot de emergencia ZFS
                          (recuperación vía rollback de snapshots)
```

El diseño responde directamente a las Fases Metodológicas del proyecto:

- **Fase 1 (Modelado de Amenazas y Perfilado de E/S):** el detector implementa la línea base de comportamiento y los umbrales de anomalía: tasas de sobreescritura, medición de entropía (Shannon y χ²) sobre los buffers de datos, secuencias masivas de open/write/rename/unlink y archivos señuelo (canaries).
- **Fase 2 (Infraestructura Confinada):** el entorno opera en una máquina virtual de laboratorio aislada (sin red hacia el host y sin volúmenes compartidos), con el pool ZFS y sus datasets configurados y snapshots periódicos e inmutables (Sección 4).
- **Fase 3 (Instrumentación del Prototipo):** el daemon FUSE retiene la operación de escritura, evalúa el contenido y emite el veredicto de bloqueo antes de que los datos lleguen al dispositivo de bloques ZFS (Sección 7).

## 3.2. Componentes del entorno

| Componente | Rol |
| :--- | :--- |
| **VM de laboratorio** (Ubuntu LTS, VirtualBox) | Entorno confinado de ejecución. Aislamiento de red y sin volúmenes compartidos con el host (mitigación del Riesgo 2 del proyecto). |
| **Pool ZFS (`tank`) y dataset (`tank/data`)** | Backend de almacenamiento con paradigma Copy-on-Write; base de la recuperación mediante snapshots. |
| **Guardian FS (daemon FUSE)** | Capa de intercepción, detección y mitigación montada sobre el dataset ZFS. |
| **Pipeline ML (opcional)** | Servidor de inferencia (`ml_server.py`) que actúa como segunda opinión asíncrona del detector estadístico. |
| **Simulador de ransomware** | Generador controlado de patrones de E/S maliciosos para la fase de calibración. |
| **Scripts de operación** | Instalación de dependencias, montaje, snapshots, rollback y tests automatizados. |

# 4. Configuración Inicial del Sistema de Archivos ZFS (Evidencia)

## 4.1. Creación del pool y dataset

Se desarrolló el script `scripts/zfs_setup.sh` (idempotente) que automatiza el despliegue del almacenamiento ZFS del entorno de pruebas:

1. Crea un pool ZFS *file-backed* de 2 GB (`/tmp/zpool_disk.img`) denominado `tank`, si no existe.
2. Crea el dataset `tank/data` con punto de montaje `/mnt/guardian_real`.
3. Aplica propiedades orientadas al caso de uso: `compression=lz4` (reducción del costo de almacenamiento) y `atime=off` (menos escrituras innecesarias).
4. Reporta el estado del pool (`zpool list`) y del dataset (`zfs list`) como verificación.

Ejecución:

```bash
sudo ./scripts/install_deps.sh    # instala zfsutils-linux, libfuse3-dev, cmake, gcc, etc.
sudo ./scripts/zfs_setup.sh       # crea pool 'tank' y dataset 'tank/data'
zfs list -t snapshot tank/data    # verificación de snapshots
```

## 4.2. Integración de ZFS con la herramienta de detección

El módulo `src/zfs_snap.c` integra la recuperación ZFS dentro del ciclo de detección/mitigación de Guardian FS, invocando la CLI de ZFS (`zfs(8)`) de forma controlada:

- **Snapshots periódicos:** al iniciar el daemon, `zfs_snapshot_schedule()` lanza un hilo que genera snapshots `tank/data@guardian_auto_<timestamp>` cada 60 segundos, con poda automática de los más antiguos (retención acotada). Esto limita la pérdida máxima de datos ante un ataque a la ventana transcurrida desde el último snapshot.
- **Snapshot de emergencia:** ante un veredicto de bloqueo, `guardian_fs.c` ejecuta `zfs_snapshot_emergency()`, que crea `tank/data@guardian_emergency_<timestamp>` para preservar el estado exacto del momento de la detección (evidencia forense y punto de retorno conocido).

## 4.3. Recuperación (rollback)

El script `scripts/rollback.sh` materializa la recuperación de datos:

```bash
sudo ./scripts/rollback.sh tank/data latest     # vuelve al snapshot más reciente
sudo ./scripts/rollback.sh tank/data <nombre>   # o a un snapshot específico
```

Esta combinación —snapshots inmutables CoW + rollback— es el mecanismo principal de recuperación frente a la alteración masiva de archivos, en línea con la fundamentación del proyecto (Dakic et al., 2024). Los objetivos de la PoC para esta capa son: RTO < 30 s y sobrecarga de almacenamiento < 5 % del dataset.

# 5. Simulación de Ataques y Muestras de Ransomware

## 5.1. Simulador propio (fase de calibración)

Se desarrolló `scripts/simulate_ransomware.py`, un simulador de comportamiento tipo ransomware que genera sobre el punto de montaje protegido los patrones de E/S característicos de un ataque de cifrado masivo (secuencias open/write/rename con datos de alta entropía), con parámetros controlables:

```bash
# Solo en la VM de laboratorio
python3 scripts/simulate_ransomware.py --target-dir /mnt/protected
python3 scripts/simulate_ransomware.py --target-dir /mnt/protected \
    --mode stealth --file-count 20 --pause-ms 200
```

El simulador incluye además el modo `--avoid-canary`, que evita deliberadamente los archivos señuelo, permitiendo generar datos de entrenamiento de ataque más realistas para el modelo de Machine Learning. El simulador es la herramienta de la **fase de calibración** (Fase 4 metodológica), previa a la ejecución de muestras reales.

## 5.2. Muestras reales de ransomware

Se recolectaron muestras reales de familias de ransomware con variantes para Linux, las cuales se encuentran almacenadas de forma aislada en la VM de laboratorio (sin red y sin volúmenes compartidos), conforme a la gestión del Riesgo 2 del proyecto. Estas muestras se utilizarán en la **fase de destrucción** (Fase 4: Ejecución Experimental Controlada), mientras que la etapa actual de calibración y desarrollo se realiza exclusivamente con el simulador propio. Las familias de referencia definidas para la evaluación son LockBit 3.0 (Linux), Cl0p y RansomEXX.

# 6. Análisis de Herramientas de Detección y Elección

## 6.1. Alternativas evaluadas

En el marco del Mes 3 del cronograma, se analizaron las categorías de herramientas disponibles para la detección de ransomware y la recuperación de datos:

| Alternativa | Fortalezas | Limitaciones para este proyecto |
| :--- | :--- | :--- |
| **Antivirus / antimalware tradicionales** | Maduros, base de firmas amplia. | Detección mayormente por firmas (tardía frente a variantes nuevas); no evitan el cifrado de grandes volúmenes antes de detectar; no integran recuperación de datos. |
| **IDS / EDR (detección de intrusiones)** | Monitoreo de comportamiento a nivel de host/red. | Suelen detectar cuando el ataque ya está avanzado; no operan sobre el punto de escritura del filesystem; no recuperan datos. |
| **Backups periódicos** | Recuperación probada. | El malware puede cifrar las propias copias antes de ser detectado; RTO dependiente del esquema de copias (O'Kane et al., 2018). |
| **Solo CoW / snapshots (ZFS, Btrfs)** | Recuperación exacta y eficiente mediante snapshots inmutables (Dakic et al., 2024). | No detectan el ataque: son reactivos. Los datos permanecen alterados hasta ejecutar el rollback. |
| **Detección en el filesystem (FUSE)** | Intercepción sincrónica de la E/S en espacio de usuario: permite evaluar el contenido y bloquear la escritura **antes** de que llegue al disco; trabajo relacionado: Rcryptect (Lee et al., 2021). | Requiere desarrollo propio y ajuste fino de umbrales para no degradar el rendimiento (Riesgo 1 del proyecto). |

## 6.2. Elección adoptada

Se resolvió **diseñar e implementar una herramienta propia basada en FUSE (Guardian FS)**, en lugar de adoptar una solución existente, por los siguientes motivos:

1. **Detección antes de la persistencia:** FUSE permite retener la operación de escritura, evaluarla (entropía, χ², tasas, canaries) y emitir un veredicto de bloqueo antes del vaciado hacia el dispositivo de bloques, algo que ninguna de las alternativas evaluadas ofrece de forma integrada.
2. **Integración detección + recuperación:** ninguna herramienta analizada combina la detección activa con la recuperación mediante snapshots CoW en una misma arquitectura, que es precisamente la hipótesis a validar empíricamente en este proyecto.
3. **Control experimental:** el diseño experimental del proyecto (variable independiente: sin protección / mitigación estática ZFS / defensa activa ZFS+detección) requiere control total sobre la lógica de detección, los umbrales y la telemetría para medir pérdida de datos, RTO y overhead — algo imposible con herramientas cerradas.
4. **Mitigación del Riesgo 1:** operar en espacio de usuario (FUSE) evita modificaciones al kernel, conteniendo el riesgo de kernel panic/deadlocks al entorno virtualizado, conforme a la estrategia de riesgo definida.
5. **Detección escalonada:** la arquitectura admite una detección estadística de baja latencia en C como camino principal, con un modelo de Machine Learning como segunda opinión asíncrona, alineado con el prototipado evolutivo planificado (de intercepción pasiva a bloqueo síncrono).

# 7. Desarrollo Inicial de la Herramienta: Guardian FS

## 7.1. Módulos implementados

La herramienta se implementa en C (estándar C17, compilada con `-Wall -Wextra -Wpedantic`) con una arquitectura modular:

| Módulo | Archivo | Función |
| :--- | :--- | :--- |
| Daemon FUSE | `src/guardian_fs.c` | Proxy transparente de filesystem: intercepta las operaciones, orquesta el veredicto y ejecuta la mitigación. |
| Entropía | `src/entropy.c` | Entropía de Shannon, prueba χ² y ventana deslizante sobre buffers de datos. |
| Detector | `src/detector.c` | Scoring estadístico por PID: tasas de escritura/rename/unlink, entropía y canaries. |
| Canary | `src/canary.c` | Archivos señuelo cuya modificación es indicador casi inequívoco de ataque. |
| Ring buffer | `src/ring_buffer.c` | Cola de eventos lock-friendly entre el camino de E/S y el análisis asíncrono. |
| Analyzer | `src/analyzer.c` | Hilo asíncrono que consume eventos y consulta al servidor ML (cliente por Unix socket, con reconexión). |
| Mitigación | `src/mitigation.c` | Bloqueo de operaciones (EPERM) y terminación del proceso atacante. |
| Snapshots ZFS | `src/zfs_snap.c` | Snapshots periódicos y de emergencia, rollback (Sección 4). |

## 7.2. Compilación y pruebas

- El proyecto **compila completo (los 8 módulos) con 0 errores y 0 warnings** en la VM de laboratorio, mediante CMake (`cmake -S . -B build && cmake --build build`).
- Se implementaron **28 pruebas unitarias** sobre 5 módulos (entropy, detector, canary, ring_buffer, mitigation), ejecutadas automáticamente vía CTest (`scripts/run_tests.sh`), **todas con resultado exitoso**.

## 7.3. Pipeline de Machine Learning (adelanto respecto del cronograma)

Aunque la integración de ML está prevista para el Mes 5, se adelantó la infraestructura completa del pipeline:

| Pieza | Ubicación | Estado |
| :--- | :--- | :--- |
| Servidor de inferencia | `src/ml_server.py` | Implementado; escucha en un Unix socket (`/tmp/guardian_ml.sock`). Si no hay modelo entrenado, degrada a reglas estadísticas. |
| Entrenamiento offline | `src/train_model.py` | Implementado; espera CSV etiquetado con 14 features por ventana de comportamiento de E/S por PID. |
| Registro de features | `data/feature_logger.py` + `scripts/ml_proxy.py` | Implementados; capturan los vectores de features que el analyzer envía al servidor ML, para construir el dataset de entrenamiento. |
| Modelo | — | Ensemble previsto: Random Forest + XGBoost (con Isolation Forest para detección no supervisada). Entrenamiento pendiente de la generación del dataset completo. |

El camino feliz de detección **no depende del ML**: el detector estadístico en C puntúa y bloquea de forma autónoma; el modelo actúa como segunda opinión asíncrona, preservando la baja latencia del camino de E/S.

## 7.4. Automatización de pruebas del pipeline

Se desarrollaron scripts para verificar el pipeline completo (build → ml_server → ml_proxy → montaje FUSE → simulador) de forma reproducible en la VM:

- `scripts/test_ml_pipeline.sh` — prueba integral del pipeline desde cero (incluye creación automática del entorno Python con sus dependencias).
- `scripts/quick_test_ml.sh` — verificación rápida.
- `scripts/diagnose_ml.sh` — diagnóstico componente por componente (entorno Python, servidor, proxy, FUSE).

## 7.5. Documentación

Se generó documentación técnica completa del estado real del sistema: `docs/architecture/README.md` (arquitectura detallada), `docs/developer-guide.md` (módulos, flujos y decisiones de diseño), `docs/ml-architecture.md` (pipeline ML, features y dataset), `docs/testing-guide.md` (tests y scripts operativos) y `README.md` (guía de inicio rápido en VM).

# 8. Próximos Pasos (hacia el Informe de Avance 2)

1. **Generación del dataset de features:** ejecutar cargas benignas y de ataque (simulador) en la VM para construir el CSV etiquetado (`label=0/1`) y entrenar el modelo (`train_model.py`).
2. **Completar features parciales del analyzer** (std, autocorrelación, χ², entre otras) y el exportador FUSE → CSV.
3. **Pruebas de integración FUSE+ZFS en la VM:** validar el bloqueo por entropía y canaries, el snapshot de emergencia y el rollback (`scripts/rollback.sh`) frente al simulador.
4. **Implementación avanzada (Mes 4):** ajuste fino de umbrales de detección y endurecimiento de la mitigación.
5. **Medición de métricas de la PoC:** pérdida de datos antes del bloqueo (< 1 MB objetivo), RTO del rollback (< 30 s), overhead de snapshots (< 5 %) y latencia de E/S inducida por FUSE.

**Riesgos activos:** se mantiene vigente el Riesgo 1 (degradación de rendimiento por intercepción FUSE), mitigado mediante el prototipado evolutivo y el despliegue confinado en VM; y el Riesgo 3 (ineficacia frente a muestras no perfiladas), que se atacará con la campaña de pruebas del Mes 6 sobre múltiples familias.

# 9. Referencias

- Dakic, V., Kovac, M., & Videc, I. (2024). High-Performance Computing Storage Performance and Design Patterns—Btrfs and ZFS Performance for Different Use Cases. *Computers*, 13(6), 139. https://doi.org/10.3390/computers13060139
- Lee, S. et al. (2021). Rcryptect: Real-time detection of cryptographic function in the user-space filesystem. *Computers & Security*, 112, 102512. https://doi.org/10.1016/j.cose.2021.102512
- O'Kane, P., Sezer, S. and Carlin, D. (2018). Evolution of ransomware. *IET Networks*, 7: 321-327. https://doi.org/10.1049/iet-net.2017.0207
- Beaman, C. et al. (2021). Ransomware: Recent advances, analysis, challenges and future research directions. *Computers & Security*, 111, 102490. https://doi.org/10.1016/j.cose.2021.102490
