# Guardian FS — ML Pipeline Testing Scripts

Scripts para probar el pipeline completo de feature logging y recolectar datos de entrenamiento ML.

## Scripts disponibles

### 1. `test_ml_pipeline.sh` — Test completo desde cero (+ recolección)
Configura el entorno Python, compila el proyecto, prepara directorios, ejecuta todos los componentes, verifica resultados y al terminar lanza la recolección de datos de entrenamiento.

```bash
./scripts/test_ml_pipeline.sh [label] [collect_rounds]
```

**Parámetros:**
- `label`: 1=ransomware (default), 0=benigno
- `collect_rounds`: rondas de `collect_training_data.sh` después del test (default: 5, usar 0 para saltear)

**Qué hace:**
1. Verifica requisitos del sistema
2. Crea venv e instala dependencias Python si es necesario
3. Compila el proyecto
4. Prepara directorios de prueba
5. Inicia ml_server.py
6. Inicia ml_proxy.py
7. Monta FUSE (con `allow_other` solo si `/etc/fuse.conf` lo habilita)
8. Ejecuta simulador o workload benigno (si la mitigación mata el simulador, el test continúa: es detección exitosa)
9. Verifica resultados
10. Limpia el stack de test (preserva logs)
11. Ejecuta `collect_training_data.sh` con las rondas indicadas

### 2. `collect_training_data.sh` — Recolector de datos etiquetados
Levanta su propio stack (ml_server + ml_proxy + FUSE) y recolecta datos de ambas clases en dos fases:

```bash
./scripts/collect_training_data.sh [rounds]
```

**Fases:**
- **Fase 1 (label 1)**: `rounds` corridas del simulador variando `--mode` (full/fast/stealth), `--file-count` (30-79), `--pause-ms` (0/20/40), `--workers` (1-4), `--partial-encrypt` (50-100%) y cada 4ª ronda `--no-rename` (detección solo por entropía); rondas impares con `--realistic`. Corre en **shadow mode** (sin kill) → cada ataque aporta features de TODAS sus ventanas (no solo la primera).
- **Fase 2 (label 0)**: `rounds` workloads benignos (copias de src/ y docs/, tar.gz, appends a log, CSVs, copia de binario). Ventanas de 5s con ≥10 writes.

**Proxy por ronda con `--tag atk_rN`/`ben_rN`** → columna `session` del CSV: `train_model.py` evalúa con `StratifiedGroupKFold` por sesión (sin leakage de ventanas contiguas entre train y test).

Todo opera sobre `/tmp/guardian_collect_*` — no toca datos reales. Requiere proyecto compilado y venv (correr `test_ml_pipeline.sh` una vez antes).

Para un dataset de entrenamiento serio: `./scripts/collect_training_data.sh 100` (o más).

### 3. `quick_test_ml.sh` — Test rápido (proyecto ya compilado)
Configura el entorno Python y salta la compilación. Útil cuando ya hiciste build y solo querés probar el pipeline.

```bash
./scripts/quick_test_ml.sh [label]
```

### 4. `diagnose_ml.sh` — Diagnóstico por componentes
Prueba la cadena ML sin FUSE: venv/deps → ml_server → ml_proxy → feature sintética → CSV. Úsalo primero cuando algo falla.

```bash
./scripts/diagnose_ml.sh
```

### 5. `cleanup_test.sh` — Limpieza manual
Limpia procesos, mountpoints (test y collect), sockets y directorios de prueba. No borra los logs.

```bash
./scripts/cleanup_test.sh
```

## Simulador — flags de realismo

`simulate_ransomware.py` calibra sus perfiles con comportamiento documentado de familias reales (LockBit, Cl0p, RansomEXX):

| Flag | Qué simula | Por qué importa |
|---|---|---|
| `--workers N` | N procesos paralelos atacando subsets disjuntos | Cada worker = PID propio → **diluye el scoring per-PID** (evasión real de ransomware multi-proceso) |
| `--partial-encrypt PCT` | Cifra solo los primeros PCT% de cada archivo (intermitente, estilo LockBit) | Menos bytes escritos de alta entropía → pone a prueba los umbrales de tasa |
| `--realistic` | Tamaños log-uniformes 16KB–8MB, writes en chunks de 256KB, jitter de pausas, ~5% de archivos salteados | Distribuciones de un filesystem real, no payloads planos |
| `--mmap` | Escribe vía mmap en vez de `write()` | **Prueba de bypass**: mmap no pasa por `gfs_write` → el detector no ve entropía. NO usar para training (no genera features) |
| `--seed N` | Reproducibilidad de toda la corrida | Runs comparables entre configuraciones |

## Shadow mode (log-only)

`GUARDIAN_SHADOW_MODE=1` (o `true`/`yes`/`on`) hace que el daemon **registre** los veredictos BLOCK sin ejecutar la mitigación (sin EPERM, sin SIGKILL, sin snapshot de emergencia):

- **Recolección de datos**: los ataques generan features de *todas* sus ventanas (no mueren en la primera) → muchas más filas label=1 y más variadas.
- **Medición de FPs**: correr workloads benignos reales sin riesgo de kills.
- Los eventos en `events.jsonl` llevan `"mode":"shadow"` para distinguirlos de corridas enforce.
- `collect_training_data.sh` lo activa por defecto; override con `GUARDIAN_SHADOW_MODE=0`.

## Verificación anti-FP (VM)

Workflows benignos que tocan canaries **no deben morir** (leer canaries
read-only no arma el kill — un ransomware los abre para ESCRIBIR):

```bash
# cp dentro del mount: lee canaries read-only, luego escribe copias
mkdir -p /mnt/protected/docs_copy
cp -r /mnt/protected/docs /mnt/protected/docs_copy        # debe COMPLETAR

# grep con salida dentro del mount
grep -r --exclude=grep_out.txt "Confidential" /mnt/protected \
    > /mnt/protected/grep_out.txt        # debe COMPLETAR
# (--exclude: sin él, grep se niega a grepear su propio archivo de salida)
```

El kill ahora verifica identidad: en `events.jsonl` los eventos
`process_killed` / `kill_skipped` muestran la decisión (`"result":"killed"`,
`"pid_reused"`, `"already_gone"`). Un ataque debe terminar en `process_killed`;
un PID reutilizado por un proceso inocente **nunca** recibe SIGKILL.

**Nota sobre `events.jsonl`**: el daemon crea `/var/log/guardian/` al iniciar
(sudo). Si corre sin permisos (p.ej. montado por un usuario sin sudo), los
eventos van a stderr — en los scripts quedan capturados en `logs/fuse.log`.

## Verificación del freno global (VM)

Un ataque multiproceso diluye el scoring per-PID; el freno global lo atrapa
por el agregado (escrituras con firma de cifrado: entropía alta + χ² uniforme):

```bash
python3 scripts/simulate_ransomware.py --target-dir /mnt/protected --workers 4
# Esperado: "GLOBAL BRAKE armed" en el log del daemon + eventos con "brake":1
grep '"brake":1' /var/log/guardian/events.jsonl | head -3
```

Un workload benigno de baja entropía durante el freno nunca es bloqueado.

## Flujo de datos

```
simulador.py / workload benigno
    ↓ escribe en el mountpoint FUSE
FUSE (guardian_fs)
    ↓ intercepta syscalls → ring buffer
analyzer.c
    ↓ flush por tiempo: cada ventana de 5s con ≥10 writes por PID → envía JSON
    ↓ (también flushea ventanas de procesos ya matados por la mitigación)
ml_proxy.py
    ↓ loggea features → CSV, forward a backend
ml_server.py
    ↓ predice veredicto
analyzer.c recibe veredicto (si la conexión se cae, reconecta cada 5s)
```

**Granularidad**: 1 fila del CSV = 1 PID × 1 ventana de 5s con ≥10 writes.

## Archivos generados

- `data/training_data.csv` — Features loggeadas (14 features + label + **session** + timestamp + pid). La columna session (ronda de recolección) permite evaluar agrupado por sesión sin leakage. CSVs viejos sin session: `train_model.py` deriva la sesión por gaps de timestamp. Es el dataset que consume `src/train_model.py`. Gitignored.
- `logs/` — Logs persistentes de cada componente (gitignored, sobreviven reinicios):
  - `ml_server.log`, `ml_proxy.log`, `fuse.log` (test_ml_pipeline / quick_test)
  - `collect_ml_server.log`, `collect_ml_proxy_label{0,1}.log`, `collect_fuse.log`, `collect_attack_round*.log` (recolección)
  - `diagnose_features.csv`, `diagnose_ml_server.log`, `diagnose_ml_proxy.log` (diagnóstico)

## Troubleshooting

### 0 features loggeadas
- Correr `./scripts/diagnose_ml.sh` — aísla si el problema es la cadena ML o el tramo FUSE
- Verificar que el simulador escribió en el mountpoint de FUSE
- Revisar logs: `tail -20 logs/fuse.log` (o `logs/collect_fuse.log`)
- Verificar que analyzer.c dice `Connected to ML server` / `Reconnected to ML server`
- Recordar: se necesitan ≥10 writes en la ventana de 5s por PID

### FUSE no monta
- Verificar que libfuse3 está instalado: `sudo apt install libfuse3-dev`
- Verificar que el binario existe: `ls -lh build/guardian_fs`
- Los scripts usan `allow_other` solo si `user_allow_other` está activo en `/etc/fuse.conf`; sin eso montan solo para el usuario actual (suficiente para los tests)

### ml_proxy no conecta
- Verificar que ml_server.py está corriendo primero
- Verificar socket: `ls -lh /tmp/guardian_ml.sock`

### Python dependencies error
- Los scripts crean automáticamente un venv en `.venv/`
- Si falla la creación del venv: `sudo apt install python3-venv`
- Las dependencias se instalan automáticamente: numpy, scikit-learn, xgboost, joblib

## Ejemplo de uso

```bash
# Test completo + 5 rondas de recolección (default)
./scripts/test_ml_pipeline.sh

# Test con datos benignos, sin recolección
./scripts/test_ml_pipeline.sh 0 0

# Solo recolección, 50 rondas por clase (dataset más serio)
./scripts/collect_training_data.sh 50

# Test rápido con datos benignos
./scripts/quick_test_ml.sh 0

# Diagnóstico por componentes
./scripts/diagnose_ml.sh

# Limpieza manual
./scripts/cleanup_test.sh

# Ver resultados
wc -l data/training_data.csv
head -5 data/training_data.csv
cut -d, -f15 data/training_data.csv | sort | uniq -c   # conteo por label
```
