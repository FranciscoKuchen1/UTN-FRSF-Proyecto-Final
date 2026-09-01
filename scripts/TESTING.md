# Guardian FS — ML Pipeline Testing Scripts

Scripts para probar el pipeline completo de feature logging para entrenamiento ML.

## Scripts disponibles

### 1. `test_ml_pipeline.sh` — Test completo desde cero
Compila el proyecto, prepara directorios, ejecuta todos los componentes y verifica resultados.

```bash
./scripts/test_ml_pipeline.sh [label]
```

**Parámetros:**
- `label`: 1=ransomware (default), 0=benigno

**Qué hace:**
1. Verifica requisitos del sistema
2. Compila el proyecto
3. Prepara directorios de prueba
4. Inicia ml_server.py
5. Inicia ml_proxy.py
6. Monta FUSE
7. Ejecuta simulador
8. Verifica resultados
9. Limpia todo al terminar

### 2. `quick_test_ml.sh` — Test rápido (proyecto ya compilado)
Salta la compilación. Útil cuando ya hiciste build y solo querés probar el pipeline.

```bash
./scripts/quick_test_ml.sh [label]
```

### 3. `cleanup_test.sh` — Limpieza manual
Limpia procesos, mountpoints, sockets y archivos de prueba.

```bash
./scripts/cleanup_test.sh
```

## Flujo de datos

```
simulador.py
    ↓ escribe en /tmp/guardian_test_mount
FUSE (guardian_fs)
    ↓ intercepta syscalls → ring buffer
analyzer.c
    ↓ cada 5s si hay ≥10 writes → envía JSON
ml_proxy.py
    ↓ loggea features → CSV, forward a backend
ml_server.py
    ↓ predice veredicto
analyzer.c recibe veredicto
```

## Archivos generados

- `data/training_data.csv` — Features loggeadas (14 features + label + timestamp + pid)
- `/tmp/guardian_test_logs/` — Logs de cada componente
  - `ml_server.log`
  - `ml_proxy.log`
  - `fuse.log`

## Troubleshooting

### 0 features loggeadas
- Verificar que el simulador escribió en el mountpoint de FUSE
- Revisar logs: `tail -20 /tmp/guardian_test_logs/fuse.log`
- Verificar que analyzer.c dice `Connected to ML server`

### FUSE no monta
- Verificar que libfuse3 está instalado: `sudo apt install libfuse3-dev`
- Verificar que el binario existe: `ls -lh build/guardian_fs`

### ml_proxy no conecta
- Verificar que ml_server.py está corriendo primero
- Verificar socket: `ls -lh /tmp/guardian_ml.sock`

## Ejemplo de uso

```bash
# Test completo con datos de ransomware
./scripts/test_ml_pipeline.sh 1

# Test rápido con datos benignos
./scripts/quick_test_ml.sh 0

# Limpieza manual
./scripts/cleanup_test.sh

# Ver resultados
wc -l data/training_data.csv
head -5 data/training_data.csv
```
