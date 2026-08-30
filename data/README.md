# Feature Logger para Guardian FS

Sistema de recolección de datos para entrenamiento del modelo ML.

## Componentes

1. **`feature_logger.py`** - Módulo Python para loggear features en CSV
2. **`ml_proxy.py`** - Proxy que intercepta features entre analyzer.c y ml_server.py

## Flujo de Datos

```
┌─────────────┐         ┌──────────────┐         ┌─────────────┐
│ analyzer.c  │ ──────> │  ML Proxy    │ ──────> │ ml_server.py│
│ (FUSE)      │ <────── │ (loggea)     │ <────── │ (inference) │
└─────────────┘         └──────────────┘         └─────────────┘
                               │
                               ▼
                        ┌──────────────┐
                        │ training_    │
                        │ data.csv     │
                        └──────────────┘
```

## Uso

### Opción 1: Proxy Interceptor (Recomendado)

Este método intercepta las features en tiempo real mientras corre el simulador.

**Paso 1: Preparar el entorno**

```bash
# Asegúrate de que ml_server.py esté corriendo
python3 src/ml_server.py &

# Cambiar el socket en analyzer.c temporalmente:
# En src/analyzer.c, línea 23:
# #define ML_SOCKET_PATH "/tmp/guardian_ml_proxy.sock"
```

**Paso 2: Iniciar el proxy**

```bash
# Para datos de ransomware (label=1)
python3 scripts/ml_proxy.py --label 1 --output data/ransomware_samples.csv

# Para datos benignos (label=0)
python3 scripts/ml_proxy.py --label 0 --output data/benign_samples.csv
```

**Paso 3: Correr el simulador**

```bash
# Ataque rápido
python3 scripts/simulate_ransomware.py --target-dir /tmp/test_data --file-count 100

# Ataque sigiloso
python3 scripts/simulate_ransomware.py --target-dir /tmp/test_data \
    --mode stealth --file-count 50 --pause-ms 200
```

**Paso 4: Combinar datasets**

```bash
# Unir ransomware + benigno
cat data/ransomware_samples.csv data/benign_samples.csv > data/features_labeled.csv
# (asegúrate de mantener solo un header)
```

### Opción 2: Logger Manual (Para testing)

```python
from data.feature_logger import FeatureLogger

# Crear logger
logger = FeatureLogger(
    output_path="data/test_samples.csv",
    label=1  # 1=ransomware, 0=benigno
)

# Loggear features
features = {
    "entropy_mean": 7.5,
    "entropy_max": 7.9,
    "write_rate": 150.0,
    "rename_rate": 20.0,
    # ... otras features
}

logger.log(features)
```

## Formato del CSV

El CSV generado tiene este formato (compatible con `train_model.py`):

```csv
entropy_mean,entropy_max,entropy_std,entropy_autocorr,write_rate,bytes_written_rate,rename_rate,unlink_rate,read_write_ratio,chi2_stat,ext_change_rate,canary_accessed,unique_dirs,file_type_variety,label,timestamp,pid
7.5,7.9,0.2,0.0,150.0,45000.0,20.0,5.0,0.5,1e9,0.8,0,3,2,1,2026-08-30T21:00:00,12345
```

**Features:**
- `entropy_mean` - Entropía media de escrituras
- `entropy_max` - Máxima entropía en ventana
- `entropy_std` - Desviación estándar de entropía
- `entropy_autocorr` - Autocorrelación temporal
- `write_rate` - Escrituras/segundo
- `bytes_written_rate` - Bytes/segundo
- `rename_rate` - Renombrados/segundo
- `unlink_rate` - Eliminaciones/segundo
- `read_write_ratio` - Ratio lectura/escritura
- `chi2_stat` - Estadístico chi-cuadrado
- `ext_change_rate` - Tasa de cambio de extensión
- `canary_accessed` - ¿Accedió a canary? (0/1)
- `unique_dirs` - Directorios únicos accedidos
- `file_type_variety` - Variedad de tipos de archivo

**Metadata:**
- `label` - 0=benigno, 1=ransomware
- `timestamp` - ISO 8601
- `pid` - Process ID

## Generar Dataset Completo

```bash
# 1. Crear directorio de prueba
mkdir -p /tmp/guardian_test

# 2. Generar datos benignos (uso normal)
python3 scripts/ml_proxy.py --label 0 --output data/benign.csv &
PROXY_PID=$!

# Simular uso normal (copiar archivos, editar, etc.)
cp -r /etc/skel /tmp/guardian_test/
find /tmp/guardian_test -type f -exec grep -l "test" {} \;

kill $PROXY_PID

# 3. Generar datos maliciosos (ransomware)
python3 scripts/ml_proxy.py --label 1 --output data/ransomware.csv &
PROXY_PID=$!

# Correr simulador
python3 scripts/simulate_ransomware.py \
    --target-dir /tmp/guardian_test \
    --file-count 200 \
    --mode full

kill $PROXY_PID

# 4. Combinar datasets
head -1 data/benign.csv > data/features_labeled.csv
tail -n +2 data/benign.csv >> data/features_labeled.csv
tail -n +2 data/ransomware.csv >> data/features_labeled.csv

# 5. Entrenar modelo
python3 src/train_model.py
```

## Notas

- El proxy debe correrse **después** de ml_server.py
- analyzer.c debe apuntar al socket del proxy (`/tmp/guardian_ml_proxy.sock`)
- Los CSV pueden ser grandes; no los subas a git (ya están en .gitignore)
- Para producción, considera rotar logs y comprimir datos antiguos
