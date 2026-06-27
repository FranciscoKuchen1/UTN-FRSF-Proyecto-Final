# Guardian FS — Arquitectura de Machine Learning

> Guía para el Científico de Datos / ML Engineer  
> Proyecto Final UTN FRSF 2026  
> Versión: v0.2.0-dev | Junio 2026

---

## Índice

1. [¿Por qué Machine Learning?](#1-por-qué-machine-learning)
2. [Arquitectura del Pipeline ML](#2-arquitectura-del-pipeline-ml)
3. [Feature Engineering — El Vector de 14 Señales](#3-feature-engineering--el-vector-de-14-señales)
4. [Ensemble de Modelos](#4-ensemble-de-modelos)
   - [4.1 Random Forest (peso 0.35)](#41-random-forest-peso-035)
   - [4.2 XGBoost (peso 0.30)](#42-xgboost-peso-030)
   - [4.3 Isolation Forest (peso 0.20)](#43-isolation-forest-peso-020)
   - [4.4 LSTM (peso 0.15)](#44-lstm-peso-015)
   - [4.5 ¿Por qué ensemble y no un solo modelo?](#45-por-qué-ensemble-y-no-un-solo-modelo)
5. [Pipeline de Entrenamiento](#5-pipeline-de-entrenamiento)
6. [Especificación del Dataset](#6-especificación-del-dataset)
7. [Protocolo de Integración C ↔ Python](#7-protocolo-de-integración-c--python)
8. [Fallback y Degradación Graceful](#8-fallback-y-degradación-graceful)
9. [Estrategia de Evaluación](#9-estrategia-de-evaluación)
10. [Caminos de Optimización](#10-caminos-de-optimización)

---

## 1. ¿Por qué Machine Learning?

El detector estadístico (`detector.c`) usa umbrales fijos calibrados con razonamiento de dominio: "si la entropía pasa de 7.2 Y hay más de 20 escrituras → sospechoso". Esto funciona para ransomware **conocido y agresivo**, pero tiene limitaciones:

| Limitación del detector estadístico | Cómo el ML lo resuelve |
|---|---|
| **Umbrales fijos** — el ransomware puede operar justo debajo (entropía 7.1, 19 escrituras) | El ML aprende combinaciones no lineales de features; no depende de umbrales discretos. |
| **Falsos positivos con backups/compresión** — tar, gzip, rsync generan alta entropía pero son legítimos | El ML ve el **contexto**: ratio R/W, correlación temporal, velocidad de cambio de extensión. |
| **Ransomware nuevo (zero-day)** — patrón de ataque nunca visto en reglas | Isolation Forest detecta anomalías sin necesidad de ejemplos de ataque en entrenamiento. |
| **Evolución temporal** — el ransomware moderno duerme entre archivos para no disparar tasa | LSTM captura patrones secuenciales: "escribió mucho → durmió 2s → escribió más". |
| **Falsos negativos** — ransomware que cifra parcialmente o solo metadatos | El ML combina 14 señales; aunque una falle, las otras 13 compensan. |

**Estrategia:** El detector C es la **primera línea** — rápida, determinista, sin dependencias externas. El ML es la **segunda opinión asíncrona** — más lenta pero más precisa, ejecutándose en un hilo separado sin bloquear al usuario.

---

## 2. Arquitectura del Pipeline ML

```
┌─────────────────────────────────────────────────────────┐
│                    OFFLINE (entrenamiento)                │
│                                                          │
│  Dataset etiquetado (CSV)                                │
│       │                                                  │
│       ▼                                                  │
│  ┌──────────────────────────────────────────────────┐   │
│  │              train_model.py                       │   │
│  │                                                   │   │
│  │  1. SMOTE (balanceo de clases)                    │   │
│  │  2. StandardScaler (normalización)                │   │
│  │  3. StratifiedKFold k=10                          │   │
│  │  4. Entrenar 3 modelos:                           │   │
│  │     ├─ RandomForest (n=200, depth=15)             │   │
│  │     ├─ XGBoost (n=200, depth=8)                   │   │
│  │     └─ IsolationForest (contamination=0.01)       │   │
│  │  5. Serializar: scaler.pkl, rf.pkl, xgb.json     │   │
│  └──────────────────────────────────────────────────┘   │
│                                                          │
│  LSTM (si se usa):                                       │
│  ┌──────────────────────────────────────────────────┐   │
│  │  Secuencias de 10 ventanas por PID                │   │
│  │  → PyTorch LSTM (hidden=64, layers=2)             │   │
│  │  → Serializar: lstm.pt                            │   │
│  └──────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────┐
│                    ONLINE (inferencia)                    │
│                                                          │
│  analyzer.c (C, hilo background)                         │
│       │                                                  │
│       │ Cada ~1s:                                        │
│       │  1. Acumula eventos del ring buffer por PID      │
│       │  2. Calcula feature vector (14 dimensiones)      │
│       │  3. Conecta a /tmp/guardian_ml.sock              │
│       │  4. Envía JSON → recibe JSON                     │
│       ▼                                                  │
│  ┌──────────────────────────────────────────────────┐   │
│  │              ml_server.py (Python 3.11+)           │   │
│  │                                                   │   │
│  │  Cargar modelos: scaler, rf, xgb, iso, lstm       │   │
│  │                                                   │   │
│  │  Por cada request:                                 │   │
│  │    ├─ StandardScaler.transform(features)           │   │
│  │    ├─ RF.predict_proba()        → p_rf            │   │
│  │    ├─ XGB.predict_proba()       → p_xgb           │   │
│  │    ├─ ISO.predict()             → anomaly_score   │   │
│  │    ├─ LSTM.forward(sequence)    → p_lstm          │   │
│  │    │                                              │   │
│  │    └─ Ensemble voting:                             │   │
│  │       p_attack = 0.35·p_rf + 0.30·p_xgb           │   │
│  │                + 0.20·iso_score + 0.15·p_lstm      │   │
│  │                                                   │   │
│  │    Response: {"p_attack": 0.89,                    │   │
│  │               "verdict": "attack",                 │   │
│  │               "scores": {"rf": 0.92, ...}}         │   │
│  └──────────────────────────────────────────────────┘   │
│       │                                                  │
│       ▼                                                  │
│  analyzer.c recibe veredicto:                             │
│    Si p_attack ≥ 0.75 → modificar score en detector.c    │
│    Si p_attack ≥ 0.50 → intensificar monitoreo del PID   │
│    Si p_attack < 0.50 → descartar                        │
└─────────────────────────────────────────────────────────┘
```

---

## 3. Feature Engineering — El Vector de 14 Señales

Cada feature fue elegida para capturar un aspecto específico del comportamiento de ransomware. No son arbitrarias — cada una ataca un vector de evasión conocido.

### Grupo A: Entropía (4 features)

Estas features miden las propiedades estadísticas de los bytes escritos.

| # | Feature | Fórmula | Qué captura |
|---|---|---|---|
| 1 | `entropy_mean` | `Σ H_i / n` | Entropía promedio en la ventana. El cifrado produce H > 7.5 consistente. |
| 2 | `entropy_max` | `max(H_i)` | ¿El proceso **alguna vez** escribió datos de muy alta entropía? Un pico aislado de 7.9 ya es sospechoso. |
| 3 | `entropy_std` | `std(H_i)` | La **variabilidad** de la entropía. Datos normales varían (texto=4.5, imagen=7.2); el cifrado es monótono (std ≈ 0.1). |
| 4 | `entropy_autocorr` | Pearson lag-1 de `H[]` | ¿La entropía de escrituras consecutivas está correlacionada? En archivos comprimidos SÍ (estructura); en cifrado NO (ruido blanco). |

**Por qué 4 features de entropía y no solo 1:** La entropía media sola no distingue un `.zip` (H=7.5, std=0.5, autocorr=0.7) de datos cifrados (H=7.8, std=0.05, autocorr=0.1). Las 4 juntas sí.

### Grupo B: Tasas de operación (4 features)

| # | Feature | Fórmula | Qué captura |
|---|---|---|---|
| 5 | `write_rate` | `write_count / window_secs` | Escrituras por segundo. Ransomware agresivo: > 100 writes/s. Backup legítimo: similar pero con otras features distintas. |
| 6 | `bytes_written_rate` | `bytes_written / window_secs` | Throughput real. Ransomware suele escribir en bloques de 4KB–64KB. |
| 7 | `rename_rate` | `rename_count / window_secs` | Renombrados por segundo. Ransomware renombra CADA archivo después de cifrarlo. |
| 8 | `unlink_rate` | `unlink_count / window_secs` | Eliminaciones por segundo. Algunos ransomware borran el original después de cifrar. |

### Grupo C: Comportamiento (4 features)

| # | Feature | Fórmula | Qué captura |
|---|---|---|---|
| 9 | `read_write_ratio` | `bytes_read / bytes_written` | Ratio lectura/escritura. El ransomware lee un archivo, lo cifra en memoria, y escribe la versión cifrada → ratio ≈ 1.0. Un backup SOLO lee (ratio >> 1). Un generador de datos SOLO escribe (ratio ≈ 0). |
| 10 | `chi2_stat` | `χ²(byte_histogram)` | Test de uniformidad de la distribución de bytes acumulada en la ventana. χ² < 300 con 255 g.l. → distribución uniforme → cifrado real. |
| 11 | `ext_change_rate` | `ext_changes / rename_count` | Proporción de renombrados que cambian la extensión (`.docx` → `.locked`). Comportamiento casi exclusivo de ransomware. |
| 12 | `canary_accessed` | `0 \| 1` | Booleano: ¿el proceso tocó un archivo canary? Feature de altísimo poder discriminante. |

### Grupo D: Diversidad (2 features)

| # | Feature | Fórmula | Qué captura |
|---|---|---|---|
| 13 | `unique_dirs` | `count(distinct dirname(path))` | ¿Cuántos directorios distintos tocó el proceso? El ransomware recorre recursivamente → muchos directorios. Un proceso normal suele operar en 1–3 directorios. |
| 14 | `file_type_variety` | `count(distinct extension(path))` | Variedad de extensiones escritas. El ransomware cifra `.docx`, `.pdf`, `.jpg`, `.xlsx` — mucha variedad. Un editor de texto solo toca `.txt` o `.md`. |

### Normalización

Todas las features numéricas se pasan por `StandardScaler` (z-score) antes de entrar a los modelos. Esto es crítico porque las escalas son muy diferentes: `write_rate` puede ser 0–500, `entropy_mean` es 0–8, `chi2_stat` es 0–100000.

---

## 4. Ensemble de Modelos

### 4.1 Random Forest (peso 0.35)

**¿Por qué Random Forest?**
- **Robusto a overfitting** — promedia cientos de árboles, cada uno entrenado con bootstrap + features aleatorias.
- **Interpretable** — `feature_importances_` nos dice exactamente qué features están contribuyendo más. Esto es oro para ajustar el detector C.
- **Maneja no-linealidades** — la combinación `entropy alta + write_rate bajo + rename_rate alto` no es una relación lineal, y RF la captura naturalmente.
- **Bueno con datos tabulares** — no requiere arquitectura especial como las imágenes o el texto.

**Hiperparámetros propuestos:**
```python
RandomForestClassifier(
    n_estimators=200,       # árboles en el bosque
    max_depth=15,           # profundidad máxima (evita overfitting)
    min_samples_split=5,    # mínimo para dividir un nodo
    class_weight='balanced',# compensa desbalance benigno >> ataque
    random_state=42
)
```

**Peso en el ensemble: 0.35** — el más alto porque RF es el modelo más robusto y confiable para este tipo de problema.

### 4.2 XGBoost (peso 0.30)

**¿Por qué XGBoost?**
- **Gradient boosting** — construye árboles secuencialmente, cada uno corrigiendo los errores del anterior.
- **Excelente con desbalance de clases** — `scale_pos_weight` ajusta la función de pérdida para penalizar más los falsos negativos. En nuestro caso, un falso negativo (ataque no detectado) es mucho peor que un falso positivo.
- **Regularización incorporada** — L1 y L2 reducen overfitting mejor que RF solo.
- **Complementa a RF** — RF y XGBoost tienden a cometer errores en ejemplos diferentes; combinados se corrigen mutuamente.

**Hiperparámetros propuestos:**
```python
XGBClassifier(
    n_estimators=200,
    max_depth=8,                # más bajo que RF (boosting necesita árboles débiles)
    learning_rate=0.05,         # paso pequeño, muchos árboles
    scale_pos_weight=10,        # penalizar 10x más los falsos negativos
    subsample=0.8,              # 80% de datos por árbol
    colsample_bytree=0.8,       # 80% de features por árbol
    random_state=42
)
```

### 4.3 Isolation Forest (peso 0.20)

**¿Por qué Isolation Forest?**
- **NO supervisado** — se entrena SOLO con datos benignos. No necesita ejemplos de ataque.
- **Detecta zero-days** — cualquier comportamiento suficientemente distinto a "normal" es una anomalía, aunque el modelo nunca haya visto ese patrón de ataque específico.
- **Fundamento teórico sólido** — las anomalías son "pocas y diferentes"; se aíslan con pocas particiones aleatorias.

**¿Cómo funciona?** Isolation Forest construye árboles de decisión aleatorios. Un punto normal requiere muchas particiones para ser aislado (está rodeado de otros puntos). Una anomalía requiere pocas particiones (está aislada). El promedio de profundidad de aislamiento es el anomaly score.

**Hiperparámetros propuestos:**
```python
IsolationForest(
    n_estimators=100,
    contamination=0.01,     # asumimos ~1% de anomalías en producción
    max_samples=256,        # submuestreo (más rápido, igual de efectivo)
    random_state=42
)
```

**Peso en el ensemble: 0.20** — menor que RF y XGB porque es no supervisado y por lo tanto menos preciso en la frontera de decisión fina. Pero es invaluable para detectar ataques nunca vistos.

### 4.4 LSTM (peso 0.15)

**¿Por qué LSTM?**
- **Captura patrones temporales** — el comportamiento de ransomware evoluciona en el tiempo: fase de enumeración → fase de cifrado → fase de renombrado.
- **Memoria de largo plazo** — un LSTM puede recordar que "hace 8 ventanas este PID hizo enumeración agresiva, luego durmió 2s, y ahora está escribiendo con alta entropía".
- **El ransomware moderno usa tácticas temporales** — sleeps entre archivos, cifrado en ráfagas, pausas para evadir detección por tasa.

**Arquitectura propuesta:**
```python
class RansomwareLSTM(nn.Module):
    def __init__(self, input_dim=14, hidden_dim=64, num_layers=2):
        self.lstm = nn.LSTM(input_dim, hidden_dim, num_layers, batch_first=True)
        self.fc = nn.Linear(hidden_dim, 1)
        self.sigmoid = nn.Sigmoid()

    def forward(self, x):  # x: (batch, seq_len=10, features=14)
        out, (hn, cn) = self.lstm(x)
        return self.sigmoid(self.fc(out[:, -1, :]))
```

**Input:** Secuencia de 10 ventanas consecutivas para el mismo PID. Cada ventana es un vector de 14 features.  
**Output:** Probabilidad de ataque.

**Peso en el ensemble: 0.15** — el más bajo porque:
- Requiere más datos de entrenamiento (secuencias, no puntos individuales).
- Es más costoso computacionalmente.
- Solo se activa cuando hay suficientes ventanas acumuladas para un PID (≥ 10).
- Si no hay suficientes datos, el ensemble opera con los otros 3 modelos (pesos renormalizados).

### 4.5 ¿Por qué ensemble y no un solo modelo?

| Riesgo de un solo modelo | Cómo el ensemble lo mitiga |
|---|---|
| **Overfitting** del modelo único a los datos de entrenamiento | 4 modelos con arquitecturas fundamentalmente diferentes no overfittean de la misma manera. |
| **Punto ciego** — el modelo único no captura cierto patrón | Si RF no lo ve, XGBoost probablemente sí. Si ambos no lo ven, Isolation Forest puede detectarlo como anomalía. |
| **Ataque adversarial** — el ransomware evoluciona para evadir un clasificador específico | "Evadir" 4 modelos simultáneamente es exponencialmente más difícil. |
| **Error de calibración** — un modelo da probabilidades mal calibradas | El voting ponderado suaviza errores individuales de calibración. |

**Voting ponderado:**

```
p_attack = 0.35 · p_rf + 0.30 · p_xgb + 0.20 · iso_score + 0.15 · p_lstm
```

Los pesos reflejan:
- **Confiabilidad esperada** (RF es el más robusto en datos tabulares).
- **Naturaleza del modelo** (supervisado vs. no supervisado, punto vs. secuencia).
- **Costo computacional** (LSTM es caro, se usa como "voto de calidad" más que como motor principal).

---

## 5. Pipeline de Entrenamiento

### 5.1 Flujo completo

```
features_labeled.csv
      │
      ├─ 1. Carga y validación
      │     └─ Verificar: 14 columnas de features + columna 'label' (0=benigno, 1=ataque)
      │     └─ Verificar: no hay nulos, no hay infinitos
      │
      ├─ 2. Split estratificado
      │     └─ train_test_split(test_size=0.2, stratify=y)
      │     └─ El split es estratificado porque el dataset está muy desbalanceado
      │
      ├─ 3. Balanceo de clases (SMOTE)
      │     └─ SMOTE(random_state=42) sobre el conjunto de entrenamiento
      │     └─ Genera ejemplos sintéticos de la clase minoritaria (ataque)
      │     └─ NO aplicar SMOTE al conjunto de test (data leakage)
      │
      ├─ 4. Normalización (StandardScaler)
      │     └─ fit() solo en train, transform() en train y test
      │     └─ Guardar scaler.pkl para usar en inferencia
      │
      ├─ 5. Validación cruzada estratificada
      │     └─ StratifiedKFold(n_splits=10, shuffle=True)
      │     └─ Para RF y XGBoost: GridSearchCV sobre hiperparámetros
      │
      ├─ 6. Entrenamiento final
      │     ├─ RandomForestClassifier → rf.pkl
      │     ├─ XGBClassifier → xgb.json
      │     ├─ IsolationForest (solo datos benignos) → iso.pkl
      │     └─ LSTM (secuencias de 10 ventanas) → lstm.pt
      │
      └─ 7. Evaluación
            ├─ ROC-AUC (área bajo la curva)
            ├─ Classification report (precision, recall, f1)
            ├─ Matriz de confusión
            ├─ FPR @ FNR=0.01 (false positive rate con 1% de falsos negativos)
            └─ Feature importance (RF) → exportar para calibración del detector C
```

### 5.2 Manejo del desbalance de clases

El dataset va a estar **fuertemente desbalanceado**: quizás 10,000 muestras benignas por cada 100 de ataque. Si entrenamos sin balancear, el modelo aprende a decir siempre "benigno" y tiene 99% de accuracy — inútil.

**Estrategia de 3 capas:**

1. **SMOTE** (Synthetic Minority Oversampling Technique): genera ejemplos sintéticos de ataque interpolando entre ejemplos reales cercanos en el espacio de features. No duplica, crea variaciones plausibles.

2. **class_weight='balanced'** en Random Forest: penaliza más los errores en la clase minoritaria.

3. **scale_pos_weight=10** en XGBoost: 10x más penalización por falso negativo que por falso positivo. Un ataque no detectado cuesta más que una falsa alarma.

---

## 6. Especificación del Dataset

### 6.1 Formato

Archivo CSV con las siguientes columnas:

```csv
entropy_mean,entropy_max,entropy_std,entropy_autocorr,write_rate,bytes_written_rate,rename_rate,unlink_rate,read_write_ratio,chi2_stat,ext_change_rate,canary_accessed,unique_dirs,file_type_variety,label
5.23,7.12,0.89,0.67,12.5,512000,0.0,0.0,4.2,15420.0,0.0,0,2,1,0
7.89,7.98,0.03,0.09,145.2,8192000,32.1,0.0,1.05,45.3,0.94,1,47,12,1
```

- **Separador:** coma (`,`)
- **Encoding:** UTF-8
- **Sin header opcional** (el pipeline lo maneja)
- **Label:** `0` = benigno, `1` = ataque

### 6.2 Composición mínima

| Clase | Muestras mínimas | Ideal | Origen |
|---|---|---|---|
| **Benigno (0)** | 5,000 | 50,000+ | Capturar en entorno real: editores de texto, navegadores, compiladores, backups, rsync, tar, gzip, git, builds, IDEs. |
| **Ataque (1)** | 500 | 5,000+ | Ejecutar muestras de ransomware conocido en entorno controlado (VM aislada). Alternativa: simular comportamiento de ransomware con scripts. |

**IMPORTANTE:** No usar datos sintéticos para la clase de ataque si es posible. SMOTE ya genera síntesis durante el entrenamiento. El dataset de ataque debe ser real (ransomware ejecutado en sandbox) o al menos simulación fiel (script que replica el comportamiento de E/S del ransomware).

### 6.3 Recolección de datos benignos

Ejecutar Guardian FS en modo "solo logueo" (sin bloquear) en un entorno de desarrollo real durante al menos 24 horas, capturando eventos de:

- Edición de documentos (LibreOffice, Google Docs, editores de código)
- Navegación web (caché del navegador)
- Compilación (gcc, cargo, go build)
- Backups (rsync, tar, Timeshift)
- Comunicación (Slack, Discord, Zoom — escrituras de caché)
- Sistema operativo (logs, systemd journal, actualizaciones)

### 6.4 Recolección de datos de ataque

Ejecutar en VM aislada (SIN conexión de red, SIN acceso al host) muestras de ransomware conocido:

- **LockBit 3.0** — ransomware moderno agresivo, alta velocidad.
- **Conti** — ransomware con tácticas de evasión (sleeps, baja tasa).
- **REvil** — cifrado parcial + renombrado agresivo.
- **Simulador propio** — script Python/C que reproduce el comportamiento de E/S del ransomware (alta entropía, cambio de extensión, recorrido de directorios).

### 6.5 Consideraciones de sesgo

| Riesgo de sesgo | Mitigación |
|---|---|
| **Sesgo de entorno** — todos los datos benignos vienen de la misma máquina/usuario | Recolectar en múltiples máquinas, múltiples usuarios, múltiples workloads. |
| **Sesgo temporal** — los datos de ataque se recolectan en una sola sesión | Ejecutar ransomware en diferentes momentos, con diferentes cargas de sistema. |
| **Sesgo de herramienta** — el simulador no es ransomware real | Priorizar muestras reales. Usar el simulador solo para aumentar variedad. |
| **Data leakage** — features calculadas con conocimiento del futuro | Las features se calculan por ventana independiente. No usar información de ventanas futuras para clasificar la ventana actual (excepto LSTM, que por diseño usa secuencias). |

---

## 7. Protocolo de Integración C ↔ Python

### 7.1 Socket Unix

```
analyzer.c                          ml_server.py
    │                                     │
    │  socket(AF_UNIX, SOCK_STREAM)       │  socket(AF_UNIX, SOCK_STREAM)
    │  connect("/tmp/guardian_ml.sock")   │  bind("/tmp/guardian_ml.sock")
    │                                     │  listen(10)
    │                                     │
    │  ──── JSON request ────→            │
    │  {"pid": 1234,                      │
    │   "features": [5.2, 7.1, ...]}      │
    │                                     │  scaler.transform()
    │                                     │  ensemble.predict()
    │                                     │
    │  ←──── JSON response ────           │
    │  {"p_attack": 0.89,                 │
    │   "verdict": "attack",              │
    │   "scores": {                       │
    │     "rf": 0.92,                     │
    │     "xgb": 0.88,                    │
    │     "iso": 0.85,                    │
    │     "lstm": 0.78                    │
    │   },                                │
    │   "top_features": [                 │
    │     {"name": "entropy_mean",        │
    │      "importance": 0.28},           │
    │     ...]}                           │
    │                                     │
```

### 7.2 Formato de mensajes

**Request (C → Python):**
```json
{
  "pid": 1234,
  "features": [
    7.89, 7.98, 0.03, 0.09, 145.2, 8192000,
    32.1, 0.0, 1.05, 45.3, 0.94, 1, 47, 12
  ],
  "sequence": [                          // opcional, solo si hay ≥ 10 ventanas
    [5.23, 7.12, ...],                   // ventana t-9
    [5.45, 7.01, ...],                   // ventana t-8
    ...                                  // 10 ventanas hacia atrás
  ]
}
```

**Response (Python → C):**
```json
{
  "p_attack": 0.89,
  "verdict": "attack",
  "scores": {
    "rf": 0.92,
    "xgb": 0.88,
    "iso": 0.85,
    "lstm": 0.78
  },
  "top_features": [
    {"name": "entropy_mean", "importance": 0.28},
    {"name": "ext_change_rate", "importance": 0.22},
    {"name": "chi2_stat", "importance": 0.18}
  ],
  "fallback": false
}
```

### 7.3 Umbrales de acción en analyzer.c

```
p_attack ≥ 0.75 → "attack"
  → Forzar score del detector a 1.0 → VERDICT_BLOCK en la próxima syscall.
  → Disparar zfs_snapshot_emergency si el detector C aún no lo hizo.

p_attack ≥ 0.50 → "suspicious"
  → Aumentar peso de las features de este PID en el detector C.
  → Loguear para análisis forense.

p_attack < 0.50 → "normal"
  → Descartar. El proceso es probablemente legítimo.
```

---

## 8. Fallback y Degradación Graceful

El sistema debe funcionar incluso si el servidor ML no está disponible. La seguridad no puede depender de un proceso Python.

### Niveles de degradación:

| Nivel | Qué falló | Qué pasa |
|---|---|---|
| **Nivel 0: Full** | Todo funciona | Detector C + ML ensemble. Máxima precisión. |
| **Nivel 1: Sin LSTM** | LSTM no disponible (no hay secuencia, PyTorch no instalado) | Ensemble con 3 modelos (RF+XGB+ISO). Pesos renormalizados: 0.44 + 0.37 + 0.19. |
| **Nivel 2: Sin ML server** | ml_server.py caído o no arrancó | Solo detector C (reglas estadísticas). La detección es más ruidosa pero funcional. |
| **Nivel 3: Sin modelos entrenados** | Primera ejecución, no hay `.pkl` | ml_server.py usa `_rule_based()` que replica las reglas del detector C. |
| **Nivel 4: Sin Python** | Python ni siquiera instalado | El sistema corre 100% en C. El analyzer thread loguea eventos y el detector C toma todas las decisiones. |

**El detector C NUNCA se desactiva.** Es la última línea de defensa y siempre está activo.

---

## 9. Estrategia de Evaluación

### 9.1 Métricas primarias

| Métrica | Objetivo | Por qué |
|---|---|---|
| **Recall (detección)** | > 0.99 | Un ataque no detectado es pérdida de datos. Queremos detectar > 99% de los ataques. |
| **FPR (false positive rate)** | < 0.01 | Menos de 1 falsa alarma cada 100 procesos legítimos. |
| **ROC-AUC** | > 0.95 | Área bajo la curva ROC — medida global de calidad del clasificador. |
| **F1-score (ataque)** | > 0.90 | Balance entre precisión y recall en la clase minoritaria. |

### 9.2 Métricas secundarias

| Métrica | Objetivo | Por qué |
|---|---|---|
| **Tiempo hasta detección** | < 3 segundos desde el inicio del ataque | Si tarda más, el ransomware ya cifró cientos de archivos. |
| **Latencia de inferencia** | < 5ms por request | El analyzer no debe convertirse en cuello de botella. |
| **Archivos cifrados antes del bloqueo** | < 10 archivos | Con snapshots ZFS cada 60s, máximo 10 archivos afectados. |
| **Precisión del ensemble vs. detector C solo** | Mejora > 20% en F1 | Justifica la complejidad adicional del ML. |

### 9.3 Validación temporal (backtesting)

El ransomware evoluciona. Un modelo entrenado con datos de 2024 puede fallar contra ransomware de 2026.

**Estrategia:** Validación con split temporal — entrenar con datos hasta fecha T, evaluar con datos posteriores a T. Si el modelo se degrada significativamente, es señal de que necesita reentrenamiento.

---

## 10. Caminos de Optimización

### 10.1 Calibración de pesos del ensemble

Los pesos actuales (0.35, 0.30, 0.20, 0.15) son una estimación inicial. Se pueden optimizar con:

```python
from scipy.optimize import minimize

def ensemble_score(weights, y_true, y_preds):
    """Busca pesos que maximicen ROC-AUC en validación."""
    weighted = sum(w * p for w, p in zip(weights, y_preds))
    return -roc_auc_score(y_true, weighted)  # negativo para minimizar

result = minimize(
    ensemble_score,
    x0=[0.35, 0.30, 0.20, 0.15],
    bounds=[(0.1, 0.5)] * 4,
    constraints={'type': 'eq', 'fun': lambda w: sum(w) - 1.0}
)
```

### 10.2 Feature selection

No todas las features son igualmente útiles. `feature_importances_` de Random Forest nos dice cuáles pesan más. Se puede experimentar con:
- Eliminar features con importancia < 0.03.
- Agregar features derivadas: `entropy_mean × write_rate`, `chi2_stat / bytes_written`.
- Agregar features de segundo orden: `differences` entre ventanas consecutivas.

### 10.3 Ajuste de umbrales

El umbral `p_attack ≥ 0.75 → "attack"` es configurable. Se puede calibrar con curva de precisión-recall:
- **Priorizar recall** (umbral más bajo, ej. 0.60) → detecta más ataques, más falsos positivos.
- **Priorizar precisión** (umbral más alto, ej. 0.85) → menos falsas alarmas, puede perder ataques sutiles.

Para un sistema de seguridad, **recall > precisión**. Es preferible una falsa alarma que un ataque no detectado.

### 10.4 Reentrenamiento continuo

Los modelos no son estáticos. Se debe planificar:
- **Reentrenamiento mensual** con datos nuevos de ataques.
- **Monitoreo de drift**: si la distribución de features benignas cambia (nueva versión de SO, nuevo software), los modelos necesitan actualizarse.
- **A/B testing**: nuevo modelo corre en shadow mode (loguea veredictos sin aplicarlos) antes de activarlo.

### 10.5 Del ensemble al stacking

El voting ponderado es simple pero limitado. Un meta-modelo (stacking) puede aprender a combinar las predicciones mejor:

```python
from sklearn.ensemble import StackingClassifier

meta_learner = LogisticRegression()
stacking = StackingClassifier(
    estimators=[('rf', rf), ('xgb', xgb), ('iso', iso)],
    final_estimator=meta_learner,
    cv=5  # usa out-of-fold predictions para entrenar el meta-modelo
)
```

El stacking aprende automáticamente cuánto confiar en cada modelo según el contexto.

---

## Apéndice: Dependencias Python

Ver `python/requirements.txt`:

```
numpy>=1.24           # cómputo numérico
scikit-learn>=1.3     # RF, IsolationForest, StandardScaler, SMOTE
xgboost>=2.0          # gradient boosting
joblib>=1.3           # serialización de modelos
pandas>=2.0           # carga y manipulación de datos
imbalanced-learn>=0.11 # SMOTE
matplotlib>=3.7       # visualización (evaluación)
# torch>=2.0          # opcional: LSTM
```

---

*Documento generado para guiar al ML Engineer / Data Scientist del equipo. Las decisiones de modelo, features y pesos están fundamentadas en el dominio del problema (detección de ransomware por comportamiento de E/S). Para preguntas técnicas, consultar `docs/architecture/README.md` y `docs/developer-guide.md`.*
