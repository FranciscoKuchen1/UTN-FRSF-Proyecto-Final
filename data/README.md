# El dataset de entrenamiento

Acá vive el dataset que alimenta al modelo de machine learning. Se genera con los scripts del proyecto — **no se commitea al repo** (está gitignoreado).

## Qué hay en `data/training_data.csv`

Una fila por **ventana de 5 segundos** de actividad de un programa, con 14 señales de comportamiento, la etiqueta y la metadata:

| Columnas | Contenido |
|---|---|
| Las 14 primeras | Señales del programa en esa ventana (entropía, velocidad, renombrados, carpetas recorridas… el significado de cada una está en [`docs/ml-architecture.md`](../docs/ml-architecture.md) §2) |
| `label` | `0` = actividad benigna, `1` = ataque |
| `session` | Qué ronda de recolección generó la fila (para evaluar sin trampas) |
| `timestamp`, `pid` | Cuándo y qué programa |

## Cómo se genera

No se anota a mano. El circuito automático es:

```
programa escribe → FUSE → analyzer (resumen de la ventana)
    → ml_proxy (ANOTA la fila en el CSV con la etiqueta de la ronda)
    → ml_server (sigue su curso normal)
```

El intermediario (`scripts/ml_proxy.py`) es la "máquina de anotar": cada ventana que viaja hacia el modelo queda registrada con la etiqueta de la ronda que estaba corriendo (ataque o workload benigno).

```bash
# El comando que hace todo (rondas de ataque + benignas, en modo sombra):
./scripts/collect_training_data.sh 25

# Después de recolectar, entrenar:
python3 src/train_model.py
```

Más variedad de workloads benignos = mejor modelo. Las rondas benignas ya incluyen los casos difíciles (compresión de archivos grandes, compilación, git, rsync, bloques idénticos, archivos de ceros) — el porqué de cada uno está en la [guía de ML](../docs/ml-architecture.md) §4.

## Archivos de este directorio

| Archivo | Rol |
|---|---|
| `training_data.csv` | El dataset (se genera, no se commitea) |
| `feature_logger.py` | Módulo de anotación que usa el proxy |
| `README.md` | Esta página |
