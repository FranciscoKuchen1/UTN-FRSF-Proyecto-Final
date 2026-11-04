# Scripts del circuito ML

> Referencia rápida de los scripts que viven en esta carpeta para probar y alimentar la parte de machine learning. La guía general de testing está en [`docs/testing-guide.md`](../docs/testing-guide.md).

## Los cuatro scripts

### `test_ml_pipeline.sh` — prueba de humo completa

```bash
./scripts/test_ml_pipeline.sh [label] [rondas]
# label: 1 = ataque simulado (default), 0 = workload benigno
# rondas: recolección posterior (default 5, con 0 se saltea)
```

Hace todo desde cero: verifica requisitos, crea el entorno Python si falta, compila, levanta el stack (server + proxy + FUSE en `/tmp`), corre el simulador o el workload benigno, comprueba que hayan llegado filas al CSV, limpia todo y (si se pidió) dispara la recolección de datos.

Si el simulador muere a mitad (status 137), el test lo trata como **éxito**: significa que la mitigación funcionó.

### `collect_training_data.sh` — el generador del dataset

```bash
./scripts/collect_training_data.sh [rondas]     # default: 10
```

Levanta su propio stack en `/tmp` y alterna dos fases, tantas rondas como se pidan:

- **Fase ataque (etiqueta 1):** el simulador con perfiles variados — modo, velocidad, cantidad de archivos, 1 a 4 procesos paralelos, cifrado parcial del 50–100%. Corre en **modo sombra** (anota pero no mata) para que cada ataque aporte todas sus ventanas, no solo la primera.
- **Fase benigna (etiqueta 0):** trabajo real de computadora — copias, compilación, git, rsync, logs, backups comprimidos, bloques idénticos, archivos de ceros. Cada ronda queda anotada con su sesión.

Cada corrida **suma** filas al CSV (no lo pisa). Más variedad → mejor modelo.

### `quick_test_ml.sh` — ídem al primero, sin compilar

Para iterar rápido cuando ya está todo compilado.

### `diagnose_ml.sh` — chequeo por partes

Prueba el circuito ML sin FUSE, pieza por pieza: dependencias → server → proxy → una ventana sintética → CSV. **Usalo primero cuando algo del circuito no funciona**: te dice exactamente qué eslabón se rompió.

## Cuando algo falla

1. Corré `diagnose_ml.sh`.
2. Mirá los logs que dejan los scripts en `logs/` (`ml_server.log`, `ml_proxy.log`, `fuse.log`).
3. Los problemas más comunes ya están en la tabla de [`docs/testing-guide.md`](../docs/testing-guide.md) §5.
