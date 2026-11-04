# El machine learning de Guardian FS, explicado sin jerga

> Esta guía explica **qué hace el ML acá, por qué existe, y cómo se lo usa**. Si buscás los números y hallazgos de la última sesión de entrenamiento, andá a [`docs/cambios-2026-11-04.md`](cambios-2026-11-04.md). Si buscás el flujo con diagramas, a [`docs/pipeline.md`](pipeline.md).

---

## 1. ¿Para qué hace falta ML si ya hay un detector?

El detector rápido (el código C que corre en cada escritura) usa **reglas fijas**: "si la entropía supera 7.2 y hay más de 20 escrituras, sospechar". Funciona muy bien contra ransomware agresivo. Pero las reglas fijas tienen dos problemas:

1. **Se les puede pasar por debajo.** Un ransomware paciente puede escribir con entropía 7.1, o dormirse entre archivos, y quedar siempre un escalón por debajo de cada umbral.
2. **Molestan a gente de buena fe.** Comprimir archivos, compilar código o guardar fotos también produce datos "muy revueltos". Una regla simple no distingue un backup de un ataque; un modelo que vio miles de ejemplos de ambos, sí.

Entonces la división del trabajo es:

| | Detector rápido (C) | Modelo ML (Python) |
|---|---|---|
| Cuándo opina | En cada escritura, al instante | Cada 5 segundos, mirando el resumen de la ventana |
| Velocidad | < 1 milisegundo | ~1–5 milisegundos, pero en segundo plano |
| Estilo | Reglas fijas calibradas a mano | Patrones aprendidos de miles de ejemplos |
| Si falla… | Nada crítico depende de Python: el ML puede confirmar ataques que las reglas no vieron, pero las reglas solas ya frenan los ataques típicos | El sistema degrada a detección estadística pura y sigue funcionando |

**El ML nunca es un cuello de botella ni un punto único de falla.** Es una segunda opinión que llega con algunos segundos de demora y sirve para atrapar lo raro.

---

## 2. Qué mira el modelo: las 14 señales

Cada 5 segundos, el sistema resume lo que hizo cada programa en esa ventana y le entrega al modelo un perfil con 14 números. Nada de nombres de archivos ni contenido: solo comportamiento.

### Las señales sobre los datos escritos (¿parecen cifrados?)

| Señal | En criollo |
|---|---|
| Entropía promedio / máxima / variación | Qué tan "revueltos" son los bytes, en promedio, en el peor momento, y qué tan pareja es esa cualidad entre escrituras. El cifrado produce datos revueltos *consistentemente*; los archivos normales van variando. |
| Correlación de entropía | Si una escritura se parece a la anterior. Un comprimido tiene estructura que se repite; el cifrado es ruido puro, sin parecido entre bloques. |
| χ² (uniformidad) | Un test de "reparto": en los datos cifrados, cada byte posible aparece más o menos la misma cantidad de veces. En un texto o una imagen, hay bytes que dominan. |

### Las señales de ritmo (¿qué tan frenético es el programa?)

| Señal | En criollo |
|---|---|
| Escrituras por segundo | El ransomware cifra a máxima velocidad. |
| Bytes por segundo | Ídem, medido en volumen. |
| Renombrados por segundo | Después de cifrar cada archivo, lo renombra (`.docx` → `.locked`). |
| Borrados por segundo | Algunos borran los backups o los originales. |

### Las señales de "estilo de trabajo"

| Señal | En criollo |
|---|---|
| Ratio lectura/escritura | El ransomware lee un archivo y escribe su versión cifrada: ratio cercano a 1. Un backup lee todo y escribe poco. Un programa generador solo escribe. |
| Proporción de renombrados que cambian la extensión | Casi exclusivo de ransomware. |
| ¿Tocó un archivo señuelo? | La trampa: señuelos con nombres tentadores que ningún programa honesto modifica. |
| Cuántas carpetas distintas recorrió | El ransomware barren toda la estructura; un editor trabaja en una o dos carpetas. |
| Cuántos tipos de archivo distintos tocó | El ransomware cifra de todo (`.docx`, `.pdf`, `.jpg`…); un programa normal toca uno o dos tipos. |

**El punto fino:** ninguna señal alcanza sola. La entropía alta la tiene un `.zip`; el ritmo frenético lo tiene un backup; los renombrados los tiene un `rsync`. El valor está en la **combinación** — y eso es justo lo que un modelo aprende mejor que unas reglas escritas a mano.

---

## 3. Los tres modelos que votan

El servidor (`src/ml_server.py`) no usa un solo modelo: combina tres, cada uno con su fortaleza, y promedia sus opiniones con pesos.

| Modelo | Peso | Su fuerte | Su debilidad |
|---|---|---|---|
| **Random Forest** (bosque de árboles de decisión) | 0.35 | Robusto, difícil de engañar con un solo rasgo; además dice qué señales pesaron en cada decisión | Le cuesta el ruido temporal |
| **XGBoost** (árboles que se corrigen entre sí) | 0.30 | Distinto del anterior: fallan en cosas distintas, se cubren mutuamente | Puede sobreajustarse |
| **Isolation Forest** (detector de rarezas) | 0.20 | **No necesita ejemplos de ataques**: aprende qué es "normal" y marca lo que se desvía — sirve para ransomware nunca visto | Menos preciso en la frontera difusa |

> Hay un cuarto modelo previsto (una red recurrente/LSTM, peso 0.15) para patrones *temporales* — "escribió mucho, durmió 2 segundos, escribió más". Está implementado pero desactivado: requiere PyTorch y suficientes datos de secuencias. Los pesos de los otros tres se renormalizan solos.

El resultado combinado es una probabilidad de ataque entre 0 y 1:

| Probabilidad | Veredicto | Qué hace el sistema |
|---|---|---|
| ≥ 0.75 | `attack` | El detector queda avisado: la próxima operación de ese programa se bloquea (y si el detector rápido no lo había matado todavía, se dispara todo el protocolo: snapshot + kill) |
| 0.50 – 0.75 | `suspicious` | Se anota para análisis forense; el programa queda bajo observación reforzada |
| < 0.50 | `normal` | Nada |

---

## 4. De dónde salen los datos para entrenar

No existe un dataset público para este diseño: las filas no son archivos sueltos, son **ventanas de comportamiento** (qué hizo tal programa durante 5 segundos). Hay que generarlas. El circuito completo lo automatiza `scripts/collect_training_data.sh`:

1. Levanta una copia del sistema en modo **sombra** (anota veredictos pero no bloquea ni mata — si matara al simulador en la primera ventana, tendríamos una sola fila por ataque en vez de toda su evolución).
2. Corre **rondas de ataque** con el simulador propio, variando modo, velocidad, cantidad de procesos y % de cifrado parcial (perfiles calibrados sobre familias reales: LockBit, Conti, REvil).
3. Corre **rondas benignas** con trabajo de verdad: compilar, git, rsync, logs, backups comprimidos, y los casos difíciles (ver abajo).
4. Un intermediario (el "proxy") anota cada ventana en `data/training_data.csv` con su etiqueta (0 = benigno, 1 = ataque) y su **sesión** de origen.

Cada ronda queda marcada con su sesión para poder evaluar sin trampas: al medir la calidad del modelo, **las ventanas de una misma corrida van enteras a "entrenar" o a "evaluar"**, nunca repartidas. Si se repartieran, el modelo "se copiaría la respuesta" (ventanas casi idénticas a un lado y otro) y las métricas quedarían infladas.

### Los casos difíciles que aprendimos por las malas

La primera versión del dataset tenía un hueco que produjo falsos positivos reales, y vale documentarlo porque es la lección más útil de todo el ML del proyecto:

- **Programas que escriben bloques idénticos** (heartbeats, páginas de base de datos): entropía bajísima pero *perfectamente constante en el tiempo*. En el dataset original, esa "constancia" solo aparecía en los ataques… así que el modelo la aprendió como firma de ataque y marcaba a estos programas inocentes como atacantes.
- **Backups comprimidos**: gzip de archivos grandes escribe megas de datos revueltos (¡entropía 8!) a buena velocidad. Sin ejemplos de esta clase, el modelo no tenía con qué distinguirlo de un cifrador.

Moraleja: **un modelo de comportamiento es tan bueno como la variedad de comportamientos benignos que vio**. Las rondas benignas ahora incluyen explícitamente: compilación, git, rsync, logs en paralelo, bloques idénticos, archivos de puros ceros y compresión de datos incomprimibles (que simula archivar fotos/videos/zip).

---

## 5. Entrenar (el circuito, en 3 comandos)

```bash
# 1. Recolectar (cada corrida suma filas al CSV; más variedad = mejor)
./scripts/collect_training_data.sh 25

# 2. Entrenar y evaluar (imprime las métricas y guarda los modelos)
python3 src/train_model.py

# 3. Los modelos quedan en /var/lib/guardian/models/ y el servidor los
#    carga solo al arrancar — reiniciarlo si estaba corriendo
```

`train_model.py` entrena y evalúa con la misma pieza que después sirve las predicciones (misma clase de Python en `ml_server.py`): lo que se mide es exactamente lo que se despliega. La evaluación imprime, para Random Forest y XGBoost:

- **ROC-AUC** (qué tan bien separa las clases en general; 1.0 es perfecto, 0.5 es adivinar);
- **precisión / recall** de cada clase;
- **FPR / FNR** (porcentaje de inocentes acusados / atacantes dejados pasar);
- y un gráfico de qué señales pesaron más, en `reports/feature_importance.png`.

---

## 6. Cómo saber si el modelo es bueno (sin autoengañarse)

Tres chequeos que valen más que cualquier número aislado:

1. **Las métricas de evaluación** (con separación por sesiones, como se explicó).
2. **Probar con filas reales del dataset** que el modelo nunca vio agrupadas — el procedimiento está en la bitácora.
3. **Probar casos sintéticos límite**, uno por clase difícil:
   - escritor de bloques idénticos → debe dar "normal";
   - gzip de archivo grande → "normal";
   - cifrado + renombrados + varias carpetas → "attack".

En la última sesión los tres pasaron, y las 50 ventanas de compresión real del dataset quedaron del lado correcto.

**Letra chica honesta:** el dataset se genera con un simulador, no con malware real ni con usuarios reales. Separar "ataque simulado" de "trabajo simulado" es más fácil que el problema real, así que estas métricas validan el *circuito* (los datos fluyen, el modelo aprende las clases difíciles, los veredictos vuelven al sistema), no que el sistema esté listo para producción. El camino hacia métricas "de verdad" pasa por más variedad benigna (más máquinas, más workloads reales) y, eventualmente, muestras controladas en sandbox.

---

## 7. Referencia rápida de archivos

| Archivo | Rol |
|---|---|
| `src/analyzer.c` | Calcula las 14 señales por ventana y las manda por socket |
| `src/ml_server.py` | Escucha el socket, corre los tres modelos, combina votos |
| `src/train_model.py` | Evalúa y entrena con el dataset; guarda los modelos |
| `scripts/ml_proxy.py` | El intermediario que anota toda ventana que pasa (con su etiqueta) |
| `scripts/collect_training_data.sh` | Automatiza el circuito de recolección completo |
| `scripts/simulate_ransomware.py` | El atacante simulado (solo VM) |
| `data/training_data.csv` | El dataset (no se commitea al repo) |
| `/var/lib/guardian/models/` | Los modelos entrenados (tampoco) |
