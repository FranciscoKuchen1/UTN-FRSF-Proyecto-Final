# Guía para desarrolladores

> Cómo está armado Guardian FS por adentro, para quien va a leer o modificar el código. Si recién llegás al proyecto, empezá por el [`README.md`](../README.md) y los [diagramas](pipeline.md). La guía de tests está [acá](tests.md).

---

## 1. El problema que resuelve el código

Un ransomware cifrador hace siempre lo mismo: recorre tus archivos, y por cada uno **lee** el contenido, **escribe** una versión cifrada y **renombra** el archivo (`.docx` → `.locked`).

Ese primer paso deja una huella que no puede disimular: los datos cifrados son estadísticamente indistinguibles del ruido. Si medís "qué tan revueltos" están los bytes de un texto, da ~4 sobre 8; una foto comprimida da ~7; datos cifrados dan **7.9+ y parejos**, escritura tras escritura. Ningún archivo legítimo hace eso de forma sostenida.

Las defensas tradicionales llegan tarde: el antivirus de firmas no conoce el ransomware nuevo, y el backup programado… también termina cifrado. La única ventana útil es **mientras el ransomware escribe**: ahí podés frenarlo antes de que el daño sea grande. Para pararse en ese punto exacto, Guardian usa **FUSE** — un mecanismo de Linux que deja implementar un filesystem como un programa normal, sin tocar el kernel. Nuestro filesystem es un "pasamanos": todo lo que llega, lo deja pasar… salvo que huela a ataque.

**Y si igualmente algo se cifró** (los primeros archivos, antes de la detección), el disco real es ZFS, que saca "fotografías" del estado (snapshots) en forma instantánea y permite volver a cualquiera de ellas en ~1 segundo.

---

## 2. El reparto de responsabilidades (quién hace qué)

```
src/
├── guardian_fs.c   ← EL PASAMANOS: recibe cada operación de archivo
├── entropy.c       ← LA CALCULADORA: mide los datos escritos
├── detector.c      ← EL GUARDIA: decide al instante (normal/sospechoso/bloquear)
├── canary.c        ← LA TRAMPA: archivos señuelo
├── ring_buffer.c   ← LA COLA: eventos esperando análisis de fondo
├── analyzer.c      ← EL ANALISTA DE FONDO: resume ventanas de 5 s (para el ML)
├── mitigation.c    ← EL MARTILLAZO: matar al proceso atacante
├── zfs_snap.c      ← LA MÁQUINA DEL TIEMPO: snapshots y rollback
├── ml_server.py    ← segunda opinión (modelos entrenados)
└── train_model.py  ← entrenamiento de esos modelos
```

El criterio del reparto es **tiempo de reacción**:

| Camino | Corre | Debe tardar | Qué hace |
|---|---|---|---|
| **Síncrono** (dentro de la operación de escritura) | `guardian_fs` → `entropy` → `detector` | < 1 ms | Decide si la escritura pasa, y en ataque: bloquea, mata, fotografía |
| **Asíncrono** (hilo de fondo, cada 5 s) | `ring_buffer` → `analyzer` → ML | no importa, el usuario no espera | Resume ventanas de cada programa; el ML refina; un "attack" confirmado bloquea al atacante en su próxima operación |
| **Fondo permanente** | `zfs_snap` | — | Snapshot automático cada 60 s |

La regla de oro del diseño: **nunca hacer nada lento en el camino síncrono**. Si `gfs_write` tardara 100 ms, el usuario lo sentiría en cada guardado de archivo.

---

## 3. Módulo por módulo

### `guardian_fs.c` — el pasamanos

Implementa las operaciones de filesystem que FUSE le deriva (abrir, leer, escribir, renombrar, borrar, listar, permisos…). Para cada una hay una función `gfs_<operación>` que:

1. Traduce la ruta a la carpeta real del disco,
2. registra el evento en la cola de fondo,
3. y solo en las operaciones "sensibles" (escribir, renombrar, borrar, abrir señuelos) consulta al detector **antes** de ejecutar.

```c
// La idea central de gfs_write(), simplificada:
double ent = entropy_shannon(buf, size);          // 1. medir
ring_buf_push(evbuf, &evento);                    // 2. anotar para el fondo
int v = detector_check_write(det, pid, path, ent, size, chi2);  // 3. decidir
if (v == VERDICT_BLOCK && !modo_sombra) {
    zfs_snapshot_emergency(dataset);              // 4a. fotografía del disco
    mitigate_and_log(pid, path);                  //     matar al atacante
    return -EPERM;                                //     la escritura NO llega al disco
}
return pwrite(fd, buf, size, offset);             // 4b. escribir normalmente
```

**Detalle que suele morder:** las operaciones "inofensivas" también importan. `cp` cambia permutos del archivo copiado, `tar` restaura fechas, `mkdir` corrige modos. Si un handler falta, el kernel le contesta "no implementado" a los programas y todo falla dentro del mount (nos pasó: ver la bitácora). Los handlers passthrough tienen que ser completos, y el daemon no debe aplicar su propio umask — el del usuario ya fue aplicado.

**Modo sombra** (`GUARDIAN_SHADOW_MODE=1`): el detector opina igual y todo se anota en el log, pero no se bloquea, no se mata y no se fotografía. Pensado para observar la realidad sin interferir — y para juntar datos de entrenamiento completos.

### `entropy.c` — la calculadora

Tres mediciones distintas sobre los bytes de cada escritura:

| Función | Mide | Intuición |
|---|---|---|
| `entropy_shannon` | Qué tan "revueltos" están los bytes (0 = todos iguales, 8 = ruido perfecto) | El medidor principal |
| `entropy_chi_square` | Si los 256 valores posibles de byte aparecen en cantidades parejas | Segunda opinión: un `.jpg` está revuelto pero con estructura; el cifrado está revuelto **y parejo** |
| `entropy_autocorrelation` | Si una escritura se parece a la anterior | El comprimido repite patrones; el cifrado no |

La combinación **revuelto + parejo + sin parecido entre bloques** es la firma del cifrado, y es lo que el freno global del detector exige antes de bloquear por multitud (ver abajo).

### `detector.c` — el guardia

Mantiene una ficha por cada programa (PID) con su actividad de los últimos 5 segundos, y calcula un puntaje:

```
puntaje = 0.35·entropía + 0.20·velocidad de escritura + 0.15·renombrados
        + 0.20·uniformidad(χ²) + 0.10·borrados
```

| Puntaje | Veredicto | Qué pasa |
|---|---|---|
| < 0.45 | NORMAL | La escritura pasa |
| ≥ 0.45 | SOSPECHOSO | Pasa, pero se anota y se toma un snapshot temprano (por si acaso) |
| ≥ 0.65 | BLOQUEAR | Snapshot de emergencia + kill + la escritura no llega al disco |

Encima del puntaje hay tres reglas de oro que no negocian:

1. **Señuelo + cifrado = ataque confirmado.** Tocar un archivo trampa para escribir y después escribir datos con firma de cifrado bloquea al instante. (Pero editar el señuelo con texto normal, o *leerlo* como hace un backup, no: la trampa discrimina la intención.)
2. **Freno global.** Un ransomware moderno reparte el trabajo entre varios procesos para que cada uno quede bajo los umbrales. El detector también suma *en total* las escrituras con firma de cifrado de todos los procesos: si en la ventana hay 100+ (o 60+ renombrados con cambio de extensión), se arma el freno y se bloquea a los escritores con firma de cifrado — aunque su puntaje individual sea bajo. Un escritor benigno de baja entropía jamás es bloqueado por el freno.
3. **Confirmación externa.** El camino de fondo (ML) puede marcar a un programa como ataque confirmado; su próxima operación se bloquea.

Las fichas expiran: los programas inactivos más de 30 segundos liberan su lugar (la tabla es de tamaño fijo). Y antes de matar a alguien se verifica la identidad: si el PID original ya murió y el sistema recicló su número para un programa inocente, **no se lo mata** (el veredicto llegó tarde; el inocente no tiene la culpa).

### `canary.c` — la trampa

Despliega archivos falsos con nombres diseñados para que un ransomware que recorre el disco en orden alfabético los encuentre primero (`A_important_report.docx`) y último (`ZZ_backup_keys.txt`), más uno oculto y otros con extensiones codiciadas. El contenido es texto plausible y *de baja entropía* a propósito: si parecieran "ya cifrados", un ransomware inteligente los saltearía.

### `ring_buffer.c` — la cola

Comunicación entre el hilo que atiende operaciones de archivo (productor) y el analista de fondo (consumidor), sin llamadas al sistema: un arreglo circular con lock. El productor nunca se bloquea ocupándose de métricas caras.

### `analyzer.c` — el analista de fondo

Consume la cola y arma, por programa, ventanas de 5 segundos. Cuando una ventana vence con al menos 10 escrituras, calcula las **14 señales** (ver la [guía de ML](ml-architecture.md)) y se las manda al servidor Python por un socket local. Con menos de 10 escrituras, la ventana se descarta (no alcanza para un resumen estadístico serio).

**Regla aprendida por las malas:** si el envío falla (server caído, reinicio del intermediario), la ventana se **guarda y se reintenta** cuando la conexión vuelva — antes se descartaba y perdíamos justamente las ventanas de los atacantes recién matados. Con un tope de 30 s de retención para no llenar la tabla si el server no vuelve nunca.

### `mitigation.c` — el martillazo

`kill(pid, SIGKILL)`. SIGKILL y no SIGTERM porque el ransomware podría tener un manejador de "al recibir SIGTERM, cifrar todo lo que falta antes de morir". SIGKILL no se puede interceptar: el kernel destruye el proceso en el acto.

### `zfs_snap.c` — la máquina del tiempo

Tres momentos, tres funciones:

| Función | Cuándo | Qué |
|---|---|---|
| `zfs_snapshot_schedule` | Hilo de fondo, cada 60 s | Fotografía de rutina (`guardian_auto_*`, retiene las últimas 20) |
| `zfs_snapshot_emergency` | Primera sospecha y cada bloqueo | Fotografía del estado pre-daño (`guardian_emergency_*`, retiene 10). **Asíncrona**: el handler de escritura solo deja señalada la orden; ejecutar `zfs` cuesta decenas de milisegundos que el usuario no puede pagar dentro de su guardado |
| `zfs_rollback_latest` | Manual (`scripts/rollback.sh`) | Vuelve el disco a la foto más reciente |

Todas las llamadas a la herramienta `zfs` se hacen con `posix_spawnp` (sin shell de por medio: ni inyección de comandos ni el costo de levantar un shell en cada snapshot).

---

## 4. Los programas Python

| Archivo | Rol | Detalle |
|---|---|---|
| `src/ml_server.py` | Escucha el socket `/tmp/guardian_ml.sock`, corre el ensemble (Random Forest + XGBoost + Isolation Forest) y contesta con probabilidad de ataque + veredicto | Si no hay modelos entrenados, cae a reglas estadísticas simples y *sigue contestando*; importa las bibliotecas pesadas solo si hay modelos (un server sin modelos gasta 30 MB, no 130) |
| `src/train_model.py` | Lee `data/training_data.csv`, evalúa con separación por sesiones, entrena y guarda en `/var/lib/guardian/models/` | Entrena con la MISMA clase que sirve las predicciones: lo evaluado es lo desplegado |
| `scripts/ml_proxy.py` | Se interpone entre el analyzer y el server, y anota cada ventana que pasa en el CSV con su etiqueta | Sin él no hay dataset: es la "máquina de anotar" |

La comunicación C ↔ Python es JSON en líneas, sobre socket local: `{pid, features{...}}` hacia un lado, `{p_attack, verdict, scores}` hacia el otro. Un detalle crítico: el lado C parsea la respuesta buscando exactamente `"verdict":"attack"` (sin espacios) — si el lado Python cambia el formato de serialización, el veredicto deja de matchear silenciosamente y todo se lee como "normal". Cambiar el formato de un lado exige cambiarlo del otro.

---

## 5. Compilar, probar, correr

```bash
# Deps del sistema (una vez)
sudo ./scripts/install_deps.sh

# Compilar (C17, sin warnings con -Wall -Wextra)
cmake -DCMAKE_BUILD_TYPE=Release -S . -B build
cmake --build build --parallel

# Tests (61, ver docs/tests.md)
./scripts/run_tests.sh

# Disco de pruebas ZFS + montar (ver README paso a paso)
sudo ./scripts/zfs_setup.sh
sudo ./scripts/mount.sh /mnt/guardian_real /mnt/protected tank/data

# Circuito ML completo de punta a punta (compila, monta, simula, verifica)
./scripts/test_ml_pipeline.sh 1 0
```

**Gotchas de build/tests que conviene saber antes de romperse la cabeza:**

- `analyzer.c` se compila **aparte** de la librería de objetos: referencia dos globales (`evbuf`, `detector`) que define `guardian_fs.c`; `tests/test_analyzer.c` trae sus propios stubs e incluye el `.c` directamente para llegar a sus funciones internas.
- El binario **no lee** `configs/guardian.conf` (es referencia): se configura por variables de entorno (`GUARDIAN_REAL_ROOT`, `GUARDIAN_ZFS_DATASET`, `GUARDIAN_LOG_PATH`, `GUARDIAN_SHADOW_MODE`) y los umbrales están como constantes en `src/guardian_fs.c`.
- En `mitigation` y sus tests, jamás usar PIDs que queden negativos al castear: eso ordenaría matar a *todos* los procesos del sistema.
- `mount.sh` hace `exec` en foreground: para dejarlo corriendo, lanzarlo con `setsid`/`&`, o desde un systemd unit (pendiente).
- Los CSVs de datos, los modelos entrenados y los logs están gitignoreados — no commitearlos.

---

## 6. Decisiones de diseño (y sus alternativas)

| Decisión | Alternativa descartada | Por qué |
|---|---|---|
| FUSE (userspace) | Módulo de kernel | Un bug nuestro no paniquea el kernel; se debuggea como cualquier programa; y conectar Python por un socket es trivial. El costo (~2 µs por operación) es despreciable contra la latencia del disco |
| Detección en C, ML aparte | Todo en Python | El camino crítico mide en microsegundos; arrancar el intérprete de Python ya cuesta más que todo el presupuesto |
| ZFS | btrfs / LVM | Snapshots instantáneos e inmutables (ni root ni el ransomware puede modificar una foto del pasado), rollback en O(1) |
| Señuelos con discriminación de intención | Señuelo tocado = bloquear | Sin discriminar, un `cp -r` o un backup que *lee* los señuelos moriría injustamente |
| Ventanas por programa | Puntaje global del sistema | Un atacante no debe poder esconderse detrás de la actividad de programas honestos (por eso el freno global solo bloquea escritores con firma de cifrado) |
| Pasamanos FUSE completo (todas las operaciones) | Solo las "de interés" | Las herramientas cotidianas usan operaciones "inofensivas" (chmod, utimens…) de formas sorprendentes; si falta una, fallan dentro del mount |
| Descartar ventanas de <10 escrituras | Enviar todo | Menos de 10 escrituras no alcanzan para un resumen estadístico decente; enviar ruido degrada la señal |

---

## 7. Qué sigue (pendientes vivos)

La lista completa y actualizada vive en [`docs/pending.md`](pending.md). Los destacados de hoy:

- [ ] Leer el archivo de configuración en vez de variables de entorno
- [ ] Apagado ordenado (hoy no hay handler de SIGTERM/SIGINT)
- [ ] Freno global con umbral por usuario (hoy es global: en un sistema multiusuario, la actividad de uno puede frenar al otro)
- [ ] Falso positivo residual del detector rápido con `rsync` masivo dentro del mount (los renombrados de sus archivos temporales disparan la regla) — decisión de diseño pendiente
- [ ] Verificación empírica del bypass por `mmap` (escribir por memoria mapeada en vez de `write()`)
