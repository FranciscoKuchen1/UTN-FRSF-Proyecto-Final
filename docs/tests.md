# Qué verifica cada test

Cuando algo se rompe, esta tabla te dice exactamente qué parte del sistema está protegida por cada test y por qué existe. Los tests viven en `tests/unit/` (y `tests/test_analyzer.c`) y se corren todos con:

```bash
./scripts/run_tests.sh
```

> **Cómo leerlo:** cada test es un programita chico que arma una situación concreta (por ejemplo, "un buffer con los 256 bytes posibles") y comprueba que el módulo responda lo esperado. Si el test falla, sabés que ese comportamiento específico se rompió.

---

## 1. Entropía — el "medidor de revuelto" de los datos

**Archivo:** `tests/unit/test_entropy.c` · **Módulo:** `src/entropy.c`

La entropía mide qué tan predecibles son los bytes de un archivo. Un texto repetitivo tiene entropía baja; los datos cifrados (que se ven como ruido aleatorio) tienen entropía casi máxima. Este número es la base de toda la detección, así que sus tests usan casos donde el resultado correcto se conoce de antemano.

| Test | Situación que arma | Qué debe dar | Por qué importa |
|---|---|---|---|
| `test_shannon_uniform` | Un buffer con los 256 valores posibles de byte, uno de cada uno | Entropía = 8.0 (el máximo teórico) | Es la referencia de "datos perfectamente aleatorios", la firma del cifrado |
| `test_shannon_constant` | Un buffer con el mismo byte repetido | Entropía = 0.0 | El otro extremo: contenido totalmente predecible (ej. un archivo de puros ceros) |
| `test_shannon_empty` | Buffer de longitud cero | Devuelve 0 sin crashear | Los programas reales hacen escrituras vacías; el sistema no puede morir por eso |
| `test_chi_square_uniform` | Muestra con distribución uniforme | χ² = 0 | El test χ² es la segunda opinión: mide si los bytes están "bien repartidos". Cifrado real = reparto parejo |
| `test_chi_square_skewed` | 512 bytes iguales (reparto totalmente desparejo) | χ² enorme (> 100.000) | Confirma que el χ² distingue "aleatorio de verdad" de "repetitivo", incluso si la entropía se parece |
| `test_sliding_window` | Buffer de ceros dividido en bloques de 512 bytes | 2 bloques, ambos con entropía 0 | El análisis por bloques permite detectar cifrado **parcial** (ransomware que solo cifra el comienzo del archivo) |
| `test_autocorrelation` | Secuencia conocida [1,2,3,4] | Correlación ≈ 0.4545 | La correlación mide si una escritura se parece a la anterior. Un valor conocido valida la fórmula |
| `test_chi2_from_hist` | Histograma con 1 byte por casillero | χ² = 0 | Versión del χ² que parte de un histograma ya calculado (más rápido en la ventana del detector) |
| `test_chi2_from_hist_empty` | Histograma con total 0 | Devuelve 0 sin crashear | Caso borde de ventana vacía |

---

## 2. Detector — el que decide "normal / sospechoso / bloquear"

**Archivo:** `tests/unit/test_detector.c` · **Módulo:** `src/detector.c`

El detector junta varias señales (entropía, velocidad, renombrados, etc.) y da un veredicto por programa. Estos tests cubren los tres veredictos y, sobre todo, los casos donde **no** hay que bloquear (los falsos positivos son el peor enemigo de un sistema así).

| Test | Situación que arma | Qué debe dar | Por qué importa |
|---|---|---|---|
| `test_init` | Contexto recién creado, una escritura cualquiera | Veredicto NORMAL | Un sistema recién arrancado no puede andar bloqueando gente |
| `test_check_write_normal` | Una escritura de entropía baja | NORMAL | Un documento de texto común no debe generar alertas |
| `test_check_write_suspicious` | 21 escrituras seguidas con entropía 8.0 | SOSPECHOSO o peor | La "regla rápida": mucha escritura súper aleatoria seguida es firma de cifrado |
| `test_check_write_chi2_blocks` | Entropía alta **y** χ² parejo (uniforme) | Bloqueo | La combinación completa de "firma de cifrado": alto *y* parejo |
| `test_check_write_no_chi2_not_blocked` | Entropía alta pero χ² alto (desparejo) | **No** bloquea | Un `.jpg` o `.zip` tiene entropía alta pero estructura interna: sin el χ² lo bloquearíamos por error |
| `test_signal_canary` | Un programa abre un archivo señuelo para escribir y luego escribe datos cifrados | Bloqueo | Tocar un señuelo + cifrar = ataque confirmado |
| `test_canary_edit_not_blocked` | Un programa abre el señuelo pero escribe **texto** (baja entropía) | **No** bloquea | Una persona editando el archivo señuelo no puede morir por eso |
| `test_note_canary_read_not_blocked` | Un programa **lee** el señuelo (ej. `cp -r`, backup) | **No** bloquea | Los backups leen todos los archivos, incluidos los señuelos: leer no es atacar |
| `test_global_brake_multiprocess` | Varios procesos, cada uno escribiendo poco pero con firma de cifrado en total | Freno global: se bloquean los escritores con firma de cifrado | Un ransomware moderno reparte el trabajo en varios procesos para "esconderse" de los umbrales individuales |
| `test_unlink_backup_hunting` | Muchas eliminaciones de archivos en la ventana | Suma al score, sola no bloquea | Borrar backups es señal de ataque, pero un `make clean` legítimo no puede ser bloqueado |
| `test_check_rename_ext_change` | 5 renombrados que cambian la extensión (`.docx` → `.locked`) | SOSPECHOSO o peor | Cambiar extensiones en serie es el paso final clásico del ransomware |
| `test_check_rename_no_ext_change` | Renombrados que conservan la extensión | NORMAL | Reorganizar archivos (`mv informe.docx viejo/informe.docx`) es totalmente normal |
| `test_confirm_attack` | El análisis de ML confirma un ataque para un PID | Ese PID queda marcado; el contexto sigue usable | La "segunda opinión" del ML tiene que poder frenar al atacante en su próxima operación |
| `test_pid_starttime_unknown` | PID sin registro de hora de arranque | Se maneja sin crashear | Caso borde de procesos que aparecen antes del registro |
| `test_reset_pid_clears_state` | Se resetea el estado de un PID | Contadores en cero, sin estado viejo | Un PID reutilizado por otro programa no debe heredar el "prontuario" del anterior |
| `test_window_rotation` | Ventana de tiempo configurada en 0 | Rota en cada llamada, la regla rápida no dispara | Las ventanas de 5 segundos evitan acumular sospechas de hace una hora sobre actividad de ahora |

---

## 3. Canaries — los archivos señuelo

**Archivo:** `tests/unit/test_canary.c` · **Módulo:** `src/canary.c`

Los canaries son archivos falsos con nombres tentadores ("informe_financiero.docx") que ningún programa legítimo modificaría. Si alguien los toca para escribir, es casi seguro un ransomware recorriendo el disco.

| Test | Situación que arma | Qué debe dar | Por qué importa |
|---|---|---|---|
| `test_init` | Crear el contexto de canaries | Se crea sin errores | Sanity check de arranque |
| `test_canary_is_canary_true` | Preguntar por un archivo señuelo desplegado | Lo reconoce como canary | Si no los reconoce, la trampa no funciona nunca |
| `test_canary_is_canary_false` | Preguntar por un archivo cualquiera | No es canary | Si todo fuera canary, bloquearíamos programas normales |
| `test_deploy_count` | Desplegar N señuelos en un directorio temporal | Exactamente N archivos creados en disco | Los señuelos tienen que existir físicamente para que el ransomware los encuentre |

---

## 4. Ring buffer — la cola interna de eventos

**Archivo:** `tests/unit/test_ring_buffer.c` · **Módulo:** `src/ring_buffer.c`

Cuando un programa escribe un archivo, Guardian no puede detenerlo a analizar con calma (notarías la lentitud). Encola el evento y un hilo de fondo lo analiza después. Esta cola tiene que ser rápida y no perder el orden.

| Test | Situación que arma | Qué debe dar | Por qué importa |
|---|---|---|---|
| `test_create_destroy` | Crear y destruir la cola | Sin errores ni fugas de memoria | Sanity check del ciclo de vida |
| `test_push_pop_single` | Encolar un evento y sacarlo | Sale idéntico (todos los campos) | Si se corrompe un campo, el análisis posterior ve datos falsos |
| `test_push_pop_fifo` | Encolar 3 eventos y sacarlos | Salen en el mismo orden | El orden importa: la correlación temporal entre escrituras es una señal |
| `test_full_buffer` | Llenar la cola a capacidad y vaciarla | Sale todo, en orden | Bajo ataque la cola se llena: no puede perder ni desordenar eventos |
| `test_wrap_around` | Encolar, sacar, volver a encolar pasando el borde del arreglo circular | El "borde" se maneja bien | Un arreglo circular eventualmente da la vuelta; un error acá corrompería eventos cada cierto tiempo |

---

## 5. Mitigation — matar al proceso atacante

**Archivo:** `tests/unit/test_mitigation.c` · **Módulo:** `src/mitigation.c`

Cuando se confirma un ataque, Guardian mata al proceso atacante. Matar procesos es una acción drástica: estos tests se aseguran de que solo muera quien corresponde.

| Test | Situación que arma | Qué debe dar | Por qué importa |
|---|---|---|---|
| `test_kill_invalid_pid` | Intentar matar PIDs que no existen (números muy grandes, fuera de rango) | Falla limpiamente (`ESRCH`), sin afectar a nadie | Un PID mal calculado podría convertirse en "matar todo" — el peor desastre posible |
| `test_pid_reuse_not_killed` | El PID que disparó la alerta ya murió y el sistema se lo asignó a **otro** programa inocente | **No** lo mata | El veredicto puede llegar tarde (análisis de fondo); sin este chequeo mataríamos a un inocente que recicló el número |
| `test_function_exists` | Compilar y linkear la función | El símbolo existe | Garantía de compilación |

> **Nota de seguridad:** estos tests usan PIDs deliberadamente absurdos (por encima del máximo del sistema). Jamás probar con PIDs que puedan existir, y menos valores que se vuelvan negativos al convertirse: eso ordenaría matar a *todos* los procesos.

---

## 6. Analyzer — el hilo de fondo que prepara datos para el ML

**Archivo:** `tests/test_analyzer.c` · **Módulo:** `src/analyzer.c`

El analyzer agrupa la actividad de cada programa en "ventanas" de 5 segundos y calcula las 14 señales que después ve el modelo de ML. Es el módulo con más tests (25) porque concentra toda la matemática de las features.

### 6.1 Asignación de casilleros por programa (tabla de PIDs)

| Test | Qué verifica | Por qué importa |
|---|---|---|
| `test_get_slot_new_pid` | Un programa nuevo obtiene su casillero, limpio y con su número | Cada programa se analiza por separado |
| `test_get_slot_same_pid` | El mismo programa siempre usa el mismo casillero | Si no, sus estadísticas se reiniciarían a cada rato |
| `test_get_slot_different_pids` | Programas distintos obtienen casilleros distintos | Un atacante no debe poder "mezclarse" con otros |
| `test_get_slot_table_full` | Con la tabla llena (128 programas), uno más es rechazado limpiamente | La memoria es finita: el rechazo controlado evita corrupción |
| `test_get_slot_reuse_inactive` | Un casillero liberado puede ser reusado por otro programa | Sin reciclaje, la tabla se agotaría para siempre |
| `test_get_slot_does_not_rotate_expired` | Buscar un casillero **no** resetea una ventana vencida | Bug de regresión: antes se perdían las estadísticas acumuladas antes de enviarlas al ML |
| `test_get_slot_reuse_zeroes_stale` | Al reusar un casillero, no queda basura del programa anterior | Un programa nuevo no puede heredar el historial de otro |

### 6.2 Ventanas de tiempo (rotación)

| Test | Qué verifica | Por qué importa |
|---|---|---|
| `test_window_rotation_expired` | Ventana vencida **sin** servidor ML disponible: se **retiene** para reintentar | Antes se descartaba: se perdían justamente las ventanas más valiosas (las de un atacante recién matado) |
| `test_window_rotation_still_active` | Ventana vigente: no se toca | No se puede resetear a mitad de ventana |
| `test_window_double_rotation` | Primera retención sin ML; vencido el plazo de retención, el casillero se libera | Sin ese plazo, un servidor ML caído llenaría la tabla para siempre |
| `test_window_rotation_exact_boundary` | Ventana que expira en el segundo exacto | Caso borde del "≥" |
| `test_window_rotation_preserves_identity` | Ventana retenida conserva su número de programa y estado activo | Perder la identidad arruinaría el seguimiento |

### 6.3 Cálculo de señales (features)

| Test | Qué verifica | Por qué importa |
|---|---|---|
| `test_entropy_max_tracking` | Lleva correctamente el máximo de entropía visto | Un solo pico de entropía 8.0 ya es sospechoso, aunque el promedio sea bajo |
| `test_entropy_std_known_values` | Desviación estándar con valores calculables a mano | Datos cifrados tienen variación casi nula; los normales, mucha |
| `test_entropy_std_guards` | Casos borde (0 o 1 muestra) sin crashear | Casos borde |
| `test_autocorr_needs_history` | Con menos de 3 muestras no intenta correlacionar | Evita dividir por cero |
| `test_read_write_ratio` | Ratio lecturas/escrituras correcto | Un backup lee mucho y escribe poco; el ransomware lee y escribe parejo |
| `test_ext_change_rate` | Proporción de renombrados que cambian extensión | Casi exclusivo de ransomware |
| `test_fnv1a_hash_deterministic` | El mismo texto siempre da el mismo hash | Los hashes identifican directorios/extensiones sin guardar texto |
| `test_hash_set_add_dedup_and_cap` | El conjunto no repite elementos y tiene tope | "Directorios distintos tocados" no puede crecer sin control |
| `test_path_dir_hash` / `test_path_ext_hash` | Extrae correctamente directorio y extensión de una ruta | El ransomware recorre muchos directorios y tipos de archivo; un editor no |
| `test_chi2_mean_samples_only` | El promedio de χ² solo cuenta las muestras válidas (≥ 256 bytes) | Muestras chicas no alcanzan para un test estadístico serio |
| `test_flush_resets_new_fields` | Al liberarse un casillero vencido, todos los campos quedan en cero | Sin basura entre programas |

---

## Resumen

| Grupo | Tests | Enfoque |
|---|---|---|
| Entropía | 9 | La matemática básica no miente |
| Detector | 16 | Bloquear lo malo **y** no bloquear lo bueno |
| Canaries | 4 | La trampa existe, se reconoce y se despliega |
| Ring buffer | 5 | La cola interna no pierde ni desordena |
| Mitigation | 3 | Matar solo al culpable |
| Analyzer | 24 | Las 14 señales del ML, bien calculadas |
| **Total** | **61** | |

Los tests de sistema completos (FUSE montado + ZFS + simulador de ransomware) no están automatizados como unit tests: se hacen con los scripts operativos que se describen en [`docs/testing-guide.md`](testing-guide.md).
