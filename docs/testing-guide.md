# Guía de testing y operación

> Cómo comprobar que el sistema funciona y cómo usar los scripts de operación. Para saber **qué verifica cada test individual**, andá a [`docs/tests.md`](tests.md).

---

## 1. Los tests unitarios (rápidos e inocuos)

```bash
./scripts/run_tests.sh
```

Compila todo y corre las 6 suites (61 tests en total). No necesitan root, ni FUSE montado, ni ZFS: cada test arma su propia situación en memoria o en `/tmp`. Dura menos de un segundo y es lo primero que hay que correr después de cualquier cambio de código.

```bash
# Un solo test directo (ejemplo):
./build/tests/unit/test_entropy

# Un solo test vía ctest:
cd build && ctest --output-on-failure -R test_detector --test-dir tests/unit
```

| Suite | Tests | Qué protege |
|---|---|---|
| `test_entropy` | 9 | La matemática de "qué tan revueltos están los bytes" |
| `test_detector` | 16 | Bloquear lo malo **y no molestar** a backups, compresores y editores |
| `test_canary` | 4 | Los archivos señuelo existen y se reconocen |
| `test_ring_buffer` | 5 | La cola interna de eventos no pierde ni desordena |
| `test_mitigation` | 3 | Matar solo al culpable, jamás a un inocente |
| `test_analyzer` | 24 | Las 14 señales del ML, bien calculadas, y la gestión de ventanas |

---

## 2. La prueba de fuego: simulador de ransomware (solo VM)

Con el filesystem montado (`sudo ./scripts/mount.sh /mnt/guardian_real /mnt/protected tank/data`), el simulador hace de atacante dentro de la carpeta protegida:

```bash
# Ataque típico: cifra y renombra todo lo que encuentra
python3 scripts/simulate_ransomware.py --target-dir /mnt/protected --file-count 40

# Ataque sigiloso (más lento, para probar que no se evade)
python3 scripts/simulate_ransomware.py --target-dir /mnt/protected \
  --mode stealth --file-count 20 --pause-ms 200

# Ataque realista: 4 procesos paralelos + cifrado parcial (estilo LockBit)
python3 scripts/simulate_ransomware.py --target-dir /mnt/protected \
  --workers 4 --partial-encrypt 50 --realistic
```

**Cómo saber que la defensa funcionó** (el simulador suele terminar matado por Guardian, y eso es una *buena* señal):

```bash
# El relato del incidente, en orden:
sudo tail /var/log/guardian/events.jsonl
#   write_suspicious  → primer aviso (entropía ~8)
#   rename_blocked    → el renombrado ".locked" no se permitió
#   process_killed    → el atacante murió

# La foto del disco tomada en el momento:
sudo zfs list -t snapshot tank/data        # guardian_emergency_*

# Y volver todo como estaba:
sudo ./scripts/rollback.sh tank/data latest
```

> El simulador tiene `--avoid-canary` (evita los archivos señuelo) y `--canary-hunt` (los busca) para probar ambas defensas por separado, y `--mmap` para probar el bypass por memoria mapeada (documentado como pendiente).

---

## 3. Los scripts del circuito ML

| Script | Para qué | Cuándo |
|---|---|---|
| `test_ml_pipeline.sh [label] [rondas]` | Prueba de humo del circuito completo: compila, levanta server + proxy + FUSE, corre simulador o workload benigno, verifica que lleguen filas al CSV, y limpia todo | Después de tocar cualquier cosa del ML |
| `quick_test_ml.sh [label]` | Ídem pero sin compilar (para iterar rápido) | Ídem, con todo ya compilado |
| `collect_training_data.sh [rondas]` | Genera el dataset: rondas de ataque + rondas benignas variadas, en modo sombra, etiquetadas por sesión | Para entrenar / reentrenar |
| `diagnose_ml.sh` | Chequeo por partes del circuito ML sin FUSE (deps → server → proxy → CSV) | Cuando algo del circuito falla y no sabés qué |

Los tres primeros levantan y tiran su propio stack en `/tmp` (no tocan datos reales) y dejan sus logs en `logs/`.

**Un detalle que ahorra horas de debug:** si un script de estos "termina raro" sin mensaje de error, mirá primero los logs de `logs/` (`ml_server.log`, `ml_proxy.log`, `fuse.log`). El 90% de las veces es el server que tardó en arrancar o el proxy que murió por una carrera de arranque — ambos casos ya están arreglados, pero los logs son el lugar correcto para empezar.

---

## 4. Scripts de infraestructura

| Script | Uso |
|---|---|
| `install_deps.sh` | `sudo ./scripts/install_deps.sh` — instala herramientas del sistema (una vez) |
| `zfs_setup.sh` | `sudo ./scripts/zfs_setup.sh` — crea el disco de pruebas de 2 GB con ZFS (una vez) |
| `mount.sh` | `sudo ./scripts/mount.sh <carpeta real> <carpeta protegida> [dataset]` — monta el filesystem protegido |
| `rollback.sh` | `sudo ./scripts/rollback.sh tank/data latest` — vuelve el disco a la foto anterior (o a una específica) |
| `cleanup_test.sh` | Destruuye el pool de pruebas y los restos de montajes — usar con cuidado |

Todos son idempotentes: correrlos de nuevo no rompe nada.

---

## 5. Problemas frecuentes

| Síntoma | Causa probable | Qué hacer |
|---|---|---|
| `test_mitigation` mata procesos del sistema | Se probó con un PID que se vuelve negativo al castear | Usar solo PIDs válidos; ver la nota de seguridad en `docs/tests.md` |
| `cmake` falla con "libfuse3 not found" | Faltan los headers de FUSE | `sudo apt install libfuse3-dev` |
| Programas fallan dentro del mount con "Function not implemented" | Falta un handler passthrough en `gfs_*` | Implementarlo como passthrough directo (ver developer-guide §3) |
| `ls` dentro del mount muestra permisos `000` / fecha 1970 | El listado entrega atributos incompletos | Cada entrada debe ir con su `lstat` completo |
| FUSE no monta | Falta `/dev/fuse` o permisos | Verificar `/dev/fuse` y, para `allow_other`, la línea `user_allow_other` en `/etc/fuse.conf` |
| El simulador termina con status 137 | **Guardian lo mató** — la detección funcionó | No es un error: ver `events.jsonl` |
| Los snapshots no se crean | El daemon corre como usuario normal (ZFS requiere root) | Montar con `sudo ./scripts/mount.sh` |
| El ml_server "no crea el socket" | Con modelos entrenados tarda ~5 s en cargar | Esperar 15 s en el poll (ya así está en los scripts) |

---

## 6. Qué NO está automatizado

Los tests unitarios no cubren FUSE montado, ZFS real ni el simulador (necesitan la VM). Eso se prueba con los scripts de esta guía, a mano. La automatización de esos casos como integration tests está en la lista de pendientes.
