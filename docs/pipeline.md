# Cómo funciona Guardian FS — diagramas del pipeline

Esta página muestra el flujo completo del sistema con diagramas. Se leen de arriba hacia abajo y siguen el camino real que recorre una operación de archivo.

> Si preferís texto antes que diagramas, el detalle módulo por módulo está en [`docs/developer-guide.md`](developer-guide.md).

---

## 1. Vista general: el sistema montado

Guardian FS se instala como una "capa" entre los programas y el disco real. Los programas guardan archivos en `/mnt/protected` sin saber que alguien revisa lo que escriben; detrás, los datos terminan en un dataset ZFS que además se fotografía (snapshots) cada 60 segundos.

```mermaid
flowchart TB
    subgraph apps["Programas del usuario"]
        A1["Editor de texto"]
        A2["Backup / compresión"]
        A3[" ransomware (si lo hay) "]
    end

    subgraph fuse["Guardian FS — capa de interposición (FUSE)"]
        direction TB
        W["gfs_write: calcula entropía de lo que se escribe<br/>y lo evalúa AL INSTANTE"]
        D["Detector: puntaje por programa<br/>(entropía, velocidad, renombrados, señuelos…)"]
        Q["Cola interna de eventos"]
        AN["Analyzer: hilo de fondo<br/>resume cada 5 s lo que hizo cada programa"]
    end

    subgraph ml["Segunda opinión (opcional)"]
        P["ml_proxy<br/>(en el medio, anota todo en un CSV)"]
        S["ml_server<br/>(Random Forest + XGBoost + Isolation Forest)"]
    end

    subgraph storage["Disco real"]
        Z["Dataset ZFS tank/data<br/>+ snapshot cada 60 s<br/>+ snapshot de emergencia al detectar ataque"]
    end

    A1 --> W
    A2 --> W
    A3 --> W
    W --> D
    W --> Q --> AN --> P --> S
    S -- "veredicto attack →<br/>se confirma el ataque" --> D
    D -- "normal" --> Z
    D -- "¡bloqueo!" --> K["Matar al atacante (SIGKILL)<br/>+ snapshot de emergencia<br/>+ la escritura NUNCA llega al disco"]

    style A3 fill:#fdd,stroke:#c33
    style K fill:#fdd,stroke:#c33
    style D fill:#ffd,stroke:#b80
    style Z fill:#dfd,stroke:#3a3
```

**Tres cosas clave del diseño:**

1. **La decisión rápida es local y síncrona** (el detector C): ocurre dentro de la misma operación de escritura, en menos de un milisegundo. Por eso puede frenar el ataque antes de que los bytes cifrados toquen el disco.
2. **La opinión del ML llega después** (asíncrona): el analyzer resume ventanas de 5 segundos y se las manda al servidor Python. Si el ML dice "ataque", el detector queda avisado y bloquea al atacante en su próxima operación. El ML **refina**, nunca reemplaza al detector.
3. **Todo funciona aunque falte el ML**: si el servidor Python no está, el sistema degrada a detección estadística pura. La seguridad no depende de un proceso de Python.

---

## 2. Qué pasa en cada escritura, paso a paso

Este es el corazón del sistema: cada vez que cualquier programa escribe un archivo, se recorre este camino.

```mermaid
flowchart TB
    START(["write(archivo, datos)"]) --> ENT["1. Medir los datos entrantes<br/>entropía (qué tan 'revueltos')<br/>+ χ² (qué tan 'parejos')"]
    ENT --> EV["2. Anotar el evento en la cola<br/>para el análisis de fondo"]
    EV --> SC["3. Detector: sumar señales del programa<br/>en su ventana de 5 segundos"]
    SC --> C1{"¿Tocó un<br/>archivo señuelo?"}
    C1 -- "sí, y lo que escribe<br/>parece cifrado" --> BLOCK
    C1 -- "no" --> C2{"¿El puntaje<br/>supera 0.65?"}
    C2 -- "sí" --> BLOCK["BLOQUEAR"]
    C2 -- "no" --> C3{"¿Supera 0.45?"}
    C3 -- "sí" --> WARN["SOSPECHOSO:<br/>pasa, pero se anota<br/>y se toma snapshot temprano"]
    C3 -- "no" --> OK["NORMAL"]
    WARN --> DISK
    OK --> DISK(["4. Escribir en el disco ZFS<br/>(el usuario ni se entera)"])
    BLOCK --> MIT["Snapshot de emergencia<br/>+ matar al atacante<br/>+ responder 'permiso denegado'"]

    style BLOCK fill:#fdd,stroke:#c33
    style MIT fill:#fdd,stroke:#c33
    style OK fill:#dfd,stroke:#3a3
    style DISK fill:#dfd,stroke:#3a3
```

**Ejemplo concreto:**

- Guardás un documento desde LibreOffice → entropía ~4.5 → puntaje bajo → se escribe normal.
- Comprimís una carpeta con `gzip` → entropía alta (~7.9) pero el χ² muestra estructura interna → **no** se bloquea (esta distinción es clave para no molestar backups).
- Un ransomware cifra archivos → entropía ~8.0 **y** χ² parejo **y** renombrados con cambio de extensión **y** varios directorios recorridos → puntaje alto → bloqueo + kill + snapshot.

---

## 3. Pipeline de datos y entrenamiento del ML

El modelo no nace solo: hay que generarle datos. Este flujo es el que se automatiza con `scripts/collect_training_data.sh`.

```mermaid
flowchart TB
    subgraph collect["FASE 1 — Recolectar (en una VM, sin tocar datos reales)"]
        direction LR
        AT["Rondas de ataque<br/>simulador de ransomware<br/>(modos, velocidades y<br/>cantidad de procesos variados)"]
        BE["Rondas benignas<br/>compilar, git, rsync,<br/>logs, gzip, copias…"]
        STACK["Stack temporal en /tmp:<br/>ml_server + ml_proxy + FUSE<br/>en modo sombra (anota, no bloquea)"]
        AT --> STACK
        BE --> STACK
        STACK --> CSV["data/training_data.csv<br/>una fila por ventana de 5 s<br/>con su etiqueta (0 benigno / 1 ataque)<br/>y su sesión de origen"]
    end

    CSV --> TRAIN["FASE 2 — Entrenar (train_model.py)"]
    subgraph eval["Evaluación honesta<br/>(sin trampas)"]
        E1["Las ventanas de una misma sesión<br/>van juntas a entrenar O a evaluar,<br/>nunca repartidas (evita 'copiarse la respuesta')"]
        E2["El escalado de datos se calcula<br/>solo con los datos de entrenamiento<br/>de cada ronda"]
    end
    TRAIN --> eval --> MODELS["FASE 3 — Modelos entrenados<br/>/var/lib/guardian/models/"]

    MODELS --> SERV["El ml_server los carga<br/>y ya responde con el ensemble<br/>en producción"]

    style CSV fill:#ffd,stroke:#b80
    style MODELS fill:#dfd,stroke:#3a3
```

**Por qué el "modo sombra"**: si el atacante simulado muriera en su primera ventana (como pasa en modo real), solo veríamos una fila por ataque. En modo sombra el sistema anota todo sin bloquear ni matar, y cada ataque aporta muchas filas: las de su inicio, desarrollo y captura.

**Un detalle que costó descubrir**: las clases de ejemplos benignos tienen que cubrir los casos *difíciles* — programas que escriben datos muy "revueltos" sin ser atacantes (comprimir, guardar multimedia). Si una clase falta del dataset, el modelo etiqueta mal a esos programas. Por eso las rondas benignas incluyen gzip de archivos grandes, compilaciones, escritura de bloques idénticos, etc.

---

## 4. Recuperación después de un ataque

Detectar y matar al atacante es la mitad del trabajo; la otra mitad es volver al estado de antes. Los snapshots de ZFS funcionan como fotos del disco: tomar la foto es instantáneo porque no copia datos, solo anota "desde acá, si algo cambia, se guarda en otro lado".

```mermaid
sequenceDiagram
    participant R as Ransomware
    participant G as Guardian FS
    participant Z as ZFS (disco real)
    participant OP as Operador

    Note over Z: Fotos automáticas cada 60 s (guardian_auto_*)
    R->>G: cifra archivo #1 (entropía 8.0)
    G->>Z: snapshot de emergencia (guardian_emergency_*)
    Note over G: guarda la foto del estado<br/>casi limpio, pre-daño mayor
    G--xR: permiso denegado + SIGKILL
    Note over R: el ataque muere acá.<br/>Solo los primeros archivos quedaron cifrados.
    OP->>Z: ./scripts/rollback.sh tank/data latest
    Z-->>OP: disco vuelve a la foto:<br/>los archivos cifrados se restauran
    Note over OP: Tiempo total de recuperación: ~1 segundo
```

**Las dos fotos que importan:**

| Snapshot | Cuándo se toma | Para qué sirve |
|---|---|---|
| `guardian_auto_*` (cada 60 s) | Siempre, en fondo | Red de seguridad ante cualquier problema (no solo ransomware) |
| `guardian_emergency_*` | En la primera sospecha y en cada bloqueo | Congela el estado justo antes del daño mayor: minimiza cuántos archivos hay que recuperar |

---

## 5. Mapa de repositorio (dónde está cada cosa)

```mermaid
flowchart LR
    subgraph src["src/ — el sistema"]
        GF["guardian_fs.c<br/>la capa FUSE"]
        DET["detector.c, entropy.c<br/>detección instantánea"]
        ANZ["analyzer.c<br/>hilo de fondo"]
        MISC["canary, zfs_snap,<br/>ring_buffer, mitigation"]
        PY["ml_server.py, train_model.py<br/>el lado ML"]
    end
    subgraph scripts["scripts/ — operativa"]
        SETUP["install_deps, zfs_setup, mount"]
        TESTS["run_tests, test_ml_pipeline"]
        DATA["collect_training_data<br/>simulador de ransomware"]
    end
    subgraph docs["docs/ — esta documentación"]
        D1["developer-guide"]
        D2["ml (guía del modelo)"]
        D3["tests (qué verifica cada test)"]
        D4["cambios (bitácora)"]
    end
    subgraph out["salidas"]
        CSVD["data/training_data.csv<br/>(dataset, no se commitea)"]
        MDL["/var/lib/guardian/models/<br/>(modelos entrenados)"]
        LOGS["logs/ y /var/log/guardian/<br/>(evidencia de eventos)"]
    end
    src --> out
    scripts --> src
    scripts --> out
```
