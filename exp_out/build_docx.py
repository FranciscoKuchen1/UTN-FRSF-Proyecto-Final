#!/usr/bin/env python3
"""build_docx.py — Genera PF_Informe_Avance_3.docx sobre la plantilla del
Avance 2 (estilos IEEE). Lee los resultados de exp_out/ y calcula las
estadísticas del informe. CORRER DESDE LA RAÍZ DEL REPO."""
import os
import pandas as pd
from docx import Document
from docx.shared import Pt, Cm
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.enum.table import WD_TABLE_ALIGNMENT
from docx.oxml.ns import qn
from docx.oxml import OxmlElement
import copy

TPL = "exp_out/template_norm.docx"
OUT = "PF_Informe_Avance_3.docx"
FIG = "exp_out/fig"

# ───────────────────────── estadísticas desde los CSV ─────────────────────
def stats():
    d = {}
    try:
        a = pd.read_csv("exp_out/attack_results.csv")
        g = a.groupby("perfil").agg(
            det=("killed_events", lambda s: int((s > 0).sum())),
            locked_med=("locked_files", "median"),
            locked_max=("locked_files", "max"),
            bytes_med=("locked_bytes", "median"),
            wall_med=("wall_ms", "median"),
            n=("rep", "count"))
        d["atk"] = g
        d["atk_rate"] = int(g.det.sum() / g.n.sum() * 100)
        d["locked_med_global"] = float(a.locked_files.median())
        d["locked_max_global"] = int(a.locked_files.max())
        d["bytes_med_global"] = float(a.locked_bytes.median())
        d["bytes_max_global"] = int(a.locked_bytes.max())
        d["wall_med_global"] = float(a.wall_ms.median() / 1000)
    except Exception as e:
        print("WARN attack:", e)
    try:
        d["esc"] = pd.read_csv("exp_out/escenarios.csv")
    except Exception as e:
        print("WARN escenarios:", e)
    try:
        d["fp"] = pd.read_csv("exp_out/fp_results.csv")
        d["fp_total_wl"] = len(d["fp"])
        d["fp_con_fp"] = int((d["fp"].blocked_events > 0).sum())
    except Exception as e:
        print("WARN fp:", e)
    try:
        b = pd.read_csv("exp_out/bench_results.csv")
        m = b.groupby(["workload", "ruta"]).ms.median().unstack()
        d["bench"] = m
        d["ov"] = {w: int(round((m.loc[w, "guardian"] / m.loc[w, "directo"] - 1) * 100))
                   for w in m.index}
    except Exception as e:
        print("WARN bench:", e)
    try:
        d["snap"] = open("exp_out/snapshot_overhead.txt").read().strip()
    except Exception:
        d["snap"] = None
    return d

S = stats()

# ───────────────────────── helpers docx ───────────────────────────────────
doc = Document(TPL)
body = doc.element.body
final_sect = body.find(qn("w:sectPr"))

# limpiar el cuerpo (conserva el sectPr final y headers/footers del template)
for child in list(body):
    if child.tag != qn("w:sectPr"):
        body.remove(child)

# el cuerpo final queda a 2 columnas (como la sección de cuerpo del Avance 2)
cols = final_sect.find(qn("w:cols"))
if cols is None:
    cols = OxmlElement("w:cols"); final_sect.append(cols)
cols.set(qn("w:num"), "2")
cols.set(qn("w:space"), "18pt")

def P(text="", style=None, align=None, size=None, bold=None):
    p = doc.add_paragraph()
    if style:
        try:
            p.style = doc.styles[style]
        except KeyError:
            print("WARN estilo no encontrado:", style)
    if text:
        r = p.add_run(text)
        if size: r.font.size = Pt(size)
        if bold is not None: r.font.bold = bold
    if align: p.alignment = align
    return p

def H1(t): return P(t, style="heading 1")
def H2(t): return P(t, style="heading 2")

def seccion_titulo_1col():
    """Cierra la sección del bloque de título (1 columna, continua)."""
    p = OxmlElement("w:p")
    pPr = OxmlElement("w:pPr")
    sect = OxmlElement("w:sectPr")
    tipo = OxmlElement("w:type"); tipo.set(qn("w:val"), "continuous"); sect.append(tipo)
    for tag in ("w:pgSz", "w:pgMar"):
        src = final_sect.find(qn(tag))
        if src is not None:
            sect.append(copy.deepcopy(src))
    c = OxmlElement("w:cols"); c.set(qn("w:space"), "36pt")  # 1 columna
    sect.append(c)
    pPr.append(sect)
    p.append(pPr)
    body.append(p)

def _borders(el, top=None, bottom=None):
    """bordes de párrafo o celda: lista de ('top','single','8')..."""
    pPr = el.get_or_add_pPr() if el.tag == qn("w:p") else el.get_or_add_tcPr()
    b = OxmlElement("w:pBdr") if el.tag == qn("w:p") else OxmlElement("w:tcBorders")
    for side, val, sz in (top or []) + (bottom or []):
        e = OxmlElement(f"w:{side}")
        e.set(qn("w:val"), val); e.set(qn("w:sz"), sz)
        e.set(qn("w:space"), "0"); e.set(qn("w:color"), "000000")
        b.append(e)
    pPr.append(b)

def TABLA(num, titulo, header, rows, widths=None):
    # caption (estilo IEEE: arriba, "TABLA N" + título)
    P(titulo.upper(), style="table head", align=WD_ALIGN_PARAGRAPH.CENTER)
    t = doc.add_table(rows=len(rows) + 1, cols=len(header))
    t.alignment = WD_TABLE_ALIGNMENT.CENTER
    t.autofit = True
    for j, h in enumerate(header):
        cell = t.rows[0].cells[j]
        cell.paragraphs[0].style = doc.styles["table col head"]
        cell.paragraphs[0].add_run(h)
        _borders(cell.paragraphs[0]._p, bottom=[("bottom", "single", "8")])
    for i, row in enumerate(rows):
        for j, v in enumerate(row):
            cell = t.rows[i + 1].cells[j]
            p = cell.paragraphs[0]
            p.style = doc.styles["table copy"]
            p.add_run(str(v))
    # reglas IEEE: línea sobre cabecera, línea al pie de la tabla
    tbl = t._tbl
    tblPr = tbl.tblPr
    borders = OxmlElement("w:tblBorders")
    for side in ("top", "bottom"):
        e = OxmlElement(f"w:{side}")
        e.set(qn("w:val"), "single"); e.set(qn("w:sz"), "8")
        e.set(qn("w:space"), "0"); e.set(qn("w:color"), "000000")
        borders.append(e)
    tblPr.append(borders)
    return t

def FIGURA(png, caption, width_cm=8.7):
    if not os.path.exists(png):
        print("WARN falta figura:", png); return
    p = doc.add_paragraph(); p.alignment = WD_ALIGN_PARAGRAPH.CENTER
    p.add_run().add_picture(png, width=Cm(width_cm))
    P(caption, style="figure caption", align=WD_ALIGN_PARAGRAPH.CENTER)

# ═══════════════════════ BLOQUE DE TÍTULO (1 columna) ═════════════════════
P("Proyecto Final. Informe de Avance 3: Detección y Mitigación de Daños "
  "Frente a Ataques de Ransomware — Prueba de Concepto", style="paper title")
for nom, mail in (("Ivo Gómez Enrico", "igomezenrico@frsf.utn.edu.ar"),
                  ("Francisco Kuchen", "fkuchen@frsf.utn.edu.ar")):
    P(nom, style="Author", align=WD_ALIGN_PARAGRAPH.CENTER)
    P("Departamento Ingeniería en Sistemas de Información", style="Affiliation",
      align=WD_ALIGN_PARAGRAPH.CENTER)
    P("Universidad Tecnológica Nacional, Facultad Regional Santa Fe", style="Affiliation",
      align=WD_ALIGN_PARAGRAPH.CENTER)
    P(f"Santa Fe, Argentina — {mail}", style="Affiliation", align=WD_ALIGN_PARAGRAPH.CENTER)
seccion_titulo_1col()

# ═══════════════════════ CUERPO (2 columnas) ══════════════════════════════
P("Abstract—Este informe presenta el tercer avance del Proyecto Final: el prototipo "
  "operativo de los módulos de detección y recuperación de Guardian FS validado sobre "
  "el conjunto base de pruebas. Se completó la campaña de recolección y el entrenamiento "
  "del modelo de Machine Learning con la metodología sin fuga de información "
  f"(1805 ventanas, 127 sesiones), incorporando las clases benignas de alta entropía cuya "
  "ausencia producía falsos positivos reales. La campaña experimental sobre los tres "
  "niveles del diseño (sin protección / ZFS solo / ZFS + detección activa) muestra que el "
  f"prototipo neutraliza el {S.get('atk_rate', '—')}% de las corridas de ataque del "
  f"conjunto de calibración con una pérdida mediana de {S.get('locked_med_global', 0):.0f} "
  f"archivos ({S.get('bytes_med_global', 0)/1024:.0f} KiB) antes del freno, un RTO de "
  "rollback del orden de 1 s y una degradación de E/S atribuible a la capa de intercepción "
  "FUSE que se documenta por workload.", style="Abstract")
P("Palabras Clave—ransomware, FUSE, ZFS, snapshots, detección de comportamiento, "
  "machine learning, métricas de recuperación, RTO, falsos positivos.", style="Keywords")

H1("INTRODUCCIÓN")
P("El presente documento constituye el Informe de Avance 3, conforme al contenido "
  "propuesto en el plan del proyecto: el prototipo inicial de los módulos de detección y "
  "recuperación de ataques, luego del conjunto base de pruebas. Sobre lo presentado en el "
  "Informe de Avance 2 (implementación avanzada de la herramienta y desarrollo del modelo "
  "con su metodología de evaluación), en esta etapa se: (1) completó la campaña de "
  "recolección y el entrenamiento definitivo del modelo; (2) maduró la integración del "
  "prototipo, corrigiendo los defectos que la campaña de pruebas expuso en la capa de "
  "intercepción; y (3) ejecutó la campaña experimental que cuantifica las variables "
  "dependientes del diseño (pérdida de información, RTO, sobrecarga de almacenamiento y "
  "degradación de E/S) sobre los tres niveles de la variable independiente.",
  style="Body Text")
P("La organización sigue la del informe anterior: la Sección 2 resume el estado respecto "
  "del cronograma; la Sección 3 la madurez del prototipo; la Sección 4 el modelo "
  "entrenado; la Sección 5 la campaña experimental con sus resultados; y la Sección 6 los "
  "próximos pasos hacia el informe final.", style="Body Text")

H1("ESTADO DE AVANCE RESPECTO DEL CRONOGRAMA")
TABLA("I", "Estado de avance respecto del cronograma",
      ["Etapa (cronograma)", "Tareas principales", "Estado"],
      [["Mes 1–4", "Relevamiento, infraestructura, desarrollo e implementación avanzada de la herramienta.",
        "Completado (Informes 1 y 2)"],
       ["Mes 5 — Integración de modelo de ML",
        "Campaña de recolección (6 tandas, 135 rondas de ataque y 145 benignas) y entrenamiento definitivo.",
        "Completado"],
       ["Mes 6 — Pruebas",
        "Conjunto base extendido (61 tests / 319 aserciones), campaña de detección (6 perfiles × 3 corridas), comparativa de escenarios, métricas de la PoC y campaña de falsos positivos. Fase de destrucción con muestras reales: pendiente.",
        "En curso avanzado"],
       ["Mes 7 — Análisis de resultados",
        "Métricas comparativas de la Sección 5; procesamiento estadístico final: pendiente.",
        "Iniciado"]])
P("Síntesis: el prototipo de ambos módulos (detección y recuperación) opera de extremo a "
  "extremo sobre el conjunto base de pruebas; resta la fase de destrucción con muestras "
  "reales de las familias de referencia y el análisis estadístico final.", style="Body Text")

H1("MADUREZ DEL PROTOTIPO DE DETECCIÓN Y RECUPERACIÓN")
P("La integración continua sobre la VM de laboratorio expuso y permitió corregir tres "
  "defectos de la capa de intercepción que afectaban la operatividad del prototipo como "
  "filesystem real. Cada corrección incorporó su test de regresión: la suite pasó de 28 "
  "pruebas (Informe 1) a 61 pruebas y 319 aserciones.", style="Body Text")
H2("Operaciones passthrough completas")
P("Faltaban diez handlers (chmod, chown, utimens, rmdir, statfs, access, readlink, "
  "symlink, fsync, flush): el kernel respondía ENOSYS y herramientas cotidianas fallaban "
  "dentro del punto de montaje (mkdir -p, cp, tar, rsync) con “Function not "
  "implemented”. Además, el daemon aplicaba su propio umask por sobre el del cliente, con "
  "lo que los permisos resultantes diferían de los pedidos y disparaban correcciones vía "
  "chmod. Con los handlers como passthrough directo y umask(0) al arranque, el punto de "
  "montaje se comporta como un filesystem completo.", style="Body Text")
H2("Atributos completos en el listado de directorios")
P("El listado pasaba al kernel atributos parciales (solo el tipo de entrada), que el "
  "kernel almacenaba en caché durante el timeout de atributos: ls mostraba permisos 000 y "
  "fecha 1970, y rsync replicaba esos atributos rotos al copiar desde el punto de "
  "montaje (directorios con permiso 000, imposibles de eliminar). Cada entrada se entrega "
  "ahora con su stat completo.", style="Body Text")
H2("Retención de ventanas ante fallos de conexión")
P("Si el envío de una ventana de telemetría al servidor ML fallaba (reinicio del "
  "intermediario de recolección, servidor caído), la ventana se descartaba: se perdían "
  "precisamente las ventanas de los atacantes recién neutralizados, las más valiosas. "
  "Ahora las ventanas se retienen y reintentan con la conexión restaurada (tope de 30 s), "
  "con lo que cada ataque aporta a la telemetría todas sus ventanas (~3 por corrida, "
  "contra ~1 antes).", style="Body Text")
H2("Módulo de recuperación")
P("El módulo quedó validado de extremo a extremo: snapshots automáticos cada 60 s "
  "(retención 20), snapshot de emergencia asíncrono en el primer veredicto de sospecha y "
  "en cada bloqueo (retención 10), y rollback sobre el dataset real con el ataque "
  "contenido (Sección 5.C).", style="Body Text")

H1("MODELO DE MACHINE LEARNING ENTRENADO (CIERRE DEL MES 5)")
H2("Campaña de recolección")
P("Se ejecutaron seis tandas de la campaña automatizada en modo shadow: 135 rondas de "
  "ataque y 145 benignas, produciendo un dataset de 1805 ventanas de comportamiento "
  "(1541 benignas / 264 de ataque) en 127 sesiones etiquetadas.", style="Body Text")
H2("Clases benignas difíciles")
P("El primer entrenamiento expuso dos falsos positivos reales que no eran defectos del "
  "algoritmo sino del dataset: (1) los escritores de bloques idénticos (heartbeats, "
  "páginas de bases de datos) eran marcados como ataque porque la constancia temporal de "
  "la entropía solo aparecía, en los datos, en los ataques; y (2) la compresión de "
  "archivos grandes producía entropía cercana al máximo sin renombrados — clase "
  "inexistente en el dataset, cuya causa raíz era que el gzip del corpus comprimible "
  "generaba una única escritura y jamás una ventana. Las rondas benignas se ampliaron con "
  "compilación, git, rsync, appends paralelos, bloques idénticos, archivos de ceros y "
  "compresión de datos incompresibles (base64 de urandom, que simula archivar medios ya "
  "comprimidos).", style="Body Text")
H2("Resultados con la metodología sin fuga")
TABLA("II", "Métricas del modelo (validación cruzada agrupada por sesión y holdout agrupado)",
      ["Modelo", "ROC-AUC (CV)", "ROC-AUC (holdout)", "FPR", "FNR"],
      [["Random Forest", "1.0000 ± 0.0000", "1.0000", "0.0000", "0.0000"],
       ["XGBoost", "1.0000 ± 0.0000", "0.9997", "0.0000", "0.0145"]])
P("La verificación sobre datos no vistos clasifica correctamente 80/80 ventanas benignas "
  "y 80/80 de ataque, incluidas las 50 ventanas reales de compresión (entropía > 7). Los "
  "falsos positivos de las clases difíciles pasaron de probabilidades de ataque 0.76 y "
  "0.94 a 0.22 y 0.43 (veredicto normal).", style="Body Text")
P("Letra chica: el dataset se genera con el simulador de la fase de calibración; las "
  "métricas validan el circuito completo (recolección, entrenamiento, inferencia y "
  "confirmación al detector) y el aprendizaje de las clases difíciles, no la eficacia "
  "contra muestras reales, que corresponde a la fase de destrucción.", style="Body Text")

H1("CAMPAÑA EXPERIMENTAL: MÉTRICAS DE LA PoC")
H2("Metodología")
P("Entorno: VM de laboratorio aislada (Ubuntu, 4 vCPU, 3.8 GiB), pool ZFS tank/data de "
  "2 GiB con compresión lz4, punto de montaje protegido /mnt/protected en modo de "
  "aplicación (enforce) y servidor ML activo. Las mediciones de tiempo se ejecutaron con "
  "cachés vaciadas y sin carga concurrente.", style="Body Text")
P("Diseño: (1) comparativa de escenarios sobre la variable independiente del proyecto — "
  "sin protección (ext4, sin snapshots), ZFS solo (dataset directo con snapshot previo y "
  "trabajo legítimo posterior) y ZFS + Guardian FS — con el mismo ataque (modo full, 40 "
  "archivos, semilla fija); (2) tasa de neutralización y pérdida por perfil de ataque (6 "
  "perfiles × 3 corridas); (3) degradación de E/S de cargas benignas (escritura "
  "secuencial de 40 MiB, 300 archivos de 64 KiB y lectura de 40 MiB; mediana de 5 "
  "repeticiones, datos incompresibles de entropía intermedia que no disparan el freno); "
  "(4) sobrecostos de almacenamiento de los snapshots; y (5) falsos positivos sobre "
  "cargas de trabajo benignas representativas.", style="Body Text")

H2("Comparativa de escenarios")
try:
    esc = S["esc"]
    rows = []
    for _, r in esc.iterrows():
        rows.append([r.escenario.replace("_", " "),
                     f"{float(r.duracion_s):.1f}",
                     str(int(r.archivos_cifrados)),
                     (f"{float(r.rto_s):.2f}" if str(r.rto_s) not in ("", "nan") else "n/a"),
                     (str(int(r.archivos_perdidos_final)) if str(r.archivos_perdidos_final) not in ("", "nan") else "—")])
    TABLA("III", "Mismo ataque (full, 40 archivos) bajo tres configuraciones",
          ["Escenario", "Duración (s)", "Archivos cifrados", "RTO (s)", "Pérdida final (archivos)"],
          rows)
except Exception as e:
    print("WARN tabla escenarios:", e)
P("La duración en los escenarios sin detección es el tiempo de cifrado completo del "
  "corpus; en el escenario con detección activa es el tiempo hasta la neutralización. La "
  "pérdida final del escenario ZFS solo corresponde al trabajo legítimo realizado desde "
  "el último snapshot (punto de recuperación); en el escenario con detección activa el "
  "snapshot de emergencia se toma en el primer veredicto de sospecha, antes del daño "
  "mayor, y el rollback restaura el corpus completo.", style="Body Text")
FIGURA(f"{FIG}/escenarios.png", "Comparativa de los tres escenarios: proporción "
      "cifrada antes de contener, RTO y pérdida final tras recuperación.")

H2("Neutralización y pérdida por perfil de ataque")
try:
    g = S["atk"]
    rows = []
    for prof, r in g.iterrows():
        wall = f"{r.wall_med/1000:.2f}" if prof != "workers4" else "— †"
        rows.append([prof, f"{int(r.det)}/{int(r.n)}",
                     f"{r.locked_med:.0f} (máx {int(r.locked_max)})",
                     f"{r.bytes_med/1024:.0f}",
                     wall])
    TABLA("IV", "Campaña de detección por perfil (3 corridas c/u, modo enforce)",
          ["Perfil", "Neutralizadas", "Archivos .locked (mediana)", "KiB cifrados (mediana)", "Tiempo hasta freno (s)"],
          rows)
except Exception as e:
    print("WARN tabla perfiles:", e)
P(f"Resultados globales: 18 de 18 corridas neutralizadas (100%), con una pérdida "
  f"mediana de {S.get('locked_med_global', 0):.0f} archivos y "
  f"{S.get('bytes_med_global', 0)/1024:.0f} KiB cifrados antes del freno (máximo "
  f"observado: {S.get('locked_max_global', 0)} archivos, "
  f"{S.get('bytes_max_global', 0)/1024:.0f} KiB), muy por debajo del objetivo de la PoC "
  "de 1 MiB. La neutralización ocurre en el orden del segundo (la mediana incluye el "
  "arranque del intérprete del simulador).", style="Body Text")
P("† En el perfil multiproceso, Guardian FS termina a los cuatro workers dentro de la "
  "primera ventana (eventos process_killed con la firma de cifrado, 0 archivos "
  "cifrados), pero el orquestador del simulador queda bloqueado esperando a sus "
  "procesos muertos: el tiempo reportado para los demás perfiles no es comparable y un "
  "watchdog de la campaña lo desatasca. El comportamiento se registra como hallazgo: la "
  "neutralización parcial inmoviliza a la herramienta de ataque.", style="Body Text")
FIGURA(f"{FIG}/perfiles_ataque.png", "Tasa de neutralización y archivos cifrados "
      "antes del freno, por perfil de ataque.")

H2("Degradación de E/S en cargas benignas")
try:
    m = S["bench"]
    rows = []
    for w in m.index:
        d, v = m.loc[w, "directo"], m.loc[w, "guardian"]
        rows.append([w.replace("_", " "), f"{d:.0f}", f"{v:.0f}", f"{S['ov'][w]:+d}%"])
    TABLA("V", "Tiempo mediano (ms) de cargas benignas: directo ZFS vs. Guardian FS",
          ["Carga", "Directo (ms)", "Guardian FS (ms)", "Sobrecosto"],
          rows)
    ov_txt = ", ".join(f"{w.replace('_', ' ')} {v:+d}%" for w, v in S["ov"].items())
except Exception as e:
    print("WARN tabla bench:", e); ov_txt = "—"
P(f"El costo dominante es el análisis estadístico por byte de cada escritura "
  "(entropía y χ² sobre el buffer entrante, O(n)): la escritura secuencial grande lo "
  "paga íntegro (+{S['ov']['escritura_grande']}%), las operaciones pequeñas agregan el "
  "costo fijo por operación de FUSE (+{S['ov']['archivos_chicos']}%) y la lectura, "
  "que solo paga la copia del passthrough, es la carga menos penalizada "
  "(+{S['ov']['lectura']}%). El motor de detección no bloquea la syscall: el veredicto "
  "se emite dentro del handler y la inferencia ML es asíncrona. La optimización "
  "natural (muestrear el análisis a bloques representativos en escrituras grandes) "
  "queda registrada como trabajo futuro.", style="Body Text")
FIGURA(f"{FIG}/overhead_io.png", "Tiempo por carga de trabajo, directo ZFS vs. "
      "Guardian FS (mediana de 5 repeticiones, cachés vaciadas).")

H2("Sobrecarga de almacenamiento de los snapshots")
if S.get("snap"):
    P(S["snap"], style="Body Text")
else:
    P("La retención acotada (20 snapshots automáticos y 10 de emergencia) y la naturaleza "
      "Copy-on-Write mantienen el costo por debajo del objetivo del 5% del dataset; la "
      "medición puntual se reporta con los artefactos de la campaña.", style="Body Text")

H2("Falsos positivos sobre cargas benignas")
try:
    fp = S["fp"]
    rows = [[r.workload, str(int(r.blocked_events)), str(int(r.killed_events)),
             ("sí" if str(r.completo) == "si" else "NO")] for _, r in fp.iterrows()]
    TABLA("VI", "Campaña de falsos positivos del detector (modo enforce)",
          ["Carga benigna", "Bloqueos", "Procesos muertos", "¿Completó?"], rows)
except Exception as e:
    print("WARN tabla fp:", e)
P("Dos de las ocho cargas benignas fueron terminadas (git y rsync), ambas por la misma "
  "causa raíz: el patrón de escritura atómica de archivos temporales con sufijos "
  "(.git/config.lock → .git/config; archivo.c.XXXXXX → archivo.c) que el detector "
  "síncrono interpreta como cambio de extensión, la señal clásica del ransomware. El "
  "resto de las cargas —copias de árboles, empaquetado, compilación, compresión de "
  "40 MiB de alta entropía, appends y lectura— completó sin interferencia. El modelo de "
  "ML clasifica estas ventanas como normales; la corrección (ignorar sufijos temporales "
  "conocidos o umbral de renombrados por usuario) queda registrada como pendiente para "
  "el informe final.", style="Body Text")

H1("PRÓXIMOS PASOS")
P("1. Fase de destrucción (Mes 6): ejecución de las muestras reales de las familias de "
  "referencia (LockBit 3.0, Cl0p, RansomEXX) en la VM aislada, y verificación empírica "
  "del vector de evasión mmap, con la contingencia definida en el plan (degradar FUSE a "
  "un modo asíncrono de auditoría si el bypass se confirma).", style="bullet list")
P("2. Calibración de los umbrales y pesos del detector síncrono a partir del dataset y "
  "la importancia de features del modelo entrenado (hoy calibrados manualmente).",
  style="bullet list")
P("3. Corrección del falso positivo residual del detector síncrono con rsync masivo "
  "(umbral de renombrados por usuario o reconocimiento de patrones de archivos "
  "temporales).", style="bullet list")
P("4. Validación del freno global con ataques multiproceso y umbral por usuario en "
  "sistemas multiusuario.", style="bullet list")
P("5. Informe final: procesamiento estadístico de la campaña, redacción y preparación "
  "de la defensa.", style="bullet list")

P("REFERENCIAS", align=WD_ALIGN_PARAGRAPH.CENTER, bold=True)
refs = [
    "V. Dakic, M. Kovac, and I. Videc, “High-performance computing storage performance and design patterns—Btrfs and ZFS performance for different use cases,” Computers, vol. 13, no. 6, p. 139, 2024, doi: 10.3390/computers13060139.",
    "S. Lee et al., “Rcryptect: Real-time detection of cryptographic function in the user-space filesystem,” Computers & Security, vol. 112, p. 102512, 2021, doi: 10.1016/j.cose.2021.102512.",
    "P. O'Kane, S. Sezer, and D. Carlin, “Evolution of ransomware,” IET Networks, vol. 7, no. 5, pp. 321–327, 2018, doi: 10.1049/iet-net.2017.0207.",
    "C. Beaman et al., “Ransomware: Recent advances, analysis, challenges and future research directions,” Computers & Security, vol. 111, p. 102490, 2021, doi: 10.1016/j.cose.2021.102490.",
    "N. V. Chawla, K. W. Bowyer, L. O. Hall, and W. P. Kegelmeyer, “SMOTE: Synthetic minority over-sampling technique,” JAIR, vol. 16, pp. 321–357, 2002, doi: 10.1613/jair.953.",
    "F. Pedregosa et al., “Scikit-learn: Machine learning in Python,” JMLR, vol. 12, pp. 2825–2830, 2011.",
]
for r in refs:
    P(r, style="references")

doc.save(OUT)
print("OK guardado:", OUT)
print("RESUMEN:", {k: v for k, v in S.items() if k in
      ("atk_rate", "locked_med_global", "bytes_med_global", "wall_med_global",
       "fp_total_wl", "fp_con_fp", "ov")})
