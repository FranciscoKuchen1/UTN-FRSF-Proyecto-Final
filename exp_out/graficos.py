#!/usr/bin/env python3
"""Graficos para el Informe de Avance 3 a partir de los CSV de exp_out/.
Genera PNG en exp_out/fig/ listos para insertar en el .docx."""
import os
import pandas as pd
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

OUT = "exp_out/fig"
os.makedirs(OUT, exist_ok=True)
plt.rcParams.update({
    "font.family": "serif", "font.size": 9,
    "figure.dpi": 300, "savefig.bbox": "tight",
})

# ── Fig 1: overhead de E/S por workload (directo vs guardian) ──
def fig_overhead():
    df = pd.read_csv("exp_out/bench_results.csv")
    g = df.groupby(["workload", "ruta"]).ms.median().unstack()
    order = [w for w in ["escritura_grande", "archivos_chicos", "lectura"] if w in g.index]
    g = g.reindex(order)
    ax = g.plot.bar(rot=15, width=0.55,
                    color=["#4472c4", "#c00000"],
                    edgecolor="black", linewidth=0.4)
    ax.set_ylabel("tiempo mediano (ms)")
    ax.set_xlabel("")
    ax.legend(title="", frameon=False)
    for c in ax.containers:
        ax.bar_label(c, fmt="%.0f", fontsize=7, padding=1)
    ov = ((g["guardian"] / g["directo"] - 1) * 100).round(0)
    ax.set_title("Tiempo por workload — directo ZFS vs Guardian FS (mediana de 5 reps)", fontsize=9)
    fig = ax.get_figure()
    fig.tight_layout()
    fig.savefig(f"{OUT}/overhead_io.png")
    plt.close(fig)
    print("overhead %:", dict(ov.astype(int)))

# ── Fig 2: pérdida de datos por perfil (archivos cifrados antes del freno) ──
def fig_perfiles():
    df = pd.read_csv("exp_out/attack_results.csv")
    g = df.groupby("perfil").agg(
        detectados=("killed_events", lambda s: (s > 0).sum()),
        locked_med=("locked_files", "median"),
        locked_max=("locked_files", "max"),
        wall_med=("wall_ms", "median"),
        n=("rep", "count"),
    )
    total = g["n"].iloc[0]
    g["tasa"] = (g["detectados"] / total * 100).round(0).astype(int)
    fig, axes = plt.subplots(1, 2, figsize=(7.0, 2.6))
    ax = axes[0]
    g["tasa"].plot.bar(ax=ax, color="#548235", edgecolor="black", linewidth=0.4)
    ax.set_ylim(0, 110); ax.set_ylabel("% corridas detectadas")
    ax.bar_label(ax.containers[0], fmt="%d%%", fontsize=7)
    ax.set_title("Tasa de neutralización (3 corridas c/perfil)", fontsize=9)
    ax = axes[1]
    g["locked_med"].plot.bar(ax=ax, color="#c00000",
                             edgecolor="black", linewidth=0.4)
    ax.set_ylabel("archivos .locked (mediana)")
    labels = [f"{m:.0f}\n(máx {x})" for m, x in zip(g.locked_med, g.locked_max)]
    ax.bar_label(ax.containers[0], labels=labels, fontsize=6)
    ax.set_title("Pérdida: archivos cifrados antes del freno", fontsize=9)
    for a in axes: a.set_xlabel(""); a.tick_params(axis="x", rotation=25)
    fig.tight_layout()
    fig.savefig(f"{OUT}/perfiles_ataque.png")
    plt.close(fig)
    print(g[["tasa", "locked_med", "locked_max", "wall_med"]])

# ── Fig 3: comparativa de escenarios (sin prot / ZFS / ZFS+Guardian) ──
def fig_escenarios():
    df = pd.read_csv("exp_out/escenarios.csv")
    TOTAL = 40
    df["pct_cifrados"] = (df.archivos_cifrados / TOTAL * 100)
    df["pct_perdida_final"] = (df.archivos_perdidos_final / TOTAL * 100)
    df["escenario"] = df.escenario.str.replace("_", "\n", regex=False)
    fig, axes = plt.subplots(1, 3, figsize=(7.0, 2.4))
    colors = ["#7f7f7f", "#4472c4", "#548235"]
    esc = df.escenario
    ax = axes[0]
    ax.bar(esc, df.pct_cifrados, color=colors, edgecolor="black", linewidth=0.4)
    ax.set_ylabel("% del corpus cifrado\nantes de contener")
    ax.bar_label(ax.containers[0], fmt="%.0f%%", fontsize=7)
    ax = axes[1]
    rto = [float(v) if str(v) not in ("", "nan") else 0 for v in df.rto_s]
    ax.bar(esc, rto, color=colors, edgecolor="black", linewidth=0.4)
    ax.set_ylabel("RTO rollback (s)")
    ax.bar_label(ax.containers[0], fmt="%.2f", fontsize=7)
    ax = axes[2]
    ax.bar(esc, df.pct_perdida_final, color=colors, edgecolor="black", linewidth=0.4)
    ax.set_ylabel("% pérdida neta final\ntras recuperación")
    ax.bar_label(ax.containers[0], fmt="%.1f%%", fontsize=7)
    for a in axes:
        a.set_xlabel(""); a.tick_params(axis="x", labelsize=7)
    fig.suptitle("Mismo ataque (full, 40 archivos) bajo tres configuraciones", fontsize=9, y=1.03)
    fig.tight_layout()
    fig.savefig(f"{OUT}/escenarios.png")
    plt.close(fig)

if __name__ == "__main__":
    for name, fn in [("overhead", fig_overhead), ("perfiles", fig_perfiles),
                     ("escenarios", fig_escenarios)]:
        try:
            fn()
            print(f"OK {name}")
        except Exception as e:
            print(f"SKIP {name}: {e}")
