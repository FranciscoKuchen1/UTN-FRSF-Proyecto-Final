#!/usr/bin/env python3
"""
Script de entrenamiento offline del modelo de detección.

Evalúa y entrena con la MISMA clase que sirve inferencia
(RansomwareDetector en ml_server.py): una sola implementación de
hiperparámetros — lo evaluado es lo desplegado.

Dataset (CSV, generado por scripts/ml_proxy.py vía collect_training_data.sh):
  14 features + label + session + timestamp + pid
  (CSVs viejos sin columna session: la sesión se deriva por gaps de timestamp)

Metodología (métricas honestas):
  - Sin SMOTE: los modelos usan class_weight/scale_pos_weight. SMOTE
    interpolaba features binarias/count (canary_accessed=0.37 no significa
    nada) y además sintetizaba muestras dentro de los folds de test.
  - Scaler DENTRO del Pipeline del CV (se ajusta solo con el fold de train;
    antes se escalaba todo el dataset antes del CV → leakage).
  - StratifiedGroupKFold por SESIÓN (ronda de recolección): las ventanas de
    una misma sesión no se reparten entre train y test (leakage temporal —
    antes el CV aleatorio mezclaba ventanas contiguas del mismo ataque).
  - Holdout también agrupado (GroupShuffleSplit) para el reporte.
"""

import sys
from pathlib import Path

import numpy as np
import pandas as pd

# Misma implementación que sirve inferencia (src/ml_server.py)
sys.path.insert(0, str(Path(__file__).resolve().parent))
from ml_server import RansomwareDetector, FeatureVector, MODEL_DIR  # noqa: E402

from sklearn.base import clone  # noqa: E402
from sklearn.pipeline import Pipeline  # noqa: E402
from sklearn.preprocessing import StandardScaler  # noqa: E402
from sklearn.model_selection import (  # noqa: E402
    StratifiedGroupKFold, GroupShuffleSplit, StratifiedKFold,
    cross_val_score, train_test_split,
)
from sklearn.metrics import classification_report, roc_auc_score  # noqa: E402

import matplotlib  # noqa: E402
matplotlib.use("Agg")   # headless (VM sin X)
import matplotlib.pyplot as plt  # noqa: E402

DATA_PATH     = Path("data/training_data.csv")
REPORTS_DIR   = Path("reports")
FEATURE_NAMES = FeatureVector.FEATURE_NAMES
SESSION_GAP_S = 60.0   # fallback: gap de timestamp que separa sesiones


def load_dataset(path: Path):
    df = pd.read_csv(path)

    missing = [c for c in FEATURE_NAMES + ["label"] if c not in df.columns]
    if missing:
        sys.exit(f"ERROR: faltan columnas en {path}: {missing}")

    counts = df["label"].value_counts().to_dict()
    print(f"Dataset: {len(df)} muestras — {counts}")
    if len(counts) < 2:
        sys.exit("ERROR: el dataset tiene una sola clase — "
                 "recolectar ambas (collect_training_data.sh)")

    groups = derive_groups(df)
    X = df[FEATURE_NAMES].values.astype(np.float32)
    y = df["label"].values.astype(int)
    return X, y, groups


def derive_groups(df: pd.DataFrame) -> np.ndarray:
    """Sesión de recolección por fila: columna session si existe,
    si no se deriva por gaps de timestamp (fallback)."""
    if "session" in df.columns and df["session"].notna().any():
        groups = df["session"].astype(str).values
        print(f"Sesiones (columna session): {len(set(groups))}")
        return groups

    if "timestamp" in df.columns:
        ts = pd.to_datetime(df["timestamp"], errors="coerce")
        if not ts.isna().all():
            # gap > SESSION_GAP_S → nueva sesión (NaN diff → False)
            gaps = ts.diff().dt.total_seconds() > SESSION_GAP_S
            groups = np.array([f"g{i}" for i in gaps.cumsum()])
            print(f"Sesiones derivadas por timestamp "
                  f"(gap > {SESSION_GAP_S:.0f}s): {len(set(groups))}")
            print("AVISO: CSVs sin columna session — usar ml_proxy.py --tag "
                  "para sesiones exactas")
            return groups

    print("AVISO: sin session ni timestamp usables — agrupando por fila "
          "(métricas posiblemente optimistas)")
    return np.array([f"row{i}" for i in range(len(df))])


def make_pipeline(estimator) -> Pipeline:
    """Scaler + modelo: el scaler se ajusta SOLO con el fold de train."""
    return Pipeline([("scaler", StandardScaler()), ("model", estimator)])


def evaluate(detector: RansomwareDetector, X, y, groups):
    """CV agrupada por sesión + holdout agrupado, por modelo."""
    n_groups = len(np.unique(groups))
    grouped = n_groups >= 2
    if not grouped:
        print("AVISO: sin sesiones distinguibles — CV sin agrupar "
              "(métricas posiblemente optimistas)")

    n_splits = min(5, n_groups) if grouped else 5

    for name, estimator in [("Random Forest", clone(detector.rf)),
                            ("XGBoost", clone(detector.xgb))]:
        pipe = make_pipeline(clone(estimator))

        try:
            if grouped:
                cv = StratifiedGroupKFold(n_splits=n_splits, shuffle=True,
                                          random_state=42)
                scores = cross_val_score(pipe, X, y, groups=groups, cv=cv,
                                         scoring="roc_auc", n_jobs=-1)
            else:
                cv = StratifiedKFold(n_splits=n_splits, shuffle=True,
                                     random_state=42)
                scores = cross_val_score(pipe, X, y, cv=cv,
                                         scoring="roc_auc", n_jobs=-1)
        except ValueError as e:
            print(f"\n{name} — CV ROC-AUC no computable ({e})")
            print("  (pocas sesiones por clase — recolectar más rondas)")
            scores = None

        mode = f"{n_splits} folds agrupados por sesión" if grouped \
               else f"{n_splits} folds sin agrupar"
        if scores is not None:
            print(f"\n{name} — CV ({mode}):")
            print(f"  ROC-AUC: {np.mean(scores):.4f} ± {np.std(scores):.4f}")

        # Holdout agrupado por sesión
        if grouped:
            gss = GroupShuffleSplit(n_splits=1, test_size=0.25,
                                    random_state=42)
            tr, te = next(gss.split(X, y, groups=groups))
        else:
            tr, te = train_test_split(np.arange(len(y)), test_size=0.25,
                                      stratify=y, random_state=42)

        pipe.fit(X[tr], y[tr])
        y_pred = pipe.predict(X[te])
        y_prob = pipe.predict_proba(X[te])[:, 1]

        print(classification_report(y[te], y_pred,
                                    target_names=["Benigno", "Ransomware"],
                                    zero_division=0))
        if len(set(y[te])) == 2:
            print(f"  ROC-AUC holdout: {roc_auc_score(y[te], y_prob):.4f}")
        fpr = (y_pred[y[te] == 0] == 1).mean() if (y[te] == 0).any() else float("nan")
        fnr = (y_pred[y[te] == 1] == 0).mean() if (y[te] == 1).any() else float("nan")
        print(f"  FPR: {fpr:.4f} | FNR: {fnr:.4f}")


def feature_importance_plot(rf_model, feature_names):
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    importances = rf_model.feature_importances_
    idx = np.argsort(importances)[::-1]
    plt.figure(figsize=(10, 5))
    plt.bar(range(len(importances)), importances[idx], color="steelblue")
    plt.xticks(range(len(importances)),
               [feature_names[i] for i in idx], rotation=45, ha="right")
    plt.title("Importancia de características — Random Forest")
    plt.tight_layout()
    out = REPORTS_DIR / "feature_importance.png"
    plt.savefig(out, dpi=150)
    print(f"Guardado: {out}")


def main():
    if not DATA_PATH.exists():
        sys.exit(f"ERROR: dataset no encontrado: {DATA_PATH}\n"
                 "Generarlo con: ./scripts/collect_training_data.sh [rounds]")

    X, y, groups = load_dataset(DATA_PATH)

    # Hiperparámetros = los desplegados (misma clase que sirve inferencia)
    detector = RansomwareDetector(MODEL_DIR)

    print("\n=== Evaluación (CV agrupada por sesión, sin SMOTE, "
          "scaler por fold) ===")
    evaluate(detector, X, y, groups)

    # Entrenamiento final: ajusta scaler+rf+iso_forest+xgb y guarda todo
    # en MODEL_DIR (los 4 artefactos que ml_server.py carga)
    print("\n=== Entrenamiento final (todo el dataset) ===")
    try:
        detector.train(X, y)
    except PermissionError:
        sys.exit("ERROR: sin permisos para escribir en "
                 f"{MODEL_DIR} — correr primero: "
                 "sudo mkdir -p /var/lib/guardian/models (ver README)")

    feature_importance_plot(detector.rf, FEATURE_NAMES)
    print(f"\nModelos guardados en {MODEL_DIR}")
    print("Levantar el server: python3 src/ml_server.py")


if __name__ == "__main__":
    main()
