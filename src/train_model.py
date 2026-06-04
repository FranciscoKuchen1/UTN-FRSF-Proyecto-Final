#!/usr/bin/env python3
"""
Script de entrenamiento offline del modelo de detección.
Requiere dataset de features extraídas de ejecuciones etiquetadas.

Dataset format (CSV):
  entropy_mean, entropy_max, entropy_std, entropy_autocorr,
  write_rate, bytes_written_rate, rename_rate, unlink_rate,
  read_write_ratio, chi2_stat, ext_change_rate, canary_accessed,
  unique_dirs, file_type_variety, label (0=benigno, 1=ransomware)
"""

import pandas as pd
import numpy as np
from pathlib import Path
from sklearn.model_selection import StratifiedKFold, cross_val_score
from sklearn.metrics import (classification_report, roc_auc_score,
                              confusion_matrix, ConfusionMatrixDisplay)
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from imblearn.over_sampling import SMOTE
import xgboost as xgb
import matplotlib.pyplot as plt
import joblib

DATA_PATH  = Path("data/features_labeled.csv")
MODEL_DIR  = Path("/var/lib/guardian/models")

def load_and_balance(path: Path):
    df = pd.read_csv(path)
    print(f"Dataset: {len(df)} muestras — "
          f"{df['label'].value_counts().to_dict()}")

    X = df.drop("label", axis=1).values.astype(np.float32)
    y = df["label"].values.astype(int)

    # Balanceo con SMOTE (Synthetic Minority Over-sampling)
    sm = SMOTE(random_state=42, k_neighbors=5)
    X_bal, y_bal = sm.fit_resample(X, y)
    print(f"Tras SMOTE: {len(X_bal)} muestras")
    return X_bal, y_bal, df.drop("label", axis=1).columns.tolist()

def evaluate_model(model, X, y, name: str):
    """Evaluación con validación cruzada estratificada k=10."""
    skf = StratifiedKFold(n_splits=10, shuffle=True, random_state=42)
    scores = cross_val_score(model, X, y, cv=skf,
                             scoring="roc_auc", n_jobs=-1)
    print(f"\n{name}:")
    print(f"  ROC-AUC: {scores.mean():.4f} ± {scores.std():.4f}")

    # Entrenamiento final y métricas completas
    from sklearn.model_selection import train_test_split
    X_tr, X_te, y_tr, y_te = train_test_split(X, y, test_size=0.2,
                                               stratify=y, random_state=42)
    model.fit(X_tr, y_tr)
    y_pred = model.predict(X_te)

    print(classification_report(y_te, y_pred,
          target_names=["Benigno", "Ransomware"]))
    print(f"  FPR: {(y_pred[y_te==0]==1).mean():.4f} "
          f"| FNR: {(y_pred[y_te==1]==0).mean():.4f}")
    return model

def feature_importance_plot(rf_model, feature_names):
    importances = rf_model.feature_importances_
    idx = np.argsort(importances)[::-1]
    plt.figure(figsize=(10, 5))
    plt.bar(range(len(importances)),
            importances[idx], color="steelblue")
    plt.xticks(range(len(importances)),
               [feature_names[i] for i in idx], rotation=45, ha="right")
    plt.title("Importancia de características — Random Forest")
    plt.tight_layout()
    plt.savefig("reports/feature_importance.png", dpi=150)
    print("Guardado: reports/feature_importance.png")

def main():
    X, y, feat_names = load_and_balance(DATA_PATH)

    scaler = StandardScaler()
    X_sc   = scaler.fit_transform(X)

    rf = RandomForestClassifier(
        n_estimators=200, max_depth=15,
        class_weight="balanced", random_state=42, n_jobs=-1
    )
    xgb_model = xgb.XGBClassifier(
        n_estimators=200, max_depth=8,
        scale_pos_weight=10, random_state=42,
        eval_metric="logloss"
    )

    rf_trained  = evaluate_model(rf,        X_sc, y, "Random Forest")
    xgb_trained = evaluate_model(xgb_model, X_sc, y, "XGBoost")

    feature_importance_plot(rf_trained, feat_names)

    # Guardar modelos
    MODEL_DIR.mkdir(parents=True, exist_ok=True)
    joblib.dump(scaler,     MODEL_DIR / "scaler.pkl")
    joblib.dump(rf_trained, MODEL_DIR / "rf.pkl")
    xgb_trained.save_model(str(MODEL_DIR / "xgb.json"))

    print(f"\nModelos guardados en {MODEL_DIR}")

if __name__ == "__main__":
    main()
