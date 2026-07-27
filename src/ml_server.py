#!/usr/bin/env python3
"""
Servidor de inferencia ML para detección de ransomware.
Se comunica con el daemon FUSE via Unix Domain Socket (UDS).
Protocolo: JSON-lines bidireccional.
"""

import json
import socket
import os
import numpy as np
import joblib
import threading
from pathlib import Path

# ── Importar modelos ──────────────────────────────────────────────
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.preprocessing import StandardScaler
import xgboost as xgb
# Para LSTM (opcional, requiere PyTorch)
try:
    import torch
    import torch.nn as nn
    LSTM_AVAILABLE = True
except ImportError:
    LSTM_AVAILABLE = False

SOCKET_PATH = "/tmp/guardian_ml.sock"
MODEL_DIR   = Path("/var/lib/guardian/models")

class FeatureVector:
    """
    Vector de características extraídas de una ventana temporal (5s por PID).
    """
    FEATURE_NAMES = [
        "entropy_mean",       # H̄ — entropía media de escrituras
        "entropy_max",        # máximo de entropía en la ventana
        "entropy_std",        # desviación estándar de entropía
        "entropy_autocorr",   # autocorrelación de entropía entre ventanas
        "write_rate",         # escrituras por segundo
        "bytes_written_rate", # bytes/segundo escritos
        "rename_rate",        # renombrados por segundo
        "unlink_rate",        # eliminaciones por segundo
        "read_write_ratio",   # ratio bytes leídos / bytes escritos
        "chi2_stat",          # estadístico χ² (uniformidad de bytes)
        "ext_change_rate",    # tasa cambio de extensión
        "canary_accessed",    # booleano: ¿accedió a canary?
        "unique_dirs",        # directorios únicos accedidos
        "file_type_variety",  # variedad de extensiones escritas
    ]
    N_FEATURES = len(FEATURE_NAMES)

    @staticmethod
    def from_dict(d: dict) -> np.ndarray:
        return np.array([d.get(f, 0.0) for f in FeatureVector.FEATURE_NAMES],
                        dtype=np.float32)


class RansomwareDetector:
    def __init__(self, model_dir: Path):
        self.scaler = StandardScaler()
        self.rf     = RandomForestClassifier(
            n_estimators=200,
            max_depth=15,
            class_weight="balanced",
            random_state=42,
            n_jobs=-1,
        )
        self.iso_forest = IsolationForest(
            n_estimators=100,
            contamination=0.05,   # esperamos ~5% de datos anómalos
            random_state=42,
        )
        self.xgb = xgb.XGBClassifier(
            n_estimators=200,
            max_depth=8,
            scale_pos_weight=10,  # compensar desbalance de clases
            eval_metric="logloss",
            random_state=42,
        )
        self.lstm  = self._build_lstm() if LSTM_AVAILABLE else None
        self.trained = False
        self.model_dir = model_dir

        # Historial por PID para la LSTM (últimas 10 ventanas)
        self._pid_history: dict[int, list] = {}
        self._hist_lock = threading.Lock()

    def _build_lstm(self):
        """LSTM para series temporales de features por PID."""
        class LSTMDetector(nn.Module):
            def __init__(self, input_sz, hidden_sz=64, n_layers=2):
                super().__init__()
                self.lstm = nn.LSTM(input_sz, hidden_sz, n_layers,
                                    batch_first=True, dropout=0.3)
                self.fc   = nn.Linear(hidden_sz, 1)
                self.sig  = nn.Sigmoid()
            def forward(self, x):
                out, _ = self.lstm(x)
                return self.sig(self.fc(out[:, -1, :]))

        return LSTMDetector(FeatureVector.N_FEATURES)

    def train(self, X: np.ndarray, y: np.ndarray):
        """
        X: (n_samples, N_FEATURES)
        y: (n_samples,) — 0=benigno, 1=ransomware
        """
        X_scaled = self.scaler.fit_transform(X)

        # Random Forest (supervisado)
        self.rf.fit(X_scaled, y)

        # Isolation Forest (no supervisado — solo datos benignos)
        self.iso_forest.fit(X_scaled[y == 0])

        # XGBoost
        self.xgb.fit(X_scaled, y,
                     eval_set=[(X_scaled, y)],
                     verbose=False)

        # LSTM — requiere secuencias temporales (X_seq shape: n, seq_len, feat)
        # (entrenamiento separado, ver train_model.py)

        self.trained = True
        self.save(self.model_dir)

    def predict(self, features: dict, pid: int) -> dict:
        """
        Retorna:
          p_attack: float [0,1] — probabilidad de ataque
          verdict:  str — "normal" | "suspicious" | "attack"
          method:   str — modelo dominante en la decisión
          flags:    list[str] — razones específicas
        """
        x = FeatureVector.from_dict(features)
        flags = []

        if not self.trained:
            # Fallback a reglas estadísticas puras
            return self._rule_based(features, x, flags)

        x_sc = self.scaler.transform(x.reshape(1, -1))

        # Scores individuales
        p_rf    = self.rf.predict_proba(x_sc)[0][1]
        iso_sc  = self.iso_forest.score_samples(x_sc)[0]  # más negativo = más anómalo
        p_iso   = 1.0 / (1.0 + np.exp(iso_sc * 5))        # sigmoid sobre score
        p_xgb   = self.xgb.predict_proba(x_sc)[0][1]

        # LSTM sobre historial del PID
        p_lstm = 0.5
        if LSTM_AVAILABLE and self.lstm is not None:
            seq = self._get_sequence(pid, x)
            if seq is not None:
                with torch.no_grad():
                    t = torch.tensor(seq, dtype=torch.float32).unsqueeze(0)
                    p_lstm = float(self.lstm(t)[0][0])

        # Ensemble: voting ponderado
        weights = {"rf": 0.35, "iso": 0.20, "xgb": 0.30, "lstm": 0.15}
        p_attack = (weights["rf"]   * p_rf   +
                    weights["iso"]  * p_iso  +
                    weights["xgb"]  * p_xgb  +
                    weights["lstm"] * p_lstm)

        # Feature importance feedback para flags
        if features.get("canary_accessed", 0):
            flags.append("canary_accessed")
            p_attack = max(p_attack, 0.9)  # evidencia directa

        if features.get("entropy_mean", 0) > 7.2:
            flags.append("high_entropy")

        if features.get("rename_rate", 0) > 10:
            flags.append("high_rename_rate")

        if features.get("chi2_stat", 1e9) < 300:
            flags.append("uniform_byte_distribution")

        if p_attack >= 0.75:
            verdict = "attack"
        elif p_attack >= 0.50:
            verdict = "suspicious"
        else:
            verdict = "normal"

        return {
            "p_attack": float(p_attack),
            "verdict":  verdict,
            "scores": {
                "random_forest":   float(p_rf),
                "isolation_forest": float(p_iso),
                "xgboost":         float(p_xgb),
                "lstm":            float(p_lstm),
            },
            "flags": flags,
        }

    def _get_sequence(self, pid: int, x: np.ndarray):
        """Mantiene historial de las últimas 10 ventanas por PID."""
        SEQ_LEN = 10
        with self._hist_lock:
            hist = self._pid_history.setdefault(pid, [])
            hist.append(x.tolist())
            if len(hist) > SEQ_LEN:
                hist.pop(0)
            if len(hist) < 3:
                return None  # secuencia insuficiente
            # Padding con ceros si hay menos de SEQ_LEN
            pad = [[0.0] * FeatureVector.N_FEATURES] * (SEQ_LEN - len(hist))
            return pad + hist

    def _rule_based(self, features: dict, x: np.ndarray,
                    flags: list) -> dict:
        """Fallback de reglas cuando no hay modelo entrenado."""
        score = 0.0
        if features.get("entropy_mean", 0) > 7.0:
            score += 0.4; flags.append("high_entropy")
        if features.get("write_rate", 0) > 100:
            score += 0.2; flags.append("high_write_rate")
        if features.get("rename_rate", 0) > 10:
            score += 0.2; flags.append("high_rename_rate")
        if features.get("canary_accessed", 0):
            score += 0.5; flags.append("canary_accessed")
        if features.get("chi2_stat", 1e9) < 300:
            score += 0.15; flags.append("uniform_bytes")

        score = min(score, 1.0)
        return {
            "p_attack": score,
            "verdict": "attack" if score >= 0.75
                       else "suspicious" if score >= 0.5
                       else "normal",
            "flags": flags,
            "method": "rule_based_fallback",
        }

    def save(self, path: Path):
        path.mkdir(parents=True, exist_ok=True)
        joblib.dump(self.scaler, path / "scaler.pkl")
        joblib.dump(self.rf,     path / "rf.pkl")
        joblib.dump(self.iso_forest, path / "iso_forest.pkl")
        self.xgb.save_model(str(path / "xgb.json"))

    def load(self, path: Path):
        self.scaler     = joblib.load(path / "scaler.pkl")
        self.rf         = joblib.load(path / "rf.pkl")
        self.iso_forest = joblib.load(path / "iso_forest.pkl")
        self.xgb.load_model(str(path / "xgb.json"))
        self.trained = True


class MLServer:
    def __init__(self):
        self.detector = RansomwareDetector(MODEL_DIR)
        if (MODEL_DIR / "rf.pkl").exists():
            self.detector.load(MODEL_DIR)
            print("[ml_server] Modelos cargados desde disco")
        else:
            print("[ml_server] Sin modelos — modo reglas estadísticas")

    def handle_client(self, conn: socket.socket):
        with conn:
            buf = b""
            while True:
                chunk = conn.recv(4096)
                if not chunk:
                    break
                buf += chunk
                while b"\n" in buf:
                    line, buf = buf.split(b"\n", 1)
                    try:
                        req = json.loads(line)
                        resp = self.detector.predict(
                            req.get("features", {}),
                            req.get("pid", 0)
                        )
                        conn.sendall(json.dumps(resp).encode() + b"\n")
                    except Exception as e:
                        conn.sendall(json.dumps({"error": str(e)}).encode() + b"\n")

    def run(self):
        if os.path.exists(SOCKET_PATH):
            os.unlink(SOCKET_PATH)
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as srv:
            srv.bind(SOCKET_PATH)
            os.chmod(SOCKET_PATH, 0o600)
            srv.listen(10)
            print(f"[ml_server] Escuchando en {SOCKET_PATH}")
            while True:
                conn, _ = srv.accept()
                threading.Thread(target=self.handle_client,
                                 args=(conn,), daemon=True).start()

if __name__ == "__main__":
    MLServer().run()
