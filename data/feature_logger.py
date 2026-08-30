#!/usr/bin/env python3
"""
Feature Logger para Guardian FS.
Intercepta features del ML server y las guarda en CSV para entrenamiento.

Usage:
    # Como módulo
    from data.feature_logger import FeatureLogger
    logger = FeatureLogger(label=1)  # 1=ransomware, 0=benigno
    logger.log(features_dict)
    
    # Como script standalone (intercepta socket)
    python3 data/feature_logger.py --label 1 --output data/ransomware_samples.csv
"""

import csv
import json
import os
import socket
import threading
import time
from datetime import datetime
from pathlib import Path
from typing import Optional


class FeatureLogger:
    """Logger de features para dataset de entrenamiento."""
    
    FEATURE_NAMES = [
        "entropy_mean",
        "entropy_max", 
        "entropy_std",
        "entropy_autocorr",
        "write_rate",
        "bytes_written_rate",
        "rename_rate",
        "unlink_rate",
        "read_write_ratio",
        "chi2_stat",
        "ext_change_rate",
        "canary_accessed",
        "unique_dirs",
        "file_type_variety",
    ]
    
    def __init__(self, output_path: str = "data/training_data.csv", 
                 label: int = 0, append: bool = True):
        """
        Args:
            output_path: Ruta al archivo CSV de salida
            label: 0=benigno, 1=ransomware
            append: Si True, agrega al archivo existente; si False, lo sobrescribe
        """
        self.output_path = Path(output_path)
        self.label = label
        self.append = append
        self.lock = threading.Lock()
        
        # Crear directorio si no existe
        self.output_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Escribir header si es archivo nuevo
        if not self.output_path.exists() or not append:
            self._write_header()
    
    def _write_header(self):
        """Escribe el header del CSV."""
        with open(self.output_path, 'w', newline='') as f:
            writer = csv.writer(f)
            # Header: features + label + timestamp
            writer.writerow(self.FEATURE_NAMES + ['label', 'timestamp'])
    
    def log(self, features: dict, timestamp: Optional[str] = None):
        """
        Registra un vector de features en el CSV.
        
        Args:
            features: Diccionario con las 14 features
            timestamp: Timestamp opcional (default: ahora)
        """
        if timestamp is None:
            timestamp = datetime.now().isoformat()
        
        # Extraer features en orden
        row = [features.get(name, 0.0) for name in self.FEATURE_NAMES]
        row.append(self.label)
        row.append(timestamp)
        
        with self.lock:
            with open(self.output_path, 'a', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(row)
    
    def log_batch(self, features_list: list):
        """Registra múltiples vectores de features."""
        for features in features_list:
            self.log(features)


class FeatureInterceptor:
    """
    Intercepta features del ML server vía Unix Domain Socket.
    Se conecta al mismo socket que usa analyzer.c y loggea todo.
    """
    
    def __init__(self, socket_path: str = "/tmp/guardian_ml.sock",
                 output_path: str = "data/intercepted_features.csv",
                 label: int = 0):
        self.socket_path = socket_path
        self.label = label
        self.logger = FeatureLogger(output_path, label, append=True)
        self.running = False
        self.count = 0
    
    def start(self):
        """Inicia la interceptación de features."""
        if not os.path.exists(self.socket_path):
            print(f"[!] Socket no encontrado: {self.socket_path}")
            print("[!] Asegúrate de que ml_server.py esté corriendo")
            return
        
        self.running = True
        print(f"[*] Interceptando features desde: {self.socket_path}")
        print(f"[*] Guardando en: {self.logger.output_path}")
        print(f"[*] Etiqueta: {self.label} ({'ransomware' if self.label else 'benigno'})")
        print("[*] Presiona Ctrl+C para detener\n")
        
        try:
            while self.running:
                self._intercept_once()
                time.sleep(0.1)
        except KeyboardInterrupt:
            print(f"\n[+] Interceptación detenida. {self.count} features registradas.")
    
    def _intercept_once(self):
        """Intenta conectar y leer una feature del socket."""
        try:
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            sock.settimeout(1.0)
            sock.connect(self.socket_path)
            
            # Enviar un request dummy para obtener features
            # (En producción, esto debería leer los requests reales)
            # Por ahora, solo contamos conexiones
            
            sock.close()
        except socket.timeout:
            pass
        except Exception as e:
            # Socket no disponible, esperar
            pass


def main():
    """CLI para interceptar features."""
    import argparse
    
    parser = argparse.ArgumentParser(
        description="Intercepta features del ML server para entrenamiento"
    )
    parser.add_argument(
        "--label", type=int, choices=[0, 1], required=True,
        help="Etiqueta: 0=benigno, 1=ransomware"
    )
    parser.add_argument(
        "--output", default="data/training_data.csv",
        help="Archivo CSV de salida (default: data/training_data.csv)"
    )
    parser.add_argument(
        "--socket", default="/tmp/guardian_ml.sock",
        help="Ruta al socket del ML server"
    )
    
    args = parser.parse_args()
    
    interceptor = FeatureInterceptor(
        socket_path=args.socket,
        output_path=args.output,
        label=args.label
    )
    interceptor.start()


if __name__ == "__main__":
    main()
