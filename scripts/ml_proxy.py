#!/usr/bin/env python3
"""
ML Proxy para Guardian FS.
Se interpone entre analyzer.c y ml_server.py, loggeando todas las features.

Flujo:
  analyzer.c -> ML_PROXY (loggea) -> ml_server.py -> ML_PROXY -> analyzer.c

Usage:
    # 1. Detener ml_server.py si está corriendo
    # 2. Cambiar la ruta del socket en analyzer.c a /tmp/guardian_ml_proxy.sock
    #    (o usar este proxy con la misma ruta y cambiar la de ml_server)
    # 3. Correr:
    python3 scripts/ml_proxy.py --label 1 --backend-socket /tmp/guardian_ml.sock
    
    # 4. Correr el simulador
    python3 scripts/simulate_ransomware.py --target-dir /tmp/test_data
"""

import argparse
import csv
import json
import os
import socket
import select
import sys
import threading
import time
from datetime import datetime
from pathlib import Path


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


class FeatureCSVLogger:
    """Logger thread-safe que escribe features en CSV."""
    
    def __init__(self, output_path: str, label: int):
        self.output_path = Path(output_path)
        self.label = label
        self.lock = threading.Lock()
        self.count = 0
        
        self.output_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Escribir header si es nuevo
        if not self.output_path.exists() or self.output_path.stat().st_size == 0:
            self._write_header()
    
    def _write_header(self):
        with open(self.output_path, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(FEATURE_NAMES + ['label', 'timestamp', 'pid'])
    
    def log_request(self, request: dict):
        """Loggea un request de features."""
        features = request.get("features", {})
        pid = request.get("pid", 0)
        timestamp = datetime.now().isoformat()
        
        row = [features.get(name, 0.0) for name in FEATURE_NAMES]
        row.append(self.label)
        row.append(timestamp)
        row.append(pid)
        
        with self.lock:
            with open(self.output_path, 'a', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(row)
            self.count += 1
            
            if self.count % 10 == 0:
                print(f"[proxy] {self.count} features loggeadas en {self.output_path}")


class MLProxy:
    """
    Proxy que se interpone entre analyzer.c y ml_server.py.
    Loggea todas las features que pasan.
    """
    
    def __init__(self, proxy_socket: str, backend_socket: str, 
                 output_path: str, label: int):
        self.proxy_socket_path = proxy_socket
        self.backend_socket_path = backend_socket
        self.logger = FeatureCSVLogger(output_path, label)
        self.running = False
    
    def start(self):
        """Inicia el proxy."""
        # Limpiar socket anterior
        if os.path.exists(self.proxy_socket_path):
            os.unlink(self.proxy_socket_path)
        
        # Verificar que el backend existe
        if not os.path.exists(self.backend_socket_path):
            print(f"[!] Backend socket no encontrado: {self.backend_socket_path}")
            print("[!] Asegúrate de que ml_server.py esté corriendo primero")
            sys.exit(1)
        
        self.running = True
        
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as server:
            server.bind(self.proxy_socket_path)
            os.chmod(self.proxy_socket_path, 0o600)
            server.listen(10)
            
            print(f"[proxy] Escuchando en: {self.proxy_socket_path}")
            print(f"[proxy] Backend: {self.backend_socket_path}")
            print(f"[proxy] Loggeando en: {self.logger.output_path}")
            print(f"[proxy] Etiqueta: {self.logger.label} "
                  f"({'ransomware' if self.logger.label else 'benigno'})")
            print("[proxy] Presiona Ctrl+C para detener\n")
            
            try:
                while self.running:
                    conn, _ = server.accept()
                    threading.Thread(
                        target=self._handle_client,
                        args=(conn,),
                        daemon=True
                    ).start()
            except KeyboardInterrupt:
                print(f"\n[+] Proxy detenido. {self.logger.count} features registradas.")
    
    def _handle_client(self, client_conn: socket.socket):
        """Maneja una conexión desde analyzer.c."""
        backend_conn = None
        
        try:
            # Conectar al backend (ml_server.py)
            backend_conn = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            backend_conn.connect(self.backend_socket_path)
            
            buf = b""
            
            while True:
                # Leer del cliente (analyzer.c)
                readable, _, _ = select.select([client_conn, backend_conn], [], [], 1.0)
                
                if client_conn in readable:
                    data = client_conn.recv(4096)
                    if not data:
                        break
                    
                    # Loggear cada request JSON completo
                    buf += data
                    while b"\n" in buf:
                        line, buf = buf.split(b"\n", 1)
                        try:
                            request = json.loads(line)
                            self.logger.log_request(request)
                        except json.JSONDecodeError:
                            pass
                    
                    # Forward al backend
                    backend_conn.sendall(data)
                
                if backend_conn in readable:
                    data = backend_conn.recv(4096)
                    if not data:
                        break
                    # Forward al cliente
                    client_conn.sendall(data)
        
        except Exception as e:
            print(f"[proxy] Error en conexión: {e}")
        finally:
            if client_conn:
                client_conn.close()
            if backend_conn:
                backend_conn.close()


def main():
    parser = argparse.ArgumentParser(
        description="ML Proxy - Intercepta y loggea features para entrenamiento"
    )
    parser.add_argument(
        "--label", type=int, choices=[0, 1], required=True,
        help="Etiqueta: 0=benigno, 1=ransomware"
    )
    parser.add_argument(
        "--output", default="data/training_data.csv",
        help="CSV de salida (default: data/training_data.csv)"
    )
    parser.add_argument(
        "--proxy-socket", default="/tmp/guardian_ml_proxy.sock",
        help="Socket donde escucha el proxy (analyzer.c se conecta acá)"
    )
    parser.add_argument(
        "--backend-socket", default="/tmp/guardian_ml.sock",
        help="Socket del ml_server.py (default: /tmp/guardian_ml.sock)"
    )
    
    args = parser.parse_args()
    
    proxy = MLProxy(
        proxy_socket=args.proxy_socket,
        backend_socket=args.backend_socket,
        output_path=args.output,
        label=args.label
    )
    proxy.start()


if __name__ == "__main__":
    main()
