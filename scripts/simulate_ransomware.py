#!/usr/bin/env python3
"""
Simulador de ransomware para pruebas de Guardian FS.

Genera patrones de E/S maliciosos (escrituras de alta entropía,
cambio de extensiones, acceso a canaries) sin usar malware real.

Usage:
    # Ataque rápido — 100 archivos, sin pausa
    python3 scripts/simulate_ransomware.py --target-dir /mnt/protected

    # Ataque sigiloso — pocos archivos, con pausas
    python3 scripts/simulate_ransomware.py --target-dir /mnt/protected \
        --mode stealth --file-count 20 --pause-ms 200

    # Solo cifrar, sin renombrar (para probar detección por entropía pura)
    python3 scripts/simulate_ransomware.py --target-dir /mnt/protected \
        --no-rename --file-count 50
"""

import argparse
import os
import random
import sys
import time


# ── Nombres y extensiones plausibles ──
FAKE_FILES = [
    "Q4_financial_report.xlsx",
    "client_contract_2025.docx",
    "employee_salaries_HR.pdf",
    "summer_vacation_photos.jpg",
    "server_config_backup.txt",
    "project_plan_milestones.docx",
    "tax_return_2024.pdf",
    "company_logo_branding.png",
    "database_dump_schema.sql",
    "meeting_notes_weekly.txt",
    "A_important_report.docx",      # empieza con "A_" — como los canaries
    "ZZ_backup_keys.txt",           # empieza con "ZZ_" — como los canaries
]

TARGET_EXTENSIONS = [".locked", ".enc", ".crypt", ".ransom", ".encrypted"]
CANARY_PATTERNS   = [
    "A_important_report", "ZZ_backup_keys", ".hidden_canary",
    "family_photos", "resume_final"
]


def high_entropy_data(size: int) -> bytes:
    """Genera bytes pseudoaleatorios que simulan datos cifrados (H ≈ 8.0)."""
    return os.urandom(size)


def is_canary_like(filename: str) -> bool:
    for pat in CANARY_PATTERNS:
        if pat in filename:
            return True
    return False


def deploy_files(target_dir: str, count: int) -> list:
    """Crea archivos de prueba con contenido plausible en target_dir."""
    created = []
    os.makedirs(target_dir, exist_ok=True)

    for i in range(count):
        name = FAKE_FILES[i % len(FAKE_FILES)]
        # Evitar colisiones de nombres
        base, ext = os.path.splitext(name)
        fname = f"{base}_{i}{ext}"
        fpath = os.path.join(target_dir, fname)

        # Contenido de baja entropía (texto normal)
        content = f"Confidential document — {base} — revision {i}\n" * 40
        with open(fpath, "w") as f:
            f.write(content)
        created.append(fpath)

    print(f"[+] Deployed {len(created)} test files in {target_dir}")
    return created


def simulate_ransomware(
    target_dir: str,
    file_count: int = 100,
    mode: str = "full",
    pause_ms: int = 0,
    rename: bool = True,
    canary_hunt: bool = False,
    cleanup: bool = True,
):
    """
    Simula el comportamiento de ransomware sobre un directorio.

    Modos:
      full    — cifra + renombra (ataque típico completo)
      fast    — muchas escrituras rápidas, sin pausas
      stealth — bajo volumen, pausas largas, mezclado
    """
    ext = random.choice(TARGET_EXTENSIONS)
    print(f"[*] Mode: {mode} | Files: {file_count} | "
          f"Rename: {rename} | Extension: {ext} | Pause: {pause_ms}ms")
    print(f"[*] Target: {target_dir}")

    files = deploy_files(target_dir, file_count)
    total_bytes = 0
    start = time.time()

    for i, fpath in enumerate(files):
        fsize = os.path.getsize(fpath)

        # ── Fase 1: Leer + Escribir (cifrado simulado) ──
        if mode == "stealth" and i % 3 == 0:
            # Modo sigiloso: a veces solo leer sin cifrar (read→write ratio)
            with open(fpath, "rb") as f:
                _ = f.read()
            pause = pause_ms * 3 if pause_ms else 50
            time.sleep(pause / 1000.0)
            continue

        # Leer contenido original
        with open(fpath, "rb") as f:
            original = f.read()

        # Escribir datos de alta entropía (simula cifrado)
        encrypted = high_entropy_data(len(original))
        with open(fpath, "wb") as f:
            f.write(encrypted)

        total_bytes += len(encrypted)

        # ── Fase 2: Renombrar (cambio de extensión) ──
        if rename:
            new_path = fpath + ext
            os.rename(fpath, new_path)
            files[i] = new_path  # actualizar para cleanup
            fpath = new_path

        # ── Progreso ──
        if (i + 1) % 10 == 0 or i == len(files) - 1:
            elapsed = time.time() - start
            rate = total_bytes / elapsed / 1024 if elapsed > 0 else 0
            print(f"    [{i+1}/{file_count}] {rate:.0f} KB/s — "
                  f"{total_bytes} bytes encrypted", end="\r")

        if pause_ms:
            time.sleep(pause_ms / 1000.0)

    elapsed = time.time() - start
    print(f"\n[+] Done. {total_bytes} bytes encrypted in {elapsed:.1f}s "
          f"({total_bytes/elapsed/1024:.0f} KB/s)")

    # ── Canary hunt ──
    if canary_hunt:
        print("[*] Hunting canary files...")
        for root, _, filenames in os.walk(target_dir):
            for fname in filenames:
                if is_canary_like(fname):
                    fpath = os.path.join(root, fname)
                    try:
                        # Intentar abrir (debería disparar detección)
                        with open(fpath, "rb") as f:
                            _ = f.read(64)
                        print(f"    [!] Accessed canary: {fname}")
                    except PermissionError:
                        print(f"    [+] BLOCKED by Guardian: {fname}")
                    except Exception as e:
                        print(f"    [?] {fname}: {e}")

    # ── Cleanup ──
    if cleanup:
        print("[*] Cleaning up test files...")
        for fpath in files:
            try:
                if os.path.exists(fpath):
                    os.remove(fpath)
            except Exception:
                pass
        print("[+] Cleanup done")


def main():
    parser = argparse.ArgumentParser(
        description="Guardian FS — Ransomware Behavior Simulator"
    )
    parser.add_argument(
        "--target-dir", required=True,
        help="Directory to attack (e.g., /mnt/protected)"
    )
    parser.add_argument(
        "--mode", choices=["full", "fast", "stealth"], default="full",
        help="Attack pattern: full (default), fast, stealth"
    )
    parser.add_argument(
        "--file-count", type=int, default=100,
        help="Number of files to create and encrypt (default: 100)"
    )
    parser.add_argument(
        "--pause-ms", type=int, default=0,
        help="Pause between file operations in ms (default: 0)"
    )
    parser.add_argument(
        "--no-rename", action="store_false", dest="rename",
        help="Encrypt without renaming (tests entropy-only detection)"
    )
    parser.add_argument(
        "--canary-hunt", action="store_true",
        help="Attempt to access canary-like files after encryption"
    )
    parser.add_argument(
        "--no-cleanup", action="store_false", dest="cleanup",
        help="Leave encrypted files for inspection"
    )

    args = parser.parse_args()

    if not os.path.isdir(args.target_dir):
        print(f"ERROR: Target directory does not exist: {args.target_dir}")
        sys.exit(1)

    simulate_ransomware(
        target_dir=args.target_dir,
        file_count=args.file_count,
        mode=args.mode,
        pause_ms=args.pause_ms,
        rename=args.rename,
        canary_hunt=args.canary_hunt,
        cleanup=args.cleanup,
    )


if __name__ == "__main__":
    main()
