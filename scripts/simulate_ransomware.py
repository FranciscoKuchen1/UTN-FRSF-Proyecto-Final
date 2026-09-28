#!/usr/bin/env python3
"""
Simulador de ransomware para pruebas de Guardian FS.

Genera patrones de E/S maliciosos (escrituras de alta entropía,
cambio de extensiones, acceso a canaries) sin usar malware real.

Los perfiles de comportamiento están calibrados a partir del comportamiento
documentado de familias reales (LockBit, Cl0p, RansomEXX):
- cifrado parcial/intermitente (solo los primeros N% de cada archivo)
- workers paralelos (PIDs propios → diluyen el scoring per-PID del detector)
- tamaños de archivo variados, writes en chunks, jitter en pausas, skips

Usage:
    # Ataque rápido — 100 archivos, sin pausa
    python3 scripts/simulate_ransomware.py --target-dir /mnt/protected

    # Ataque sigiloso — pocos archivos, con pausas
    python3 scripts/simulate_ransomware.py --target-dir /mnt/protected \
        --mode stealth --file-count 20 --pause-ms 200

    # Solo cifrar, sin renombrar (para probar detección por entropía pura)
    python3 scripts/simulate_ransomware.py --target-dir /mnt/protected \
        --no-rename --file-count 50

    # Ataque realista: 4 workers paralelos + cifrado parcial (estilo LockBit)
    python3 scripts/simulate_ransomware.py --target-dir /mnt/protected \
        --workers 4 --partial-encrypt 50 --realistic

    # Prueba de evasión por mmap (NO genera features — no usar para training)
    python3 scripts/simulate_ransomware.py --target-dir /mnt/protected --mmap
"""

import argparse
import math
import mmap
import multiprocessing
import os
import random
import sys
import time


# ── Nombres y extensiones plausibles ──
FAKE_FILES_SAFE = [
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
]

FAKE_FILES_CANARY = [
    "A_important_report.docx",      # empieza con "A_" — como los canaries
    "ZZ_backup_keys.txt",           # empieza con "ZZ_" — como los canaries
]

FAKE_FILES = FAKE_FILES_SAFE + FAKE_FILES_CANARY

TARGET_EXTENSIONS = [".locked", ".enc", ".crypt", ".ransom", ".encrypted"]
CANARY_PATTERNS   = [
    "A_important_report", "ZZ_backup_keys", ".hidden_canary",
    "family_photos", "resume_final"
]

CHUNK_SIZE = 256 * 1024   # writes de ~256 KB, como cifrado con buffer


def high_entropy_data(size: int) -> bytes:
    """Genera bytes pseudoaleatorios que simulan datos cifrados (H ≈ 8.0)."""
    return os.urandom(size)


def is_canary_like(filename: str) -> bool:
    for pat in CANARY_PATTERNS:
        if pat in filename:
            return True
    return False


def realistic_file_size(rng: random.Random) -> int:
    """Log-uniform entre 16 KB y 8 MB (mezcla documentos/fotos/dumps)."""
    lo = math.log(16 * 1024)
    hi = math.log(8 * 1024 * 1024)
    return int(math.exp(rng.uniform(lo, hi)))


def deploy_files(target_dir: str, count: int, avoid_canary: bool = False,
                 realistic: bool = False,
                 rng: random.Random = None) -> list:
    """Crea archivos de prueba con contenido plausible en target_dir."""
    if rng is None:
        rng = random
    created = []
    os.makedirs(target_dir, exist_ok=True)

    # Seleccionar qué archivos usar según si queremos evitar canaries
    files_to_use = FAKE_FILES_SAFE if avoid_canary else FAKE_FILES

    for i in range(count):
        name = files_to_use[i % len(files_to_use)]
        # Evitar colisiones de nombres
        base, ext = os.path.splitext(name)
        fname = f"{base}_{i}{ext}"
        fpath = os.path.join(target_dir, fname)

        # Contenido de baja entropía (texto normal)
        if realistic:
            # Tamaños variados como un filesystem real de usuario
            size = realistic_file_size(rng)
            line = f"Confidential document — {base} — revision {i}\n"
            content = (line * (size // len(line) + 1))[:size]
        else:
            content = f"Confidential document — {base} — revision {i}\n" * 40

        with open(fpath, "w") as f:
            f.write(content)
        created.append(fpath)

    print(f"[+] Deployed {len(created)} test files in {target_dir}"
          + (" (realistic sizes)" if realistic else ""))
    return created


def attack_worker(job):
    """
    Ataca un subset de archivos. Corre en su propio proceso → PID propio en
    FUSE → diluye el scoring per-PID del detector (evasión real de familias
    multi-proceso). Devuelve stats y las rutas finales (post-rename).

    job: (worker_id, files, ext, mode, pause_ms, rename, partial_pct,
          realistic, use_mmap, rng_seed)
    """
    (worker_id, files, ext, mode, pause_ms, rename,
     partial_pct, realistic, use_mmap, rng_seed) = job

    rng = random.Random(rng_seed)
    stats = {"worker": worker_id, "files": 0, "bytes": 0,
             "reads": 0, "final_paths": []}

    for fpath in files:
        # Ransomware real saltea ~5% de archivos (ilegibles/permisos)
        if realistic and rng.random() < 0.05:
            stats["final_paths"].append(fpath)
            continue

        # Modo sigiloso: a veces solo leer sin cifrar (read→write ratio)
        if mode == "stealth" and rng.random() < 0.33:
            try:
                with open(fpath, "rb") as f:
                    _ = f.read()
                stats["reads"] += 1
            except OSError:
                pass
            pause = pause_ms * 3 if pause_ms else 50
            time.sleep(pause / 1000.0)
            stats["final_paths"].append(fpath)
            continue

        try:
            # ── Fase 1: Leer + Escribir (cifrado simulado) ──
            with open(fpath, "rb") as f:
                original = f.read()

            # Cifrado parcial/intermitente (LockBit): solo los primeros
            # partial_pct% del archivo; el resto queda plano en disco.
            enc_len = max(1, (len(original) * partial_pct) // 100)
            encrypted = high_entropy_data(enc_len)

            if use_mmap:
                # Evasión: mmap no pasa por write() → el detector no ve
                # entropía (para probar el bypass, no para training)
                with open(fpath, "r+b") as f:
                    mm = mmap.mmap(f.fileno(), enc_len)
                    mm[:] = encrypted
                    mm.flush()
                    mm.close()
            else:
                with open(fpath, "r+b") as f:
                    f.seek(0)
                    pos = 0
                    while pos < enc_len:
                        piece = encrypted[pos:pos + CHUNK_SIZE]
                        f.write(piece)
                        pos += len(piece)
                        if realistic and rng.random() < 0.10:
                            time.sleep(rng.uniform(0.001, 0.012))

            stats["files"] += 1
            stats["bytes"] += enc_len

            # ── Fase 2: Renombrar (cambio de extensión) ──
            if rename:
                new_path = fpath + ext
                os.rename(fpath, new_path)
                stats["final_paths"].append(new_path)
            else:
                stats["final_paths"].append(fpath)
        except OSError:
            stats["final_paths"].append(fpath)
            continue

        if pause_ms:
            jitter = rng.uniform(0.5, 1.5) if realistic else 1.0
            time.sleep(pause_ms * jitter / 1000.0)

    return stats


def simulate_ransomware(
    target_dir: str,
    file_count: int = 100,
    mode: str = "full",
    pause_ms: int = 0,
    rename: bool = True,
    canary_hunt: bool = False,
    cleanup: bool = True,
    avoid_canary: bool = False,
    workers: int = 1,
    partial_encrypt: int = 100,
    realistic: bool = False,
    use_mmap: bool = False,
    seed: int = None,
):
    """
    Simula el comportamiento de ransomware sobre un directorio.

    Modos:
      full    — cifra + renombra (ataque típico completo)
      fast    — muchas escrituras rápidas, sin pausas
      stealth — bajo volumen, pausas largas, mezclado
    """

    rng = random.Random(seed)

    ext = rng.choice(TARGET_EXTENSIONS)
    print(f"[*] Mode: {mode} | Files: {file_count} | Rename: {rename} | "
          f"Extension: {ext} | Pause: {pause_ms}ms")
    print(f"[*] Workers: {workers} | Partial encrypt: {partial_encrypt}% | "
          f"Realistic: {realistic} | mmap: {use_mmap}"
          + (f" | Seed: {seed}" if seed is not None else ""))
    if avoid_canary:
        print(f"[*] Avoiding canary-like filenames (for ML training data)")
    if use_mmap:
        print("[!] mmap: bypasses write() — the detector sees NO entropy "
             "(bypass testing only, generates no training features)")
    print(f"[*] Target: {target_dir}")

    files = deploy_files(target_dir, file_count, avoid_canary=avoid_canary,
                         realistic=realistic, rng=rng)

    # Repartir archivos entre workers (subsets disjuntos)
    if workers <= 1:
        jobs = [(0, files, ext, mode, pause_ms, rename,
                 partial_encrypt, realistic, use_mmap,
                 rng.randrange(1 << 30))]
        start = time.time()
        all_stats = [attack_worker(jobs[0])]
    else:
        chunks = [files[i::workers] for i in range(workers)]
        jobs = [(w, chunk, ext, mode, pause_ms, rename,
                 partial_encrypt, realistic, use_mmap,
                 rng.randrange(1 << 30))
                for w, chunk in enumerate(chunks)]
        start = time.time()
        # fork: cada worker es un proceso distinto → PID distinto en FUSE
        ctx = multiprocessing.get_context("fork")
        with ctx.Pool(workers) as pool:
            all_stats = pool.map(attack_worker, jobs)

    elapsed = time.time() - start
    total_files = sum(s["files"] for s in all_stats)
    total_bytes = sum(s["bytes"] for s in all_stats)
    for s in all_stats:
        if workers > 1:
            print(f"[+] Worker {s['worker']}: {s['files']} files, "
                  f"{s['bytes']} bytes encrypted")
    print(f"\n[+] Done. {total_files} files / {total_bytes} bytes encrypted "
          f"in {elapsed:.1f}s ({total_bytes/elapsed/1024:.0f} KB/s)")

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
    final_paths = [p for s in all_stats for p in s["final_paths"]]
    if cleanup:
        print("[*] Cleaning up test files...")
        for fpath in final_paths:
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
    parser.add_argument(
        "--avoid-canary", action="store_true",
        help="Avoid canary-like filenames (for ML training data generation)"
    )
    parser.add_argument(
        "--workers", type=int, default=1, metavar="N",
        help="Parallel worker processes, each with its own PID — dilutes "
             "per-PID scoring (realistic multi-process evasion) (default: 1)"
    )
    parser.add_argument(
        "--partial-encrypt", type=int, default=100, metavar="PCT",
        help="Encrypt only the first PCT%% of each file — intermittent "
             "encryption like LockBit (default: 100 = full file)"
    )
    parser.add_argument(
        "--realistic", action="store_true",
        help="Realistic profile: varied file sizes (16KB-8MB), chunked "
             "writes, pause jitter, ~5%% of files skipped"
    )
    parser.add_argument(
        "--mmap", action="store_true",
        help="Write via mmap instead of write() — bypasses FUSE write "
             "handler (bypass testing ONLY: no entropy features are generated)"
    )
    parser.add_argument(
        "--seed", type=int, default=None,
        help="RNG seed for reproducible runs"
    )

    args = parser.parse_args()

    if args.workers < 1:
        print("ERROR: --workers must be >= 1")
        sys.exit(1)
    if not 1 <= args.partial_encrypt <= 100:
        print("ERROR: --partial-encrypt must be in [1, 100]")
        sys.exit(1)
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
        avoid_canary=args.avoid_canary,
        workers=args.workers,
        partial_encrypt=args.partial_encrypt,
        realistic=args.realistic,
        use_mmap=args.mmap,
        seed=args.seed,
    )


if __name__ == "__main__":
    main()
