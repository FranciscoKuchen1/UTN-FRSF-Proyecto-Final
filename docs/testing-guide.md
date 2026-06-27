# Guardian FS — Testing & Operations Guide

**Project**: UTN FRSF Proyecto Final 2026  
**Scope**: Unit tests, build verification, and operational scripts for the Guardian FS ransomware detection system.

---

## Table of Contents

1. [Unit Test Suite](#unit-test-suite)
   - [entropy — Shannon & Chi-Square](#1-entropy--shannon-entropy--chi-square-statistical-tests)
   - [canary — Decoy File Deployment & Detection](#2-canary--decoy-files)
   - [detector — Ransomware Behavior Engine](#3-detector--behavior-scoring-engine)
   - [ring_buffer — Lock-Free Event Queue](#4-ring_buffer--lock-free-circular-buffer)
   - [mitigation — Process Termination](#5-mitigation--process-kill)
2. [Running All Tests](#running-all-tests)
3. [Operational Scripts](#operational-scripts)
   - [install_deps.sh](#install_depssh)
   - [zfs_setup.sh](#zfs_setupsh)
   - [mount.sh](#mountsh)
   - [rollback.sh](#rollbacksh)
   - [run_tests.sh](#run_testssh)
4. [Build Prerequisites](#build-prerequisites)
5. [Troubleshooting](#troubleshooting)

---

## Unit Test Suite

All test files live in `tests/unit/`. Each test is a standalone C program compiled against the corresponding source module. Tests use a custom assertion framework (no external library required beyond the C standard library and POSIX threads).

### Test Macro Overview

| Macro | Behavior |
|---|---|
| `ASSERT(expr)` | Fails if `expr` is falsy (0, NULL) |
| `ASSERT_EQ(a, b)` | Fails if `a != b` |
| `ASSERT_FLOAT_EQ(actual, expected, tol)` | Fails if `\|actual - expected\| > tol` |
| `ASSERT_TRUE(expr)` | Same as ASSERT |
| `ASSERT_NOT_NULL(ptr)` | Fails if `ptr == NULL` |
| `ASSERT_NULL(ptr)` | Fails if `ptr != NULL` |
| `ASSERT_NEGATIVE(expr)` | Fails if `expr >= 0` |
| `ASSERT_NOT_CRASH(expr, msg)` | Always passes if the expression evaluates without crashing |

---

### 1. Entropy — Shannon Entropy & Chi-Square Statistical Tests

**Source**: `src/entropy.c`  
**Header**: `include/entropy.h`  
**Test file**: `tests/unit/test_entropy.c`

**Quick compile & run**:
```bash
gcc -std=c17 -Wall -Wextra -Wpedantic \
    tests/unit/test_entropy.c src/entropy.c \
    -Iinclude -lm -o /tmp/test_entropy && /tmp/test_entropy
```

| Test | What it verifies | Expected |
|---|---|---|
| `test_shannon_uniform` | Buffer with bytes 0..255 once each → maximum entropy | H = 8.0 |
| `test_shannon_constant` | Buffer with all identical bytes → zero entropy | H = 0.0 |
| `test_shannon_empty` | Empty buffer (`len=0`) → returns 0 without crashing | H = 0.0 |
| `test_chi_square_uniform` | Each byte appears exactly once in 256-byte sample | χ² = 0.0 |
| `test_chi_square_skewed` | All 512 bytes identical → extreme χ² value | χ² > 100,000 |
| `test_sliding_window` | 1024-byte zero buffer, window=512 → 2 blocks of H=0.0 | n_blocks=2, H=[0,0] |
| `test_autocorrelation` | Known sequence [1,2,3,4] → lag-1 Pearson correlation | ≈ 0.4545 |
| `test_chi2_from_hist` | Uniform histogram (1 per bucket) → zero chi² | χ² = 0.0 |
| `test_chi2_from_hist_empty` | All-zero histogram, total=0 → returns 0 | χ² = 0.0 |

**Dependencies**: `-lm` (math library for `log2`, `fabs`)

---

### 2. Canary — Decoy Files

**Source**: `src/canary.c`  
**Header**: `include/canary.h`  
**Test file**: `tests/unit/test_canary.c`

**Quick compile & run**:
```bash
gcc -std=c17 -Wall -Wextra -Wpedantic \
    tests/unit/test_canary.c src/canary.c \
    -Iinclude -o /tmp/test_canary && /tmp/test_canary
```

| Test | What it verifies |
|---|---|
| `test_init` | `canary_init()` allocates context without crashing |
| `test_canary_is_canary_true` | Deployed canary files are recognized via `canary_is_canary()` |
| `test_canary_is_canary_false` | Non-canary paths return 0 |
| `test_deploy_count` | `canary_deploy(ctx, N)` creates exactly N files on disk |

**Important**: Each test creates a temporary directory via `mkdtemp("/tmp/canary_test_XXXXXX")` and cleans it up with `rm -rf` afterward. No root privileges required.

---

### 3. Detector — Behavior Scoring Engine

**Source**: `src/detector.c`  
**Header**: `include/detector.h`  
**Test file**: `tests/unit/test_detector.c`

**Quick compile & run**:
```bash
gcc -std=c17 -Wall -Wextra -Wpedantic \
    tests/unit/test_detector.c src/detector.c src/entropy.c \
    -Iinclude -lm -lpthread -o /tmp/test_detector && /tmp/test_detector
```

| Test | What it verifies | Expected verdict |
|---|---|---|
| `test_init` | Context created, initial write is normal | `VERDICT_NORMAL` (0) |
| `test_check_write_normal` | Single write with low entropy → normal | `VERDICT_NORMAL` (0) |
| `test_check_write_suspicious` | 21 writes with entropy=8.0 → quick rule triggers | `≥ VERDICT_SUSPICIOUS` (1) |
| `test_signal_canary` | After canary signal, next write for same PID → block | `VERDICT_BLOCK` (2) |
| `test_check_rename_no_ext_change` | Rename without extension change → normal | `VERDICT_NORMAL` (0) |
| `test_check_rename_ext_change` | 5 extension-changing renames → suspicious | `≥ VERDICT_SUSPICIOUS` (1) |
| `test_confirm_attack` | `detector_confirm_attack()` sets flag, context remains usable | `VERDICT_NORMAL` (0) |
| `test_window_rotation` | window_secs=0 → rotates every call, quick rule never fires | `VERDICT_NORMAL` (0) |

**Dependencies**: `-lm -lpthread` (pthread mutex, math functions)

**Verdict semantics**:
- `0` = `VERDICT_NORMAL` — no action
- `1` = `VERDICT_SUSPICIOUS` — log, increase monitoring
- `2` = `VERDICT_BLOCK` — deny the operation

---

### 4. Ring Buffer — Lock-Free Circular Buffer

**Source**: `src/ring_buffer.c`  
**Header**: `include/ring_buffer.h`  
**Test file**: `tests/unit/test_ring_buffer.c`

**Quick compile & run**:
```bash
gcc -std=c17 -Wall -Wextra -Wpedantic \
    tests/unit/test_ring_buffer.c src/ring_buffer.c \
    -Iinclude -lpthread -o /tmp/test_ring_buffer && /tmp/test_ring_buffer
```

| Test | What it verifies |
|---|---|
| `test_create_destroy` | Ring buffer allocates and destroys without leaks/crashes |
| `test_push_pop_single` | Push one event, pop it back — all fields match exactly |
| `test_push_pop_fifo` | Push 3 events, pop them — FIFO order preserved |
| `test_full_buffer` | Fill to capacity, pop all — order and count correct |
| `test_wrap_around` | Push 3, pop 2, push 2, pop 3 — head/tail wrap modulo capacity works |

**Data structure**: `io_event_t` (defined in `include/ring_buffer.h`):
```c
typedef struct {
    int       type;        // EV_READ=1, EV_WRITE=2, EV_RENAME=3, EV_UNLINK=4
    uint32_t  pid;
    char      path[4096];
    double    entropy;
    uint64_t  size;
    uint64_t  ts_ns;
    int       ext_changed;
} io_event_t;
```

**Dependencies**: `-lpthread` (mutex + condition variables for blocking push/pop)

---

### 5. Mitigation — Process Kill

**Source**: `src/mitigation.c`  
**Header**: `include/mitigation.h`  
**Test file**: `tests/unit/test_mitigation.c`

**Quick compile & run**:
```bash
gcc -std=c17 -Wall -Wextra -Wpedantic \
    tests/unit/test_mitigation.c src/mitigation.c \
    -Iinclude -o /tmp/test_mitigation && /tmp/test_mitigation
```

| Test | What it verifies |
|---|---|
| `test_kill_invalid_pid` | `kill()` with impossible PIDs returns -1 (ESRCH) |
| `test_function_exists` | The `mitigation_kill_process` symbol exists and links |

**Safety note**: This test deliberately uses PIDs well above `/proc/sys/kernel/pid_max` to avoid hitting real processes. PIDs that wrap to negative values (e.g., `0xFFFFFFFF` → `-1`) would trigger `kill(-1, SIGKILL)` which broadcasts to all processes — **never use PID values that become negative when cast to `pid_t`**.

---

## Running All Tests

### Option A: Via CMake/CTest (recommended for CI)

```bash
cmake -S . -B build -DBUILD_TESTS=ON
cmake --build build --target all --parallel "$(nproc)"
cd build && ctest --output-on-failure --test-dir tests/unit
```

### Option B: Via convenience script

```bash
bash scripts/run_tests.sh
```

This script:
1. Configures CMake with `-DBUILD_TESTS=ON`
2. Builds all test targets in parallel
3. Runs `ctest` with failure output
4. Returns exit code 0 if all pass, 1 otherwise

### Option C: Individual compilation (for debugging)

```bash
# Each test is self-contained — compile and run directly:
for test in entropy canary detector ring_buffer mitigation; do
    echo "=== $test ==="
    gcc -std=c17 -Wall -Wextra -Wpedantic \
        tests/unit/test_$test.c src/$test.c \
        -Iinclude -lm -lpthread \
        -o /tmp/test_$test 2>&1 && /tmp/test_$test
done
```

**Note**: Not all tests need `-lm` or `-lpthread`. The table above shows the exact dependencies per module.

---

## Operational Scripts

All scripts live in `scripts/`. They are bash scripts targeting Ubuntu 24.04 and are **idempotent** — safe to run multiple times.

### install_deps.sh

Installs all system dependencies needed to build and run Guardian FS.

```bash
sudo bash scripts/install_deps.sh
```

Packages installed:
- `build-essential`, `cmake`, `pkg-config` — C build toolchain
- `libfuse3-dev` — FUSE3 userspace filesystem library
- `zfsutils-linux` — ZFS command-line tools
- `python3`, `python3-pip`, `python3-venv` — Python analysis scripts
- `git`, `curl` — version control and HTTP

### zfs_setup.sh

Creates a file-backed ZFS pool for PoC/testing (no physical disks required).

```bash
sudo bash scripts/zfs_setup.sh [dataset] [mountpoint]
# Default: tank/data, mountpoint=/mnt/guardian_real
```

What it does:
1. Creates a 2 GB sparse file at `/tmp/zpool_disk.img`
2. Creates a zpool named `tank` backed by that file
3. Creates a ZFS dataset `tank/data`
4. Sets `compression=lz4`, `atime=off`

### mount.sh

Mounts the Guardian FUSE filesystem over a real directory.

```bash
sudo bash scripts/mount.sh <source_dir> <mountpoint>
# Example: sudo bash scripts/mount.sh /mnt/guardian_real /mnt/protected
```

Pre-conditions:
- `guardian_fs` binary must exist in `build/`
- Source directory must exist (ZFS dataset mountpoint)
- FUSE kernel module must be loaded

### rollback.sh

Rolls back a ZFS dataset to a named snapshot or the latest one.

```bash
sudo bash scripts/rollback.sh <dataset> <snapshot_name|latest>
# Example: sudo bash scripts/rollback.sh tank/data guardian-auto-20250101T120000Z
#          sudo bash scripts/rollback.sh tank/data latest
```

### run_tests.sh

One-command test suite runner (described in [Running All Tests](#running-all-tests)).

```bash
bash scripts/run_tests.sh
```

---

## Build Prerequisites

| Dependency | Minimum version | Why |
|---|---|---|
| GCC or Clang | C17 support (`-std=c17`) | Compilation |
| CMake | 3.16+ | Build system |
| libfuse3 | 3.x | FUSE filesystem hooks |
| ZFS | 0.8+ | Snapshot management |
| POSIX threads | Any | Detector mutex, ring buffer synchronization |

---

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| `test_detector` hangs | pthread mutex deadlock | Ensure `-lpthread` is linked; mutex is always locked/unlocked in pairs |
| `test_canary` fails on `test_deploy_count` | Residual files from previous run in `/tmp` | `rm -rf /tmp/canary_test_*` |
| `test_mitigation` kills system processes | PID value cast to negative `pid_t` | Only use PIDs ≤ `0x7FFFFFFE` (below `INT32_MAX`) |
| `cmake` fails with `libfuse3 not found` | Missing FUSE3 development headers | `sudo apt install libfuse3-dev` |
| `ctest` reports no tests | CMake configured without `-DBUILD_TESTS=ON` | Re-run cmake with the flag |
| `fatal error: entropy.h: No such file` | `-Iinclude` flag missing or wrong | Compile from project root with `-Iinclude` |

---

## Test Coverage Summary

| Module | Test file | # Tests | # Assertions | Status |
|---|---|---|---|---|
| entropy | `test_entropy.c` | 9 | 12 | ✅ All passing |
| canary | `test_canary.c` | 4 | 13 | ✅ All passing |
| detector | `test_detector.c` | 8 | 9 | ✅ All passing |
| ring_buffer | `test_ring_buffer.c` | 5 | 46 | ✅ All passing |
| mitigation | `test_mitigation.c` | 2 | 3 | ✅ All passing |
| **Total** | | **28** | **83** | ✅ **All passing** |

---

*Generated: 2026-06-27. For questions or issues, refer to the project's Engram memory under `sdd-init/utn-frsf-proyecto-final`.*
