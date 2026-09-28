/* test_detector.c — Unit tests for detector module
 * Compile with: gcc -std=c17 -Wall -Wextra test_detector.c ../src/detector.c ../src/entropy.c \
 *               -I../include -lm -lpthread -o test_detector
 *
 * Tests behavior through the public API only (detector_ctx is opaque).
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include "detector.h"

static int tests_run = 0;
static int tests_passed = 0;
static int tests_failed = 0;

#define ASSERT(expr) do {                                                         \
    tests_run++;                                                                  \
    if (expr) {                                                                   \
        tests_passed++;                                                           \
        printf("  PASS: %s\n", __func__);                                         \
    } else {                                                                      \
        tests_failed++;                                                           \
        printf("  FAIL: %s: %s\n", __func__, #expr);                              \
    }                                                                             \
} while(0)

#define ASSERT_EQ(a, b) do {                                                      \
    tests_run++;                                                                  \
    if ((a) == (b)) {                                                             \
        tests_passed++;                                                           \
        printf("  PASS: %s (%d == %d)\n", __func__, (int)(a), (int)(b));          \
    } else {                                                                      \
        tests_failed++;                                                           \
        printf("  FAIL: %s: got %d, expected %d\n", __func__, (int)(a), (int)(b));\
    }                                                                             \
} while(0)

/* ---------------------------------------------------------------- */

static void test_init(void) {
    struct detector_ctx *ctx = detector_init(10, 7.5, 50, 10);
    ASSERT(ctx != NULL);

    /* Verify the context can be used immediately without crashing */
    int verdict = detector_check_write(ctx, 1000, "/tmp/test.txt", 3.0, 1024, 0.0);
    ASSERT_EQ(verdict, VERDICT_NORMAL);

    detector_destroy(ctx);
}

static void test_check_write_normal(void) {
    struct detector_ctx *ctx = detector_init(10, 7.5, 50, 10);

    /* A single write with low entropy → NORMAL */
    int verdict = detector_check_write(ctx, 2000, "/tmp/file.txt", 3.0, 512, 0.0);
    ASSERT_EQ(verdict, VERDICT_NORMAL);

    detector_destroy(ctx);
}

static void test_check_write_suspicious(void) {
    struct detector_ctx *ctx = detector_init(10, 7.5, 50, 10);
    uint32_t pid = 3000;
    int suspicious_seen = 0;

    /* 21 writes with high entropy (8.0) — quick rule triggers:
     * entropy > threshold (7.5) AND write_count > 20 → SUSPICIOUS */
    for (int i = 0; i < 21; i++) {
        int verdict = detector_check_write(ctx, pid, "/tmp/encrypted.bin",
                                           8.0, 4096, 0.0);
        if (verdict >= VERDICT_SUSPICIOUS)
            suspicious_seen = 1;
    }

    ASSERT(suspicious_seen);

    detector_destroy(ctx);
}

static void test_check_write_chi2_blocks(void) {
    struct detector_ctx *ctx = detector_init(10, 7.5, 50, 10);
    uint32_t pid = 3100;
    int verdict = VERDICT_NORMAL;

    /* High entropy + uniform bytes (chi2 ≈ 250 with 255 dof):
     * entropy (0.40) + write rate (0.20) + chi2 (0.25 * 0.583) ≈ 0.75
     * ≥ score_thresh (0.65) → BLOCK.
     * Without the chi2 signal the score caps at 0.60 → never BLOCK. */
    for (int i = 0; i < 60; i++) {
        verdict = detector_check_write(ctx, pid, "/tmp/encrypted.bin",
                                       8.0, 4096, 250.0);
    }

    ASSERT_EQ(verdict, VERDICT_BLOCK);

    detector_destroy(ctx);
}

static void test_check_write_no_chi2_not_blocked(void) {
    struct detector_ctx *ctx = detector_init(10, 7.5, 50, 10);
    uint32_t pid = 3200;
    int verdict = VERDICT_NORMAL;

    /* Control: same traffic but chi2 = 0.0 (no valid samples, e.g. text).
     * Score caps at 0.40 + 0.20 = 0.60 < 0.65 → only the quick rule
     * fires → SUSPICIOUS, never BLOCK. */
    for (int i = 0; i < 60; i++) {
        verdict = detector_check_write(ctx, pid, "/tmp/skewed.bin",
                                       8.0, 4096, 0.0);
    }

    ASSERT_EQ(verdict, VERDICT_SUSPICIOUS);

    detector_destroy(ctx);
}

static void test_signal_canary(void) {
    struct detector_ctx *ctx = detector_init(10, 7.5, 50, 10);
    uint32_t pid = 4000;

    /* Signal a canary alert for this PID (p.ej. lo abrió para escribir) */
    detector_signal_canary(ctx, "/mnt/canary_file.docx", pid);

    /* Ransomware: tras tocar el canary, cifra → escritura de alta
     * entropía → BLOCK inmediato */
    int verdict = detector_check_write(ctx, pid, "/mnt/some_file.txt",
                                        8.0, 4096, 250.0);
    ASSERT_EQ(verdict, VERDICT_BLOCK);

    detector_destroy(ctx);
}

static void test_canary_edit_not_blocked(void) {
    /* Usuario editando el señuelo: el canary armó la señal, pero sus
     * escrituras son de baja entropía (texto) → pasan. La regla canary
     * bloquea solo escrituras con firma de cifrado. */
    struct detector_ctx *ctx = detector_init(10, 7.5, 50, 10);
    uint32_t pid = 4100;

    detector_signal_canary(ctx, "/mnt/A_important_report.docx", pid);

    /* Temporal/lock del editor (baja entropía, otra ruta) → pasa */
    int v1 = detector_check_write(ctx, pid, "/mnt/.~lock.tmp",
                                   3.0, 512, 0.0);
    ASSERT_EQ(v1, VERDICT_NORMAL);

    /* Guardar el propio canary con contenido normal → pasa */
    int v2 = detector_check_write(ctx, pid, "/mnt/A_important_report.docx",
                                   3.0, 2048, 0.0);
    ASSERT_EQ(v2, VERDICT_NORMAL);

    detector_destroy(ctx);
}

static void test_global_brake_multiprocess(void) {
    /* Evasión multiproceso: 8 PIDs con pocas escrituras de alta entropía
     * cada uno — ninguno dispara el score per-PID (máx 0.53 < 0.65) ni
     * la regla rápida (≤20 writes), pero el agregado global (120 ≥ 100)
     * arma el freno → los escritores con firma de cifrado se bloquean. */
    struct detector_ctx *ctx = detector_init(10, 7.5, 50, 10);

    for (int p = 0; p < 8; p++)
        for (int i = 0; i < 15; i++)
            detector_check_write(ctx, 50000 + p, "/tmp/e.bin",
                                 8.0, 4096, 250.0);

    ASSERT(detector_global_brake_armed(ctx) == 1);

    /* Otro write con firma de cifrado (score per-PID aún bajo) → BLOCK
     * por el freno global */
    ASSERT_EQ(detector_check_write(ctx, 50003, "/tmp/e2.bin",
                                    8.0, 4096, 250.0),
              VERDICT_BLOCK);

    /* Un proceso benigno de baja entropía durante el freno → pasa */
    ASSERT_EQ(detector_check_write(ctx, 60000, "/tmp/notes.txt",
                                    3.0, 4096, 0.0),
              VERDICT_NORMAL);

    detector_destroy(ctx);
}

static void test_unlink_backup_hunting(void) {
    /* Caza de backups (análogo Linux del vssadmin): los unlinks solos
     * no bloquean (make clean / rm de temporales), pero suman al score y
     * combinados con cifrado sí. */
    struct detector_ctx *ctx = detector_init(10, 7.5, 50, 10);
    uint32_t pid = 4500;

    int verdict = VERDICT_NORMAL;
    for (int i = 0; i < 50; i++)
        verdict = detector_check_unlink(ctx, pid, "/mnt/backup/file.bak");

    /* 50 unlinks / thresh 40 → f_unlink=1 → 0.10 < 0.65 → NORMAL */
    ASSERT_EQ(verdict, VERDICT_NORMAL);

    /* Mismo PID además cifra: 0.35 + 0.20 + 0.117 + 0.10 ≈ 0.77 ≥ 0.65
     * → BLOCK (borra los backups tras cifrarlos) */
    for (int i = 0; i < 50; i++)
        verdict = detector_check_write(ctx, pid, "/mnt/doc.docx",
                                       8.0, 4096, 250.0);
    ASSERT_EQ(verdict, VERDICT_BLOCK);

    detector_destroy(ctx);
}

static void test_note_canary_read_not_blocked(void) {
    /* Un canary tocado en modo read-only (tar, cp -r, thumbnailer, AV)
     * NO arma el kill: la próxima escritura del mismo PID debe pasar.
     * Regresión del FP que mataba backups. */
    struct detector_ctx *ctx = detector_init(10, 7.5, 50, 10);
    uint32_t pid = 4100;

    detector_note_canary_read(ctx, pid);
    detector_note_canary_read(ctx, pid);

    int verdict = detector_check_write(ctx, pid, "/mnt/some_file.txt",
                                       3.0, 1024, 0.0);
    ASSERT_EQ(verdict, VERDICT_NORMAL);

    detector_destroy(ctx);
}

static void test_pid_starttime_unknown(void) {
    /* PID sin entrada en el detector → starttime 0 (sin verificación) */
    struct detector_ctx *ctx = detector_init(10, 7.5, 50, 10);
    ASSERT_EQ(detector_pid_starttime(ctx, 999999), 0ULL);
    detector_destroy(ctx);
}

static void test_reset_pid_clears_state(void) {
    /* detector_reset_pid descarta el estado envenenado de un PID
     * (p.ej. tras detectar reuso de PID): la misma señal de canary
     * ya no bloquea tras el reset. */
    struct detector_ctx *ctx = detector_init(10, 7.5, 50, 10);
    uint32_t pid = 4200;

    detector_signal_canary(ctx, "/mnt/canary_file.docx", pid);
    ASSERT_EQ(detector_check_write(ctx, pid, "/tmp/x.txt", 8.0, 4096, 250.0),
              VERDICT_BLOCK);

    detector_reset_pid(ctx, pid);
    /* Estado fresco: una única escritura de alta entropía no bloquea */
    ASSERT_EQ(detector_check_write(ctx, pid, "/tmp/x.txt", 8.0, 4096, 250.0),
              VERDICT_NORMAL);

    detector_destroy(ctx);
}

static void test_check_rename_no_ext_change(void) {
    struct detector_ctx *ctx = detector_init(10, 7.5, 50, 10);

    /* Rename without extension change → NORMAL */
    int verdict = detector_check_rename(ctx, 5000,
                                        "/mnt/old.txt", "/mnt/new.txt", 0);
    ASSERT_EQ(verdict, VERDICT_NORMAL);

    detector_destroy(ctx);
}

static void test_check_rename_ext_change(void) {
    struct detector_ctx *ctx = detector_init(10, 7.5, 50, 10);
    uint32_t pid = 6000;

    /* Multiple extension changes → suspicious.
     * Each ext_changed=1 adds 0.4 to the aggregate score.
     * After enough calls, warn_threshold (0.45) is crossed → SUSPICIOUS */
    int verdict = VERDICT_NORMAL;
    for (int i = 0; i < 5; i++) {
        verdict = detector_check_rename(ctx, pid,
                                        "/mnt/file.txt", "/mnt/file.enc", 1);
    }

    ASSERT(verdict >= VERDICT_SUSPICIOUS);

    detector_destroy(ctx);
}

static void test_confirm_attack(void) {
    struct detector_ctx *ctx = detector_init(10, 7.5, 50, 10);

    /* Confirm attack for PID 7000 (e.g. ML verdict "attack").
     * The next write of that PID must be BLOCKED — this is what gives
     * the async ML second opinion real enforcement power. */
    detector_confirm_attack(ctx, 7000);

    int verdict = detector_check_write(ctx, 7000, "/tmp/after.txt", 3.0, 1024, 0.0);
    ASSERT_EQ(verdict, VERDICT_BLOCK);

    /* And the next rename too */
    verdict = detector_check_rename(ctx, 7000,
                                    "/tmp/a.txt", "/tmp/b.enc", 1);
    ASSERT_EQ(verdict, VERDICT_BLOCK);

    detector_destroy(ctx);
}

static void test_window_rotation(void) {
    /* window_secs=0 forces rotation on every call
     * (elapsed >= 0 is always true for monotonic clock).
     * After rotation, write_count resets to 1 each time,
     * so the quick rule (write_count > 20) never fires. */
    struct detector_ctx *ctx = detector_init(0, 7.5, 50, 10);
    uint32_t pid = 8000;

    int verdict = VERDICT_NORMAL;
    for (int i = 0; i < 30; i++) {
        verdict = detector_check_write(ctx, pid, "/tmp/rot.txt", 8.0, 4096, 250.0);
        /* Small sleep to ensure elapsed time > 0 between calls */
        usleep(1);
    }

    /* With window_secs=0, every write rotates, so write_count never
     * exceeds 1. The quick rule won't fire, and score stays low.
     * Expected: NORMAL */
    ASSERT_EQ(verdict, VERDICT_NORMAL);

    detector_destroy(ctx);
}

/* ---------------------------------------------------------------- */

int main(void) {
    printf("=== Detector Unit Tests ===\n\n");

    test_init();
    test_check_write_normal();
    test_check_write_suspicious();
    test_check_write_chi2_blocks();
    test_check_write_no_chi2_not_blocked();
    test_signal_canary();
    test_canary_edit_not_blocked();
    test_note_canary_read_not_blocked();
    test_global_brake_multiprocess();
    test_unlink_backup_hunting();
    test_pid_starttime_unknown();
    test_reset_pid_clears_state();
    test_check_rename_no_ext_change();
    test_check_rename_ext_change();
    test_confirm_attack();
    test_window_rotation();

    printf("\n=== Results: %d/%d passed, %d failed ===\n",
           tests_passed, tests_run, tests_failed);
    return tests_failed > 0 ? 1 : 0;
}
