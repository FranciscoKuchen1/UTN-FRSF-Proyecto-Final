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
    int verdict = detector_check_write(ctx, 1000, "/tmp/test.txt", 3.0, 1024);
    ASSERT_EQ(verdict, VERDICT_NORMAL);

    free(ctx);
}

static void test_check_write_normal(void) {
    struct detector_ctx *ctx = detector_init(10, 7.5, 50, 10);

    /* A single write with low entropy → NORMAL */
    int verdict = detector_check_write(ctx, 2000, "/tmp/file.txt", 3.0, 512);
    ASSERT_EQ(verdict, VERDICT_NORMAL);

    free(ctx);
}

static void test_check_write_suspicious(void) {
    struct detector_ctx *ctx = detector_init(10, 7.5, 50, 10);
    uint32_t pid = 3000;
    int suspicious_seen = 0;

    /* 21 writes with high entropy (8.0) — quick rule triggers:
     * entropy > threshold (7.5) AND write_count > 20 → SUSPICIOUS */
    for (int i = 0; i < 21; i++) {
        int verdict = detector_check_write(ctx, pid, "/tmp/encrypted.bin",
                                           8.0, 4096);
        if (verdict >= VERDICT_SUSPICIOUS)
            suspicious_seen = 1;
    }

    ASSERT(suspicious_seen);

    free(ctx);
}

static void test_signal_canary(void) {
    struct detector_ctx *ctx = detector_init(10, 7.5, 50, 10);
    uint32_t pid = 4000;

    /* Signal a canary alert for this PID */
    detector_signal_canary(ctx, "/mnt/canary_file.docx", pid);

    /* Subsequent write for the same PID should return BLOCK
     * because canary_triggered flag forces BLOCK verdict */
    int verdict = detector_check_write(ctx, pid, "/mnt/some_file.txt", 3.0, 1024);
    ASSERT_EQ(verdict, VERDICT_BLOCK);

    free(ctx);
}

static void test_check_rename_no_ext_change(void) {
    struct detector_ctx *ctx = detector_init(10, 7.5, 50, 10);

    /* Rename without extension change → NORMAL */
    int verdict = detector_check_rename(ctx, 5000,
                                        "/mnt/old.txt", "/mnt/new.txt", 0);
    ASSERT_EQ(verdict, VERDICT_NORMAL);

    free(ctx);
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

    free(ctx);
}

static void test_confirm_attack(void) {
    struct detector_ctx *ctx = detector_init(10, 7.5, 50, 10);

    /* Confirm attack for PID 7000 — should not crash */
    detector_confirm_attack(ctx, 7000);

    /* Verify the context is still usable after confirmation */
    int verdict = detector_check_write(ctx, 7000, "/tmp/after.txt", 3.0, 1024);
    ASSERT_EQ(verdict, VERDICT_NORMAL);

    free(ctx);
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
        verdict = detector_check_write(ctx, pid, "/tmp/rot.txt", 8.0, 4096);
        /* Small sleep to ensure elapsed time > 0 between calls */
        usleep(1);
    }

    /* With window_secs=0, every write rotates, so write_count never
     * exceeds 1. The quick rule won't fire, and score stays low.
     * Expected: NORMAL */
    ASSERT_EQ(verdict, VERDICT_NORMAL);

    free(ctx);
}

/* ---------------------------------------------------------------- */

int main(void) {
    printf("=== Detector Unit Tests ===\n\n");

    test_init();
    test_check_write_normal();
    test_check_write_suspicious();
    test_signal_canary();
    test_check_rename_no_ext_change();
    test_check_rename_ext_change();
    test_confirm_attack();
    test_window_rotation();

    printf("\n=== Results: %d/%d passed, %d failed ===\n",
           tests_passed, tests_run, tests_failed);
    return tests_failed > 0 ? 1 : 0;
}
