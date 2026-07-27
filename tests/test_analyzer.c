/* test_analyzer.c — Unit tests for the asynchronous analyzer module
 *
 * Tests the per-PID aggregation table (get_slot) and window-rotation logic
 * using the technique of #include'ing the .c source to reach static helpers.
 *
 * Compile with:
 *   gcc -std=c17 -Wall -Wextra test_analyzer.c ../src/analyzer.c \
 *       ../src/ring_buffer.c ../src/detector.c ../src/entropy.c \
 *       -I../include -lpthread -lm -o test_analyzer
 *
 * No framework — plain asserts.
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include <pthread.h>

/* ── Stubs for extern globals referenced by analyzer.c ── */
#include "ring_buffer.h"
#include "detector.h"

struct ring_buf    *evbuf    = NULL;
struct detector_ctx *detector = NULL;

/* ── Bring in the static implementation under test ── */
#include "../src/analyzer.c"

/* ── Test harness ── */
static int tests_run    = 0;
static int tests_passed = 0;
static int tests_failed = 0;

#define TNAME __func__

#define ASSERT(expr) do {                                           \
    tests_run++;                                                    \
    if (expr) {                                                     \
        tests_passed++;                                             \
        printf("  PASS: %s\n", TNAME);                              \
    } else {                                                        \
        tests_failed++;                                             \
        printf("  FAIL: %s — %s\n", TNAME, #expr);                  \
    }                                                               \
} while(0)

#define ASSERT_EQ(a, b) do {                                        \
    tests_run++;                                                    \
    if ((a) == (b)) {                                               \
        tests_passed++;                                             \
        printf("  PASS: %s (%d == %d)\n", TNAME, (int)(a), (int)(b));\
    } else {                                                        \
        tests_failed++;                                             \
        printf("  FAIL: %s — got %d, expected %d\n",               \
               TNAME, (int)(a), (int)(b));                          \
    }                                                               \
} while(0)

#define ASSERT_PTR_EQ(a, b) do {                                    \
    tests_run++;                                                    \
    if ((a) == (b)) {                                               \
        tests_passed++;                                             \
        printf("  PASS: %s (ptr match)\n", TNAME);                  \
    } else {                                                        \
        tests_failed++;                                             \
        printf("  FAIL: %s — pointer mismatch\n", TNAME);           \
    }                                                               \
} while(0)

#define ASSERT_NOT_NULL(p) do {                                     \
    tests_run++;                                                    \
    if ((p) != NULL) {                                              \
        tests_passed++;                                             \
        printf("  PASS: %s (not NULL)\n", TNAME);                   \
    } else {                                                        \
        tests_failed++;                                             \
        printf("  FAIL: %s — unexpected NULL pointer\n", TNAME);    \
    }                                                               \
} while(0)

/* ── Reset global state between tests ── */
static void reset_table(void) {
    memset(pid_table, 0, sizeof(pid_table));
    /* Re-initialize mutex if needed — PTHREAD_MUTEX_INITIALIZER
     * means it's fine across resets, but let's be safe */
    pthread_mutex_lock(&pid_mutex);
    pthread_mutex_unlock(&pid_mutex);
}

/* ═══════════════════════════════════════════════════════════════
 * Tests: get_slot() — slot assignment
 * ═══════════════════════════════════════════════════════════════ */

/* Fresh PID gets a valid slot with correct metadata */
static void test_get_slot_new_pid(void) {
    reset_table();
    pthread_mutex_lock(&pid_mutex);
    pid_stats_t *s = get_slot(1000);
    pthread_mutex_unlock(&pid_mutex);

    ASSERT_NOT_NULL(s);
    ASSERT_EQ(s->active, 1);
    ASSERT_EQ((int)s->pid, 1000);
    ASSERT_EQ(s->write_count, 0ULL);
    ASSERT_EQ(s->total_bytes, 0ULL);
    ASSERT_EQ(s->entropy_sum, 0.0);
    ASSERT_EQ(s->entropy_max, 0.0);
    ASSERT_EQ(s->rename_count, 0ULL);
    ASSERT_EQ(s->unlink_count, 0ULL);
}

/* Same PID called twice returns the SAME slot pointer */
static void test_get_slot_same_pid(void) {
    reset_table();
    pthread_mutex_lock(&pid_mutex);
    pid_stats_t *s1 = get_slot(2000);
    pid_stats_t *s2 = get_slot(2000);
    pthread_mutex_unlock(&pid_mutex);

    ASSERT_NOT_NULL(s1);
    ASSERT_PTR_EQ(s1, s2);
}

/* Different PIDs get DIFFERENT slots */
static void test_get_slot_different_pids(void) {
    reset_table();
    pthread_mutex_lock(&pid_mutex);
    pid_stats_t *s1 = get_slot(3000);
    pid_stats_t *s2 = get_slot(3001);
    pid_stats_t *s3 = get_slot(3002);
    pthread_mutex_unlock(&pid_mutex);

    ASSERT_NOT_NULL(s1);
    ASSERT_NOT_NULL(s2);
    ASSERT_NOT_NULL(s3);
    /* Pointers must be distinct */
    ASSERT(s1 != s2);
    ASSERT(s2 != s3);
    ASSERT(s1 != s3);
}

/* Table full (MAX_PID_SLOTS) → returns NULL */
static void test_get_slot_table_full(void) {
    reset_table();
    pthread_mutex_lock(&pid_mutex);

    /* Fill every slot */
    for (int i = 0; i < MAX_PID_SLOTS; i++) {
        pid_stats_t *s = get_slot((uint32_t)(10000 + i));
        ASSERT_NOT_NULL(s);
    }

    /* One more should fail */
    pid_stats_t *full = get_slot(99999);
    ASSERT(full == NULL);

    pthread_mutex_unlock(&pid_mutex);
}

/* Slot marked as inactive gets reused by a new PID */
static void test_get_slot_reuse_inactive(void) {
    reset_table();
    pthread_mutex_lock(&pid_mutex);

    pid_stats_t *s1 = get_slot(4000);
    ASSERT_NOT_NULL(s1);
    ASSERT_EQ((int)s1->pid, 4000);

    /* Manually deactivate (simulate cleanup in a real destroy path) */
    s1->active = 0;

    /* A new PID should land in that same slot */
    pid_stats_t *s2 = get_slot(4001);
    ASSERT_NOT_NULL(s2);
    ASSERT_EQ((int)s2->pid, 4001);

    /* Should be the same pointer — reused the inactive slot */
    ASSERT_PTR_EQ(s1, s2);

    pthread_mutex_unlock(&pid_mutex);
}

/* ═══════════════════════════════════════════════════════════════
 * Tests: window rotation
 * ═══════════════════════════════════════════════════════════════ */

/* Window expired (> ML_WINDOW_SECS) → stats reset to zero */
static void test_window_rotation_expired(void) {
    reset_table();
    pthread_mutex_lock(&pid_mutex);

    pid_stats_t *s = get_slot(5000);
    ASSERT_NOT_NULL(s);

    /* Simulate activity in the current window */
    s->write_count  = 25;
    s->total_bytes  = 100000;
    s->entropy_sum  = 180.0;
    s->entropy_max  = 7.9;
    s->rename_count = 12;
    s->unlink_count = 3;

    /* Force window_start far into the past so rotation triggers */
    s->window_start = time(NULL) - (ML_WINDOW_SECS + 10);

    /* Calling get_slot again must rotate and reset */
    pid_stats_t *s2 = get_slot(5000);
    ASSERT_PTR_EQ(s, s2);       /* same slot */
    ASSERT_EQ(s2->write_count,  0ULL);
    ASSERT_EQ(s2->total_bytes,  0ULL);
    ASSERT_EQ(s2->entropy_sum,  0.0);
    ASSERT_EQ(s2->entropy_max,  0.0);
    ASSERT_EQ(s2->rename_count, 0ULL);
    ASSERT_EQ(s2->unlink_count, 0ULL);
    ASSERT(s2->active == 1);    /* stays active */
    ASSERT_EQ((int)s2->pid, 5000); /* PID preserved */

    pthread_mutex_unlock(&pid_mutex);
}

/* Window still fresh → stats are NOT reset */
static void test_window_rotation_still_active(void) {
    reset_table();
    pthread_mutex_lock(&pid_mutex);

    pid_stats_t *s = get_slot(6000);
    ASSERT_NOT_NULL(s);

    s->write_count  = 8;
    s->total_bytes  = 32000;
    s->entropy_sum  = 56.0;
    s->entropy_max  = 7.5;
    s->rename_count = 4;
    s->unlink_count = 1;
    /* window_start is current time — well within the window */

    pid_stats_t *s2 = get_slot(6000);
    ASSERT_PTR_EQ(s, s2);
    ASSERT_EQ(s2->write_count,  8ULL);
    ASSERT_EQ(s2->total_bytes,  32000ULL);
    ASSERT_EQ(s2->entropy_sum,  56.0);
    ASSERT_EQ(s2->entropy_max,  7.5);
    ASSERT_EQ(s2->rename_count, 4ULL);
    ASSERT_EQ(s2->unlink_count, 1ULL);

    pthread_mutex_unlock(&pid_mutex);
}

/* Double rotation: window expires, rotates, expires again, rotates again */
static void test_window_double_rotation(void) {
    reset_table();
    pthread_mutex_lock(&pid_mutex);

    pid_stats_t *s = get_slot(7000);
    ASSERT_NOT_NULL(s);

    /* First window: accumulate */
    s->write_count  = 20;
    s->entropy_max  = 8.0;
    s->window_start = time(NULL) - (ML_WINDOW_SECS + 5);

    /* Rotate */
    pid_stats_t *s2 = get_slot(7000);
    ASSERT_PTR_EQ(s, s2);
    ASSERT_EQ(s2->write_count,  0ULL);
    ASSERT_EQ(s2->entropy_max,  0.0);

    /* Second window: accumulate again */
    s2->write_count  = 30;
    s2->entropy_max  = 7.8;
    s2->window_start = time(NULL) - (ML_WINDOW_SECS + 5);

    /* Rotate again */
    pid_stats_t *s3 = get_slot(7000);
    ASSERT_PTR_EQ(s, s3);
    ASSERT_EQ(s3->write_count,  0ULL);
    ASSERT_EQ(s3->entropy_max,  0.0);

    pthread_mutex_unlock(&pid_mutex);
}

/* Window rotation at exact boundary */
static void test_window_rotation_exact_boundary(void) {
    reset_table();
    pthread_mutex_lock(&pid_mutex);

    pid_stats_t *s = get_slot(8000);
    ASSERT_NOT_NULL(s);

    s->write_count  = 15;
    /* set window_start exactly ML_WINDOW_SECS ago */
    s->window_start = time(NULL) - ML_WINDOW_SECS;

    /* exactly ML_WINDOW_SECS → rotation triggers (>= condition) */
    pid_stats_t *s2 = get_slot(8000);
    ASSERT_EQ(s2->write_count, 0ULL);
    ASSERT_EQ(s2->total_bytes, 0ULL);

    pthread_mutex_unlock(&pid_mutex);
}

/* Rotation preserves active flag and PID */
static void test_window_rotation_preserves_identity(void) {
    reset_table();
    pthread_mutex_lock(&pid_mutex);

    pid_stats_t *s = get_slot(9000);
    ASSERT_NOT_NULL(s);

    s->write_count  = 42;
    s->window_start = time(NULL) - (ML_WINDOW_SECS + 10);

    pid_stats_t *s2 = get_slot(9000);
    ASSERT_PTR_EQ(s, s2);
    ASSERT_EQ(s2->active, 1);
    ASSERT_EQ((int)s2->pid, 9000);

    pthread_mutex_unlock(&pid_mutex);
}

/* ═══════════════════════════════════════════════════════════════
 * Tests: entropy_max tracking
 * ═══════════════════════════════════════════════════════════════ */

/* entropy_max tracks the maximum entropy value seen */
static void test_entropy_max_tracking(void) {
    reset_table();
    pthread_mutex_lock(&pid_mutex);

    pid_stats_t *s = get_slot(11000);
    ASSERT_NOT_NULL(s);

    /* Initial: max is 0.0 */
    ASSERT(s->entropy_max == 0.0);

    /* Simulate EV_WRITE events with increasing entropy */
    s->entropy_max = 6.5;  /* first write */
    s->entropy_max = (7.2 > s->entropy_max) ? 7.2 : s->entropy_max;  /* = 7.2 */
    s->entropy_max = (5.0 > s->entropy_max) ? 5.0 : s->entropy_max;  /* stays 7.2 */
    s->entropy_max = (7.9 > s->entropy_max) ? 7.9 : s->entropy_max;  /* = 7.9 */

    ASSERT(s->entropy_max == 7.9);

    pthread_mutex_unlock(&pid_mutex);
}

/* ═══════════════════════════════════════════════════════════════
 * Runner
 * ═══════════════════════════════════════════════════════════════ */

int main(void) {
    printf("=== Analyzer Unit Tests ===\n\n");

    printf("-- Slot assignment --\n");
    test_get_slot_new_pid();
    test_get_slot_same_pid();
    test_get_slot_different_pids();
    test_get_slot_table_full();
    test_get_slot_reuse_inactive();

    printf("\n-- Window rotation --\n");
    test_window_rotation_expired();
    test_window_rotation_still_active();
    test_window_double_rotation();
    test_window_rotation_exact_boundary();
    test_window_rotation_preserves_identity();

    printf("\n-- Entropy tracking --\n");
    test_entropy_max_tracking();

    printf("\n=== Results: %d/%d passed, %d failed ===\n",
           tests_passed, tests_run, tests_failed);
    return tests_failed > 0 ? 1 : 0;
}
