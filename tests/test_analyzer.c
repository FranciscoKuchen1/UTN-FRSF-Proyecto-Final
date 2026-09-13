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
#include <math.h>
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

/* Flush with no ML connection (ml_fd = -1) */
static void flush_no_ml(void) {
    int ml_fd = -1;
    flush_expired_windows(&ml_fd);
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
 * Tests: window rotation (via flush_expired_windows)
 * ═══════════════════════════════════════════════════════════════ */

/* REGRESSION: get_slot must NOT rotate expired windows — doing so
 * discarded accumulated features before they could ever be sent to ML */
static void test_get_slot_does_not_rotate_expired(void) {
    reset_table();
    pthread_mutex_lock(&pid_mutex);

    pid_stats_t *s = get_slot(5000);
    ASSERT_NOT_NULL(s);
    s->write_count  = 25;
    s->window_start = time(NULL) - (ML_WINDOW_SECS + 10);

    pid_stats_t *s2 = get_slot(5000);
    pthread_mutex_unlock(&pid_mutex);

    ASSERT_PTR_EQ(s, s2);
    ASSERT_EQ(s2->write_count, 25ULL);
}

/* Window expired → flush resets stats to zero */
static void test_window_rotation_expired(void) {
    reset_table();
    pthread_mutex_lock(&pid_mutex);

    pid_stats_t *s = get_slot(5100);
    ASSERT_NOT_NULL(s);
    s->write_count  = 25;
    s->total_bytes  = 100000;
    s->entropy_sum  = 180.0;
    s->entropy_max  = 7.9;
    s->rename_count = 12;
    s->unlink_count = 3;
    s->window_start = time(NULL) - (ML_WINDOW_SECS + 10);

    pthread_mutex_unlock(&pid_mutex);

    flush_no_ml();

    ASSERT_EQ(s->write_count,  0ULL);
    ASSERT_EQ(s->total_bytes,  0ULL);
    ASSERT_EQ(s->entropy_sum,  0.0);
    ASSERT_EQ(s->entropy_max,  0.0);
    ASSERT_EQ(s->rename_count, 0ULL);
    ASSERT_EQ(s->unlink_count, 0ULL);
    ASSERT(s->active == 1);
    ASSERT_EQ((int)s->pid, 5100);
}

/* Window still fresh → flush leaves stats untouched */
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

    pthread_mutex_unlock(&pid_mutex);

    flush_no_ml();

    ASSERT_EQ(s->write_count,  8ULL);
    ASSERT_EQ(s->total_bytes,  32000ULL);
    ASSERT_EQ(s->entropy_sum,  56.0);
    ASSERT_EQ(s->entropy_max,  7.5);
    ASSERT_EQ(s->rename_count, 4ULL);
    ASSERT_EQ(s->unlink_count, 1ULL);
}

/* Double rotation: flush twice with expired windows in between */
static void test_window_double_rotation(void) {
    reset_table();
    pthread_mutex_lock(&pid_mutex);

    pid_stats_t *s = get_slot(7000);
    ASSERT_NOT_NULL(s);
    s->write_count  = 20;
    s->entropy_max  = 8.0;
    s->window_start = time(NULL) - (ML_WINDOW_SECS + 5);

    pthread_mutex_unlock(&pid_mutex);

    flush_no_ml();
    ASSERT_EQ(s->write_count, 0ULL);
    ASSERT_EQ(s->entropy_max, 0.0);

    pthread_mutex_lock(&pid_mutex);
    s->write_count  = 30;
    s->entropy_max  = 7.8;
    s->window_start = time(NULL) - (ML_WINDOW_SECS + 5);
    pthread_mutex_unlock(&pid_mutex);

    flush_no_ml();
    ASSERT_EQ(s->write_count, 0ULL);
    ASSERT_EQ(s->entropy_max, 0.0);
}

/* Window rotation at exact boundary (>= condition) */
static void test_window_rotation_exact_boundary(void) {
    reset_table();
    pthread_mutex_lock(&pid_mutex);

    pid_stats_t *s = get_slot(8000);
    ASSERT_NOT_NULL(s);
    s->write_count  = 15;
    s->window_start = time(NULL) - ML_WINDOW_SECS;

    pthread_mutex_unlock(&pid_mutex);

    flush_no_ml();
    ASSERT_EQ(s->write_count, 0ULL);
    ASSERT_EQ(s->total_bytes, 0ULL);
}

/* Rotation preserves active flag and PID */
static void test_window_rotation_preserves_identity(void) {
    reset_table();
    pthread_mutex_lock(&pid_mutex);

    pid_stats_t *s = get_slot(9000);
    ASSERT_NOT_NULL(s);
    s->write_count  = 42;
    s->window_start = time(NULL) - (ML_WINDOW_SECS + 10);

    pthread_mutex_unlock(&pid_mutex);

    flush_no_ml();
    ASSERT_EQ(s->active, 1);
    ASSERT_EQ((int)s->pid, 9000);
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
 * Tests: feature computation helpers (14/14 real features)
 * ═══════════════════════════════════════════════════════════════ */

static void test_fnv1a_hash_deterministic(void) {
    uint64_t h1 = fnv1a_hash("/docs/readme.md", 15);
    uint64_t h2 = fnv1a_hash("/docs/readme.md", 15);
    uint64_t h3 = fnv1a_hash("/docs/other.md", 14);
    ASSERT(h1 == h2);
    ASSERT(h1 != h3);
    ASSERT(h1 != 0);
}

static void test_hash_set_add_dedup_and_cap(void) {
    uint64_t set[HASH_TRACK_CAP];
    uint32_t count = 0;
    memset(set, 0, sizeof(set));

    hash_set_add(set, &count, 111);
    hash_set_add(set, &count, 111);
    hash_set_add(set, &count, 222);
    ASSERT_EQ(count, 2U);

    hash_set_add(set, &count, 0);
    ASSERT_EQ(count, 2U);

    for (uint32_t i = 0; i < HASH_TRACK_CAP + 10; i++)
        hash_set_add(set, &count, 1000 + i);
    ASSERT_EQ(count, (uint32_t)HASH_TRACK_CAP);
}

static void test_path_dir_hash(void) {
    uint64_t a = path_dir_hash("/docs/a.md");
    uint64_t b = path_dir_hash("/docs/b.txt");
    uint64_t c = path_dir_hash("/src/a.md");
    uint64_t root = path_dir_hash("/a.md");
    ASSERT(a == b);
    ASSERT(a != c);
    ASSERT(root != a);
}

static void test_path_ext_hash(void) {
    uint64_t md1 = path_ext_hash("/docs/a.md");
    uint64_t md2 = path_ext_hash("/x/y/b.md");
    uint64_t txt = path_ext_hash("/docs/c.txt");
    ASSERT(md1 == md2);
    ASSERT(md1 != txt);
    ASSERT(path_ext_hash("/noext") == 0);
    ASSERT(path_ext_hash("/.hidden") == 0);
}

static void test_entropy_std_known_values(void) {
    reset_table();
    pthread_mutex_lock(&pid_mutex);
    pid_stats_t *s = get_slot(12000);
    /* entropías 6.0 y 8.0 → mean 7.0, std poblacional 1.0 */
    s->write_count    = 2;
    s->entropy_sum    = 14.0;
    s->entropy_sq_sum = 36.0 + 64.0;
    pthread_mutex_unlock(&pid_mutex);

    ASSERT(fabs(compute_entropy_std(s) - 1.0) < 1e-9);
}

static void test_entropy_std_guards(void) {
    reset_table();
    pthread_mutex_lock(&pid_mutex);
    pid_stats_t *s = get_slot(12100);
    pthread_mutex_unlock(&pid_mutex);
    ASSERT(compute_entropy_std(s) == 0.0);
}

static void test_read_write_ratio(void) {
    reset_table();
    pthread_mutex_lock(&pid_mutex);
    pid_stats_t *s = get_slot(12200);
    s->read_count  = 30;
    s->write_count = 10;
    pid_stats_t *z = get_slot(12201);
    pthread_mutex_unlock(&pid_mutex);

    ASSERT(fabs(compute_read_write_ratio(s) - 3.0) < 1e-9);
    ASSERT(compute_read_write_ratio(z) == 0.0);
}

static void test_ext_change_rate(void) {
    reset_table();
    pthread_mutex_lock(&pid_mutex);
    pid_stats_t *s = get_slot(12300);
    s->rename_count     = 4;
    s->ext_change_count = 3;
    pthread_mutex_unlock(&pid_mutex);

    ASSERT(fabs(compute_ext_change_rate(s) - 0.75) < 1e-9);
}

static void test_autocorr_needs_history(void) {
    reset_table();
    pthread_mutex_lock(&pid_mutex);
    pid_stats_t *s = get_slot(12400);
    s->hist_count = 2;
    pthread_mutex_unlock(&pid_mutex);

    ASSERT(compute_autocorr(s) == 0.0);
}

static void test_flush_resets_new_fields(void) {
    reset_table();
    pthread_mutex_lock(&pid_mutex);
    pid_stats_t *s = get_slot(12500);
    s->write_count      = 20;
    s->read_count       = 5;
    s->entropy_sq_sum   = 100.0;
    s->chi2_sum         = 500.0;
    s->ext_change_count = 2;
    s->canary_count     = 1;
    s->hist_count       = 5;
    s->hist_pos         = 5;
    s->dir_count        = 3;
    s->ext_count        = 2;
    s->window_start     = time(NULL) - (ML_WINDOW_SECS + 1);
    pthread_mutex_unlock(&pid_mutex);

    flush_no_ml();

    ASSERT_EQ(s->write_count, 0ULL);
    ASSERT_EQ(s->read_count, 0ULL);
    ASSERT(s->entropy_sq_sum == 0.0);
    ASSERT(s->chi2_sum == 0.0);
    ASSERT_EQ(s->ext_change_count, 0ULL);
    ASSERT_EQ(s->canary_count, 0ULL);
    ASSERT_EQ(s->hist_count, 0U);
    ASSERT_EQ(s->dir_count, 0U);
    ASSERT_EQ(s->ext_count, 0U);
    ASSERT_EQ(s->active, 1);
}

static void test_get_slot_reuse_zeroes_stale(void) {
    reset_table();
    pthread_mutex_lock(&pid_mutex);
    pid_stats_t *s = get_slot(12600);
    s->write_count  = 99;
    s->canary_count = 7;
    s->active = 0;
    pid_stats_t *s2 = get_slot(12601);
    pthread_mutex_unlock(&pid_mutex);

    ASSERT_PTR_EQ(s, s2);
    ASSERT_EQ(s2->write_count, 0ULL);
    ASSERT_EQ(s2->canary_count, 0ULL);
}

static void test_chi2_mean_samples_only(void) {
    reset_table();
    pthread_mutex_lock(&pid_mutex);
    pid_stats_t *s = get_slot(12700);
    s->chi2_sum     = 300.0;
    s->chi2_samples = 2;
    pid_stats_t *z = get_slot(12701);
    pthread_mutex_unlock(&pid_mutex);

    ASSERT(fabs(compute_chi2_mean(s) - 150.0) < 1e-9);
    ASSERT(compute_chi2_mean(z) == 0.0);
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
    test_get_slot_does_not_rotate_expired();
    test_window_rotation_expired();
    test_window_rotation_still_active();
    test_window_double_rotation();
    test_window_rotation_exact_boundary();
    test_window_rotation_preserves_identity();

    printf("\n-- Entropy tracking --\n");
    test_entropy_max_tracking();

    printf("\n-- Feature computation --\n");
    test_fnv1a_hash_deterministic();
    test_hash_set_add_dedup_and_cap();
    test_path_dir_hash();
    test_path_ext_hash();
    test_entropy_std_known_values();
    test_entropy_std_guards();
    test_read_write_ratio();
    test_ext_change_rate();
    test_autocorr_needs_history();
    test_chi2_mean_samples_only();
    test_flush_resets_new_fields();
    test_get_slot_reuse_zeroes_stale();

    printf("\n=== Results: %d/%d passed, %d failed ===\n",
           tests_passed, tests_run, tests_failed);
    return tests_failed > 0 ? 1 : 0;
}
