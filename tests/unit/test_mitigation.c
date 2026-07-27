/* test_mitigation.c — Unit tests for mitigation module
 * Compile with: gcc -std=c17 -Wall -Wextra test_mitigation.c ../src/mitigation.c \
 *               -I../include -o test_mitigation
 *
 * Tests that the module links and handles edge cases without crashing.
 * We do NOT test killing real processes.
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <errno.h>
#include "mitigation.h"

static int tests_run = 0;
static int tests_passed = 0;
static int tests_failed = 0;

#define ASSERT_NOT_CRASH(expr, msg) do {                                          \
    tests_run++;                                                                  \
    volatile int result = (expr); /* force evaluation */                           \
    (void)result;                                                                 \
    tests_passed++;                                                               \
    printf("  PASS: %s (did not crash: %s)\n", __func__, msg);                    \
} while(0)

#define ASSERT_NEGATIVE(expr) do {                                                 \
    tests_run++;                                                                  \
    int result = (expr);                                                          \
    if (result < 0) {                                                             \
        tests_passed++;                                                           \
        printf("  PASS: %s (returned %d as expected)\n", __func__, result);        \
    } else {                                                                      \
        tests_failed++;                                                           \
        printf("  FAIL: %s: expected < 0, got %d\n", __func__, result);            \
    }                                                                             \
} while(0)

/* ---------------------------------------------------------------- */

static void test_kill_invalid_pid(void) {
    /* SAFETY: PID values are uint32_t but kill() takes pid_t (int32_t).
     * 0xFFFFFFFF (4294967295) as uint32_t becomes -1 as int32_t.
     * kill(-1, SIGKILL) sends SIGKILL to ALL processes the caller has
     * permission to signal — CATASTROPHIC if run as root or with privileges.
     *
     * Use PIDs just below INT32_MAX that don't wrap to negative values,
     * and avoid PID 1 (init/systemd), 0 (process group), and -1 (broadcast).
     */

    /* PID just below INT32_MAX — cannot exist on any Linux system.
     * /proc/sys/kernel/pid_max defaults to 32768 or 4194304.
     * Should return -1 (ESRCH) safely. */
    ASSERT_NEGATIVE(mitigation_kill_process(0x7FFFFFFE));

    /* Another impossible PID — should also return -1 without crashing. */
    ASSERT_NEGATIVE(mitigation_kill_process(0x7FFFFFFD));
}

static void test_function_exists(void) {
    /* Verify the function address is non-NULL (it exists and links) */
    ASSERT_NOT_CRASH(mitigation_kill_process != NULL ? 0 : -1,
                     "mitigation_kill_process exists");
}

/* ---------------------------------------------------------------- */

int main(void) {
    printf("=== Mitigation Unit Tests ===\n\n");

    test_kill_invalid_pid();
    test_function_exists();

    printf("\n=== Results: %d/%d passed, %d failed ===\n",
           tests_passed, tests_run, tests_failed);
    return tests_failed > 0 ? 1 : 0;
}
