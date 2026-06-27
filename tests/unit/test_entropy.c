/* test_entropy.c — Unit tests for entropy module
 * Compile with: gcc -std=c17 -Wall -Wextra test_entropy.c ../src/entropy.c -I../include -lm -o test_entropy
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <math.h>
#include "entropy.h"

static int tests_run = 0;
static int tests_passed = 0;
static int tests_failed = 0;

#define ASSERT_FLOAT_EQ(actual, expected, tol) do {                              \
    tests_run++;                                                                  \
    double a = (actual);                                                           \
    double e = (expected);                                                         \
    if (fabs(a - e) <= (tol)) {                                                   \
        tests_passed++;                                                           \
        printf("  PASS: %s (%.4f ~= %.4f)\n", __func__, a, e);                    \
    } else {                                                                      \
        tests_failed++;                                                           \
        printf("  FAIL: %s: got %.4f, expected %.4f (tol=%.4f)\n",               \
               __func__, a, e, tol);                                              \
    }                                                                             \
} while(0)

#define ASSERT_TRUE(expr) do {                                                    \
    tests_run++;                                                                  \
    if (expr) {                                                                   \
        tests_passed++;                                                           \
        printf("  PASS: %s\n", __func__);                                         \
    } else {                                                                      \
        tests_failed++;                                                           \
        printf("  FAIL: %s: %s\n", __func__, #expr);                              \
    }                                                                             \
} while(0)

#define ASSERT_NOT_NULL(ptr) do {                                                 \
    tests_run++;                                                                  \
    if ((ptr) != NULL) {                                                          \
        tests_passed++;                                                           \
        printf("  PASS: %s\n", __func__);                                         \
    } else {                                                                      \
        tests_failed++;                                                           \
        printf("  FAIL: %s: expected non-NULL pointer\n", __func__);              \
    }                                                                             \
} while(0)

#define ASSERT_NULL(ptr) do {                                                     \
    tests_run++;                                                                  \
    if ((ptr) == NULL) {                                                          \
        tests_passed++;                                                           \
        printf("  PASS: %s\n", __func__);                                         \
    } else {                                                                      \
        tests_failed++;                                                           \
        printf("  FAIL: %s: expected NULL pointer\n", __func__);                  \
    }                                                                             \
} while(0)

/* ---------------------------------------------------------------- */

static void test_shannon_uniform(void) {
    /* Buffer with bytes 0..255 exactly once → entropy = 8.0 */
    uint8_t buf[256];
    for (int i = 0; i < 256; i++) buf[i] = (uint8_t)i;
    double H = entropy_shannon(buf, 256);
    ASSERT_FLOAT_EQ(H, 8.0, 0.01);
}

static void test_shannon_constant(void) {
    /* All same byte → entropy = 0.0 */
    uint8_t buf[256];
    memset(buf, 0xAB, sizeof(buf));
    double H = entropy_shannon(buf, 256);
    ASSERT_FLOAT_EQ(H, 0.0, 0.001);
}

static void test_shannon_empty(void) {
    /* Empty buffer → entropy = 0.0 */
    double H = entropy_shannon(NULL, 0);
    ASSERT_FLOAT_EQ(H, 0.0, 0.001);
}

static void test_chi_square_uniform(void) {
    /* Uniform distribution → chi² ≈ 0 (well below 300) */
    uint8_t buf[256];
    for (int i = 0; i < 256; i++) buf[i] = (uint8_t)i;
    double chi2 = entropy_chi_square(buf, 256);
    ASSERT_FLOAT_EQ(chi2, 0.0, 0.01);
}

static void test_chi_square_skewed(void) {
    /* All same byte → chi² extremely high */
    uint8_t buf[512];
    memset(buf, 0x42, sizeof(buf));
    double chi2 = entropy_chi_square(buf, 512);
    /* expected = 512/256 = 2.0
     * One bucket: obs=512, diff=510, chi2 contrib = 510^2/2 = 130050
     * 255 buckets: obs=0, diff=-2, chi2 contrib = 4/2 = 2 each = 510
     * Total ~= 130560 */
    ASSERT_TRUE(chi2 > 100000.0);
}

static void test_sliding_window(void) {
    uint8_t buf[1024];
    memset(buf, 0x00, sizeof(buf));

    size_t n_blocks = 0;
    double *windows = entropy_sliding_window(buf, sizeof(buf), 512, &n_blocks);

    ASSERT_NOT_NULL(windows);
    ASSERT_TRUE(n_blocks == 2);
    /* Both blocks are all zeros → entropy = 0.0 */
    ASSERT_FLOAT_EQ(windows[0], 0.0, 0.001);
    ASSERT_FLOAT_EQ(windows[1], 0.0, 0.001);
    free(windows);
}

static void test_autocorrelation(void) {
    /* Known sequence: [1.0, 2.0, 3.0, 4.0]
     * mean = 2.5
     * num = (-1.5)*(-0.5) + (-0.5)*(0.5) + (0.5)*(1.5) = 0.75 - 0.25 + 0.75 = 1.25
     * den = 2.25 + 0.25 + 0.25 = 2.75
     * corr = 1.25 / 2.75 ≈ 0.4545 */
    double H[] = {1.0, 2.0, 3.0, 4.0};
    double corr = entropy_autocorrelation(H, 4);
    ASSERT_FLOAT_EQ(corr, 0.454545, 0.001);
}

static void test_chi2_from_hist(void) {
    /* Uniform histogram with 256 entries → expected=1, chi²=0 */
    uint64_t hist[256];
    for (int i = 0; i < 256; i++) hist[i] = 1;
    double chi2 = entropy_chi2_from_hist(hist, 256);
    ASSERT_FLOAT_EQ(chi2, 0.0, 0.01);
}

static void test_chi2_from_hist_empty(void) {
    /* total=0 → returns 0 */
    uint64_t hist[256] = {0};
    double chi2 = entropy_chi2_from_hist(hist, 0);
    ASSERT_FLOAT_EQ(chi2, 0.0, 0.001);
}

/* ---------------------------------------------------------------- */

int main(void) {
    printf("=== Entropy Unit Tests ===\n\n");

    test_shannon_uniform();
    test_shannon_constant();
    test_shannon_empty();
    test_chi_square_uniform();
    test_chi_square_skewed();
    test_sliding_window();
    test_autocorrelation();
    test_chi2_from_hist();
    test_chi2_from_hist_empty();

    printf("\n=== Results: %d/%d passed, %d failed ===\n",
           tests_passed, tests_run, tests_failed);
    return tests_failed > 0 ? 1 : 0;
}
