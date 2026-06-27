/* test_canary.c — Unit tests for canary module
 * Compile with: gcc -std=c17 -Wall -Wextra test_canary.c ../src/canary.c \
 *               -I../include -o test_canary
 *
 * Uses mkdtemp() for temporary directories. No root or filesystem privileges needed.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/stat.h>
#include "canary.h"

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

/* Helper: count files in a directory (non-recursive, skips '.' and '..') */
static int count_files_in(const char *dirpath) {
    DIR *d = opendir(dirpath);
    if (!d) return -1;
    int count = 0;
    struct dirent *entry;
    while ((entry = readdir(d)) != NULL) {
        /* Skip only the directory entries, not hidden files */
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
            continue;
        count++;
    }
    closedir(d);
    return count;
}

/* Helper: recursively remove directory */
static void rm_rf(const char *path) {
    char cmd[512];
    snprintf(cmd, sizeof(cmd), "rm -rf %s", path);
    system(cmd);
}

/* ---------------------------------------------------------------- */

static void test_init(void) {
    char template[] = "/tmp/canary_test_XXXXXX";
    char *tmpdir = mkdtemp(template);
    ASSERT(tmpdir != NULL);

    struct canary_ctx *ctx = canary_init(tmpdir);
    ASSERT(ctx != NULL);

    rm_rf(tmpdir);
    free(ctx);
}

static void test_canary_is_canary_true(void) {
    char template[] = "/tmp/canary_test_XXXXXX";
    char *tmpdir = mkdtemp(template);
    ASSERT(tmpdir != NULL);

    struct canary_ctx *ctx = canary_init(tmpdir);
    ASSERT(ctx != NULL);

    canary_deploy(ctx, 3);

    /* After deploy, we should be able to check if a deployed file is a canary.
     * The is_canary function matches fuse_path against the relative path from root.
     * In canary_deploy, paths are stored as abs: tmpdir/CANARY_NAME.
     * is_canary checks: stored_path + strlen(root) == fuse_path */
    int found = canary_is_canary(ctx, "/A_important_report.docx");
    ASSERT(found == 1);

    int found2 = canary_is_canary(ctx, "/ZZ_backup_keys.txt");
    ASSERT(found2 == 1);

    rm_rf(tmpdir);
    free(ctx);
}

static void test_canary_is_canary_false(void) {
    char template[] = "/tmp/canary_test_XXXXXX";
    char *tmpdir = mkdtemp(template);
    ASSERT(tmpdir != NULL);

    struct canary_ctx *ctx = canary_init(tmpdir);
    ASSERT(ctx != NULL);

    canary_deploy(ctx, 2);

    /* A file we never deployed should NOT be recognized as a canary */
    int found = canary_is_canary(ctx, "/some_random_file.txt");
    ASSERT(found == 0);

    int found2 = canary_is_canary(ctx, "/totally_not_a_canary.jpg");
    ASSERT(found2 == 0);

    rm_rf(tmpdir);
    free(ctx);
}

static void test_deploy_count(void) {
    char template[] = "/tmp/canary_test_XXXXXX";
    char *tmpdir = mkdtemp(template);
    ASSERT(tmpdir != NULL);

    struct canary_ctx *ctx = canary_init(tmpdir);
    ASSERT(ctx != NULL);

    canary_deploy(ctx, 5);

    /* Verify N files exist on disk */
    int count = count_files_in(tmpdir);
    ASSERT(count == 5);

    rm_rf(tmpdir);
    free(ctx);
}

/* ---------------------------------------------------------------- */

int main(void) {
    printf("=== Canary Unit Tests ===\n\n");

    test_init();
    test_canary_is_canary_true();
    test_canary_is_canary_false();
    test_deploy_count();

    printf("\n=== Results: %d/%d passed, %d failed ===\n",
           tests_passed, tests_run, tests_failed);
    return tests_failed > 0 ? 1 : 0;
}
