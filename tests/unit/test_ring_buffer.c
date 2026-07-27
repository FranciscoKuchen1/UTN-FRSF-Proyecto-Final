/* test_ring_buffer.c — Unit tests for ring buffer module
 * Compile with: gcc -std=c17 -Wall -Wextra test_ring_buffer.c ../src/ring_buffer.c \
 *               -I../include -lpthread -o test_ring_buffer
 *
 * Tests use non-blocking paths only (push when not full, pop when not empty).
 * Blocking behavior (push on full, pop on empty) is not tested here.
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "ring_buffer.h"

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

/* ---------------------------------------------------------------- */

static void test_create_destroy(void) {
    struct ring_buf *rb = ring_buf_create(16, sizeof(io_event_t));
    ASSERT(rb != NULL);
    ring_buf_destroy(rb);
}

static void test_push_pop_single(void) {
    struct ring_buf *rb = ring_buf_create(8, sizeof(io_event_t));
    ASSERT(rb != NULL);

    io_event_t in = {
        .type     = EV_WRITE,
        .pid      = 1234,
        .path     = "/tmp/test.txt",
        .entropy  = 7.2,
        .size     = 4096,
        .ts_ns    = 1000000000,
        .ext_changed = 0,
    };

    int ret = ring_buf_push(rb, &in);
    ASSERT(ret == 0);

    io_event_t out;
    memset(&out, 0, sizeof(out));
    ret = ring_buf_pop(rb, &out);
    ASSERT(ret == 0);

    ASSERT(out.type == EV_WRITE);
    ASSERT(out.pid == 1234);
    ASSERT(strcmp(out.path, "/tmp/test.txt") == 0);
    /* entropy as double is bit-exact after memcpy */
    ASSERT(out.entropy == 7.2);
    ASSERT(out.size == 4096);
    ASSERT(out.ts_ns == 1000000000);

    ring_buf_destroy(rb);
}

static void test_push_pop_fifo(void) {
    struct ring_buf *rb = ring_buf_create(8, sizeof(io_event_t));
    ASSERT(rb != NULL);

    io_event_t events[3];
    for (int i = 0; i < 3; i++) {
        memset(&events[i], 0, sizeof(events[i]));
        events[i].type = EV_WRITE;
        events[i].pid  = (uint32_t)(100 + i);
        snprintf(events[i].path, sizeof(events[i].path),
                 "/tmp/file_%d.txt", i);
        events[i].entropy = 4.0 + (double)i;
        int ret = ring_buf_push(rb, &events[i]);
        ASSERT(ret == 0);
    }

    /* Pop in FIFO order */
    for (int i = 0; i < 3; i++) {
        io_event_t out;
        memset(&out, 0, sizeof(out));
        int ret = ring_buf_pop(rb, &out);
        ASSERT(ret == 0);
        ASSERT(out.pid == (uint32_t)(100 + i));

        char expected_path[4096];
        snprintf(expected_path, sizeof(expected_path), "/tmp/file_%d.txt", i);
        ASSERT(strcmp(out.path, expected_path) == 0);
    }

    ring_buf_destroy(rb);
}

static void test_full_buffer(void) {
    /* Fill to capacity — all pushes should succeed since we never exceed it */
    size_t cap = 4;
    struct ring_buf *rb = ring_buf_create(cap, sizeof(io_event_t));
    ASSERT(rb != NULL);

    for (size_t i = 0; i < cap; i++) {
        io_event_t ev = {
            .type = EV_WRITE,
            .pid  = (uint32_t)i,
            .path = "",
            .entropy = 0.0,
            .size = 0,
            .ts_ns = i,
        };
        int ret = ring_buf_push(rb, &ev);
        ASSERT(ret == 0);
    }

    /* Pop them all back — order must be preserved */
    for (size_t i = 0; i < cap; i++) {
        io_event_t out;
        int ret = ring_buf_pop(rb, &out);
        ASSERT(ret == 0);
        ASSERT(out.pid == (uint32_t)i);
        ASSERT(out.ts_ns == i);
    }

    ring_buf_destroy(rb);
}

static void test_wrap_around(void) {
    /* Capacity 3: push A,B,C, pop A,B, push D,E, pop C,D,E
     * This forces head and tail to wrap around mod capacity. */
    struct ring_buf *rb = ring_buf_create(3, sizeof(io_event_t));
    ASSERT(rb != NULL);

    /* Push A, B, C */
    for (int i = 0; i < 3; i++) {
        io_event_t ev = { .type = EV_WRITE, .pid = (uint32_t)(10 + i), .path = "" };
        snprintf(ev.path, sizeof(ev.path), "E%d", i);
        ring_buf_push(rb, &ev);
    }

    /* Pop A, B */
    for (int i = 0; i < 2; i++) {
        io_event_t out;
        ring_buf_pop(rb, &out);
        ASSERT(out.pid == (uint32_t)(10 + i));
    }

    /* Push D, E */
    for (int i = 3; i < 5; i++) {
        io_event_t ev = { .type = EV_WRITE, .pid = (uint32_t)(10 + i), .path = "" };
        snprintf(ev.path, sizeof(ev.path), "E%d", i);
        ring_buf_push(rb, &ev);
    }

    /* Pop C, D, E — must be FIFO */
    for (int i = 2; i < 5; i++) {
        io_event_t out;
        ring_buf_pop(rb, &out);
        ASSERT(out.pid == (uint32_t)(10 + i));
    }

    ring_buf_destroy(rb);
}

/* ---------------------------------------------------------------- */

int main(void) {
    printf("=== Ring Buffer Unit Tests ===\n\n");

    test_create_destroy();
    test_push_pop_single();
    test_push_pop_fifo();
    test_full_buffer();
    test_wrap_around();

    printf("\n=== Results: %d/%d passed, %d failed ===\n",
           tests_passed, tests_run, tests_failed);
    return tests_failed > 0 ? 1 : 0;
}
