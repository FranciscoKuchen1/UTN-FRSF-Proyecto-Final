#define _GNU_SOURCE
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include "ring_buffer.h"

struct ring_buf {
    io_event_t     *events;
    size_t          capacity;
    size_t          head;
    size_t          tail;
    size_t          count;
    pthread_mutex_t lock;
    pthread_cond_t  not_empty;
    pthread_cond_t  not_full;
};

struct ring_buf *ring_buf_create(size_t capacity, size_t elem_size) {
    (void)elem_size; /* preserved for API compatibility — always io_event_t */
    struct ring_buf *rb = malloc(sizeof(*rb));
    if (!rb) return NULL;
    rb->events = malloc(capacity * sizeof(io_event_t));
    if (!rb->events) { free(rb); return NULL; }
    rb->capacity = capacity;
    rb->head = 0;
    rb->tail = 0;
    rb->count = 0;
    pthread_mutex_init(&rb->lock, NULL);
    pthread_cond_init(&rb->not_empty, NULL);
    pthread_cond_init(&rb->not_full, NULL);
    return rb;
}

int ring_buf_push(struct ring_buf *rb, const io_event_t *ev) {
    pthread_mutex_lock(&rb->lock);
    while (rb->count == rb->capacity)
        pthread_cond_wait(&rb->not_full, &rb->lock);
    memcpy(&rb->events[rb->head], ev, sizeof(io_event_t));
    rb->head = (rb->head + 1) % rb->capacity;
    rb->count++;
    pthread_cond_signal(&rb->not_empty);
    pthread_mutex_unlock(&rb->lock);
    return 0;
}

int ring_buf_pop(struct ring_buf *rb, io_event_t *ev) {
    pthread_mutex_lock(&rb->lock);
    while (rb->count == 0)
        pthread_cond_wait(&rb->not_empty, &rb->lock);
    memcpy(ev, &rb->events[rb->tail], sizeof(io_event_t));
    rb->tail = (rb->tail + 1) % rb->capacity;
    rb->count--;
    pthread_cond_signal(&rb->not_full);
    pthread_mutex_unlock(&rb->lock);
    return 0;
}

void ring_buf_destroy(struct ring_buf *rb) {
    if (!rb) return;
    free(rb->events);
    pthread_mutex_destroy(&rb->lock);
    pthread_cond_destroy(&rb->not_empty);
    pthread_cond_destroy(&rb->not_full);
    free(rb);
}
