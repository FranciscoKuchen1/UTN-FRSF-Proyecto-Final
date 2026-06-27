#ifndef RING_BUFFER_H
#define RING_BUFFER_H

#include <stdint.h>
#include <stddef.h>

#define EV_READ   1
#define EV_WRITE  2
#define EV_RENAME 3
#define EV_UNLINK 4

typedef struct {
    int       type;
    uint32_t  pid;
    char      path[4096];
    double    entropy;
    uint64_t  size;
    uint64_t  ts_ns;
    int       ext_changed;
} io_event_t;

/* Opaque circular buffer */
struct ring_buf;

struct ring_buf *ring_buf_create(size_t capacity, size_t elem_size);
int ring_buf_push(struct ring_buf *rb, const io_event_t *ev);
int ring_buf_pop(struct ring_buf *rb, io_event_t *ev);
void ring_buf_destroy(struct ring_buf *rb);

#endif /* RING_BUFFER_H */
