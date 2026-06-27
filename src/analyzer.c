#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <pthread.h>
#include "ring_buffer.h"
#include "detector.h"
#include "analyzer.h"

/* External globals from guardian_fs.c */
extern struct ring_buf    *evbuf;
extern struct detector_ctx *detector;

#define ML_SOCKET_PATH "/tmp/guardian_ml.sock"

static int __attribute__((unused)) ml_connect(void) {
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, ML_SOCKET_PATH, sizeof(addr.sun_path) - 1);
    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(fd);
        return -1;
    }
    return fd;
}

void *analyzer_thread(void *arg) {
    (void)arg;
    io_event_t ev;
    fprintf(stderr, "[analyzer] Started, consuming ring buffer events\n");

    while (1) {
        if (ring_buf_pop(evbuf, &ev) != 0) {
            usleep(100000);
            continue;
        }

        /* Log event — ML integration via Unix socket comes later */
        fprintf(stderr, "[analyzer] event type=%d pid=%u path=%s\n",
                ev.type, ev.pid, ev.path);
    }
    return NULL;
}
