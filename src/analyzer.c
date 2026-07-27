#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <math.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/select.h>
#include <pthread.h>
#include "ring_buffer.h"
#include "detector.h"
#include "analyzer.h"

/* External globals from guardian_fs.c */
extern struct ring_buf    *evbuf;
extern struct detector_ctx *detector;

#define ML_SOCKET_PATH    "/tmp/guardian_ml.sock"
#define ML_WINDOW_SECS    5
#define MAX_PID_SLOTS     128

/* ── Per-PID aggregation ── */
typedef struct {
    uint32_t pid;
    uint64_t write_count;
    uint64_t total_bytes;
    double   entropy_sum;
    double   entropy_max;
    uint64_t rename_count;
    uint64_t unlink_count;
    time_t   window_start;
    int      active;
} pid_stats_t;

static pid_stats_t  pid_table[MAX_PID_SLOTS];
static pthread_mutex_t pid_mutex = PTHREAD_MUTEX_INITIALIZER;

static pid_stats_t *get_slot(uint32_t pid) {
    time_t now = time(NULL);

    /* Buscar slot existente */
    for (int i = 0; i < MAX_PID_SLOTS; i++) {
        if (pid_table[i].active && pid_table[i].pid == pid) {
            /* Rotar ventana si expiró */
            if (now - pid_table[i].window_start >= ML_WINDOW_SECS) {
                pid_table[i].window_start = now;
                pid_table[i].write_count   = 0;
                pid_table[i].total_bytes   = 0;
                pid_table[i].entropy_sum   = 0.0;
                pid_table[i].entropy_max   = 0.0;
                pid_table[i].rename_count  = 0;
                pid_table[i].unlink_count  = 0;
            }
            return &pid_table[i];
        }
    }

    /* Buscar slot libre */
    for (int i = 0; i < MAX_PID_SLOTS; i++) {
        if (!pid_table[i].active) {
            pid_table[i].pid          = pid;
            pid_table[i].window_start = now;
            pid_table[i].active       = 1;
            return &pid_table[i];
        }
    }

    return NULL;  /* tabla llena */
}

/* ── Conexión al servidor ML ── */
static int ml_connect(void) {
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

/* ── Enviar features y recibir veredicto ── */
static int ml_query(int fd, uint32_t pid, const pid_stats_t *s) {
    double window = ML_WINDOW_SECS;
    double entropy_mean   = s->write_count ? s->entropy_sum / s->write_count : 0.0;
    double write_rate     = s->write_count / window;
    double bytes_rate     = s->total_bytes / window;
    double rename_rate    = s->rename_count / window;
    double unlink_rate    = s->unlink_count / window;

    char json[2048];
    int len = snprintf(json, sizeof(json),
        "{"
        "\"pid\":%u,"
        "\"features\":{"
            "\"entropy_mean\":%.4f,"
            "\"entropy_max\":%.4f,"
            "\"entropy_std\":0.0,"
            "\"entropy_autocorr\":0.0,"
            "\"write_rate\":%.2f,"
            "\"bytes_written_rate\":%.2f,"
            "\"rename_rate\":%.2f,"
            "\"unlink_rate\":%.2f,"
            "\"read_write_ratio\":0.0,"
            "\"chi2_stat\":0.0,"
            "\"ext_change_rate\":0.0,"
            "\"canary_accessed\":0,"
            "\"unique_dirs\":1,"
            "\"file_type_variety\":1"
        "}}\n",
        pid,
        entropy_mean, s->entropy_max,
        write_rate, bytes_rate,
        rename_rate, unlink_rate);

    if (write(fd, json, len) < 0) return -1;

    /* Leer respuesta (non-blocking con timeout implícito vía select) */
    char resp[1024];
    fd_set fds;
    struct timeval tv = { .tv_sec = 1, .tv_usec = 0 };
    FD_ZERO(&fds);
    FD_SET(fd, &fds);

    if (select(fd + 1, &fds, NULL, NULL, &tv) <= 0) return -1;

    ssize_t n = read(fd, resp, sizeof(resp) - 1);
    if (n <= 0) return -1;
    resp[n] = '\0';

    /* Parsear veredicto: buscar "verdict":"attack" */
    if (strstr(resp, "\"verdict\":\"attack\""))
        return 2;   /* VERDICT_BLOCK */
    if (strstr(resp, "\"verdict\":\"suspicious\""))
        return 1;   /* VERDICT_SUSPICIOUS */
    return 0;       /* VERDICT_NORMAL */
}

/* ── Hilo principal de análisis ── */
void *analyzer_thread(void *arg) {
    (void)arg;
    io_event_t ev;
    int ml_fd = -1;
    time_t last_ml_attempt = 0;

    fprintf(stderr, "[analyzer] Started, ML socket: %s\n", ML_SOCKET_PATH);

    /* Intentar conectar al ML server (reintentar cada 5s si falla) */
    ml_fd = ml_connect();
    if (ml_fd >= 0)
        fprintf(stderr, "[analyzer] Connected to ML server\n");
    else
        fprintf(stderr, "[analyzer] ML server not available — "
                        "using statistical rules only\n");

    while (1) {
        if (ring_buf_try_pop(evbuf, &ev) != 0) {
            /* Sin eventos: dormir y reintentar conexión ML si se cayó */
            if (ml_fd < 0) {
                time_t now = time(NULL);
                if (now - last_ml_attempt >= 5) {
                    ml_fd = ml_connect();
                    last_ml_attempt = now;
                    if (ml_fd >= 0)
                        fprintf(stderr, "[analyzer] Reconnected to ML server\n");
                }
            }
            usleep(50000);  /* 50 ms */
            continue;
        }

        /* Acumular estadísticas por PID */
        pthread_mutex_lock(&pid_mutex);
        pid_stats_t *s = get_slot(ev.pid);
        if (!s) {
            pthread_mutex_unlock(&pid_mutex);
            continue;
        }

        switch (ev.type) {
        case EV_WRITE:
            s->write_count++;
            s->total_bytes += ev.size;
            s->entropy_sum += ev.entropy;
            if (ev.entropy > s->entropy_max)
                s->entropy_max = ev.entropy;
            break;
        case EV_RENAME:
            s->rename_count++;
            break;
        case EV_UNLINK:
            s->unlink_count++;
            break;
        }

        /* ¿Ventana llena? Evaluar vía ML */
        time_t now = time(NULL);
        int window_done = (now - s->window_start >= ML_WINDOW_SECS);

        if (window_done && s->write_count >= 10 && ml_fd >= 0) {
            int verdict = ml_query(ml_fd, ev.pid, s);

            /* Resetear ventana */
            s->window_start = now;
            s->write_count  = 0;
            s->total_bytes  = 0;
            s->entropy_sum  = 0.0;
            s->entropy_max  = 0.0;
            s->rename_count = 0;
            s->unlink_count = 0;

            if (verdict == 2) {
                fprintf(stderr,
                        "[analyzer] ML verdict=ATTACK pid=%u — "
                        "confirming with detector\n", ev.pid);
                detector_confirm_attack(detector, ev.pid);
            }
        } else if (window_done && s->write_count >= 10) {
            /* Sin ML: rotar ventana igual */
            s->window_start = now;
            s->write_count  = 0;
            s->total_bytes  = 0;
            s->entropy_sum  = 0.0;
            s->entropy_max  = 0.0;
            s->rename_count = 0;
            s->unlink_count = 0;
        }

        pthread_mutex_unlock(&pid_mutex);
    }

    if (ml_fd >= 0) close(ml_fd);
    return NULL;
}
