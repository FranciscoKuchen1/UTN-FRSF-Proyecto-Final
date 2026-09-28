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
#include "entropy.h"
#include "analyzer.h"

/* External globals from guardian_fs.c */
extern struct ring_buf    *evbuf;
extern struct detector_ctx *detector;

#define ML_SOCKET_PATH    "/tmp/guardian_ml_proxy.sock"
#define ML_WINDOW_SECS    5
#define MAX_PID_SLOTS     128
#define ENTROPY_HIST_LEN  32   /* últimas entropías por PID (autocorr) */
#define HASH_TRACK_CAP    16   /* dirs/extensiones distintas por ventana */

/* ── Per-PID aggregation ── */
typedef struct {
    uint32_t pid;
    uint64_t write_count;
    uint64_t read_count;
    uint64_t total_bytes;
    double   entropy_sum;
    double   entropy_sq_sum;
    double   entropy_max;
    double   chi2_sum;
    uint32_t chi2_samples;
    uint64_t rename_count;
    uint64_t ext_change_count;
    uint64_t unlink_count;
    uint64_t canary_count;
    double   entropy_hist[ENTROPY_HIST_LEN];
    uint32_t hist_count;
    uint32_t hist_pos;
    uint64_t dir_hashes[HASH_TRACK_CAP];
    uint32_t dir_count;
    uint64_t ext_hashes[HASH_TRACK_CAP];
    uint32_t ext_count;
    time_t   window_start;
    int      active;
} pid_stats_t;

static pid_stats_t  pid_table[MAX_PID_SLOTS];
static pthread_mutex_t pid_mutex = PTHREAD_MUTEX_INITIALIZER;

static pid_stats_t *get_slot(uint32_t pid) {
    time_t now = time(NULL);

    /* Buscar slot existente */
    for (int i = 0; i < MAX_PID_SLOTS; i++) {
        if (pid_table[i].active && pid_table[i].pid == pid)
            return &pid_table[i];
    }

    /* Buscar slot libre */
    for (int i = 0; i < MAX_PID_SLOTS; i++) {
        if (!pid_table[i].active) {
            memset(&pid_table[i], 0, sizeof(pid_stats_t));
            pid_table[i].pid          = pid;
            pid_table[i].window_start = now;
            pid_table[i].active       = 1;
            return &pid_table[i];
        }
    }

    return NULL;  /* tabla llena */
}

/* ── Cálculo de features ── */
static uint64_t fnv1a_hash(const char *s, size_t len) {
    uint64_t h = 1469598103934665603ULL;
    for (size_t i = 0; i < len; i++) {
        h ^= (uint8_t)s[i];
        h *= 1099511628211ULL;
    }
    return h;
}

/* Set de hashes de capacidad fija; devuelve 1 si h es nuevo */
static int hash_set_add(uint64_t *set, uint32_t *count, uint64_t h) {
    if (h == 0) return 0;
    for (uint32_t i = 0; i < *count; i++)
        if (set[i] == h) return 0;
    if (*count >= HASH_TRACK_CAP) return 0;
    set[*count] = h;
    (*count)++;
    return 1;
}

static uint64_t path_dir_hash(const char *path) {
    const char *slash = strrchr(path, '/');
    if (!slash) return fnv1a_hash(".", 1);
    size_t len = (size_t)(slash - path);
    if (len == 0) return fnv1a_hash("/", 1);
    return fnv1a_hash(path, len);
}

static uint64_t path_ext_hash(const char *path) {
    const char *slash = strrchr(path, '/');
    const char *base  = slash ? slash + 1 : path;
    const char *dot   = strrchr(base, '.');
    if (!dot || dot == base) return 0;  /* sin extensión u oculto */
    return fnv1a_hash(dot, strlen(dot));
}

static double compute_entropy_std(const pid_stats_t *s) {
    if (s->write_count < 2) return 0.0;
    double n    = (double)s->write_count;
    double mean = s->entropy_sum / n;
    double var  = s->entropy_sq_sum / n - mean * mean;
    return var > 0.0 ? sqrt(var) : 0.0;
}

static double compute_autocorr(const pid_stats_t *s) {
    if (s->hist_count < 3) return 0.0;
    double tmp[ENTROPY_HIST_LEN];
    uint32_t n     = s->hist_count;
    uint32_t start = (n < ENTROPY_HIST_LEN) ? 0 : s->hist_pos;
    for (uint32_t i = 0; i < n; i++)
        tmp[i] = s->entropy_hist[(start + i) % ENTROPY_HIST_LEN];
    return entropy_autocorrelation(tmp, n);
}

static double compute_read_write_ratio(const pid_stats_t *s) {
    if (s->write_count == 0) return 0.0;
    return (double)s->read_count / (double)s->write_count;
}

static double compute_ext_change_rate(const pid_stats_t *s) {
    if (s->rename_count == 0) return 0.0;
    return (double)s->ext_change_count / (double)s->rename_count;
}

static double compute_chi2_mean(const pid_stats_t *s) {
    if (s->chi2_samples == 0) return 0.0;
    return s->chi2_sum / (double)s->chi2_samples;
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
    double entropy_std    = compute_entropy_std(s);
    double autocorr       = compute_autocorr(s);
    double write_rate     = s->write_count / window;
    double bytes_rate     = s->total_bytes / window;
    double rename_rate    = s->rename_count / window;
    double unlink_rate    = s->unlink_count / window;
    double rw_ratio       = compute_read_write_ratio(s);
    double chi2_mean      = compute_chi2_mean(s);
    double ext_change     = compute_ext_change_rate(s);
    int    canary         = s->canary_count > 0 ? 1 : 0;

    char json[2048];
    int len = snprintf(json, sizeof(json),
        "{"
        "\"pid\":%u,"
        "\"features\":{"
            "\"entropy_mean\":%.4f,"
            "\"entropy_max\":%.4f,"
            "\"entropy_std\":%.4f,"
            "\"entropy_autocorr\":%.4f,"
            "\"write_rate\":%.2f,"
            "\"bytes_written_rate\":%.2f,"
            "\"rename_rate\":%.2f,"
            "\"unlink_rate\":%.2f,"
            "\"read_write_ratio\":%.4f,"
            "\"chi2_stat\":%.4f,"
            "\"ext_change_rate\":%.4f,"
            "\"canary_accessed\":%d,"
            "\"unique_dirs\":%u,"
            "\"file_type_variety\":%u"
        "}}\n",
        pid,
        entropy_mean, s->entropy_max, entropy_std, autocorr,
        write_rate, bytes_rate, rename_rate, unlink_rate,
        rw_ratio, chi2_mean, ext_change, canary,
        s->dir_count, s->ext_count);

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

static void reset_window(pid_stats_t *s, time_t now) {
    uint32_t pid = s->pid;
    memset(s, 0, sizeof(*s));
    s->pid          = pid;
    s->window_start = now;
    s->active       = 1;
}

/* Rota ventanas expiradas por tiempo (no por eventos): envía features al
 * proxy ML antes de resetear. Así también se registran las features de
 * procesos ya matados por la mitigación.
 * PIDs cuya ventana venció sin actividad suficiente liberan su slot: sin
 * esto la tabla se llena con procesos muertos y las features ML se pierden
 * en silencio para siempre (incluido un atacante nuevo). */
static void flush_expired_windows(int *ml_fd) {
    time_t now = time(NULL);

    pthread_mutex_lock(&pid_mutex);
    for (int i = 0; i < MAX_PID_SLOTS; i++) {
        pid_stats_t *s = &pid_table[i];
        if (!s->active || now - s->window_start < ML_WINDOW_SECS)
            continue;

        if (s->write_count >= 10 && *ml_fd >= 0) {
            int verdict = ml_query(*ml_fd, s->pid, s);
            if (verdict < 0) {
                close(*ml_fd);
                *ml_fd = -1;
                fprintf(stderr, "[analyzer] ML connection lost — will reconnect\n");
            } else if (verdict == 2) {
                fprintf(stderr,
                        "[analyzer] ML verdict=ATTACK pid=%u — "
                        "confirming with detector\n", s->pid);
                detector_confirm_attack(detector, s->pid);
            }
        }
        if (s->write_count < 10)
            memset(s, 0, sizeof(*s));       /* active = 0 → slot libre */
        else
            reset_window(s, now);
    }
    pthread_mutex_unlock(&pid_mutex);
}

/* Reintenta la conexión cada 5s tanto en idle como bajo carga de eventos */
static int ml_ensure_connected(int ml_fd) {
    static time_t last_attempt = 0;

    if (ml_fd >= 0)
        return ml_fd;

    time_t now = time(NULL);
    if (now - last_attempt >= 5) {
        last_attempt = now;
        ml_fd = ml_connect();
        if (ml_fd >= 0)
            fprintf(stderr, "[analyzer] Reconnected to ML server\n");
    }
    return ml_fd;
}

/* ── Hilo principal de análisis ── */
void *analyzer_thread(void *arg) {
    (void)arg;
    io_event_t ev;
    int ml_fd = -1;

    fprintf(stderr, "[analyzer] Started, ML socket: %s\n", ML_SOCKET_PATH);

    /* Intentar conectar al ML server (reintentar cada 5s si falla) */
    ml_fd = ml_connect();
    if (ml_fd >= 0)
        fprintf(stderr, "[analyzer] Connected to ML server\n");
    else
        fprintf(stderr, "[analyzer] ML server not available — "
                        "using statistical rules only\n");

    while (1) {
        ml_fd = ml_ensure_connected(ml_fd);

        if (ring_buf_try_pop(evbuf, &ev) != 0) {
            flush_expired_windows(&ml_fd);
            usleep(50000);  /* 50 ms */
            continue;
        }

        /* Acumular estadísticas por PID */
        pthread_mutex_lock(&pid_mutex);
        pid_stats_t *s = get_slot(ev.pid);
        if (!s) {
            pthread_mutex_unlock(&pid_mutex);
            static uint64_t dropped = 0;
            if (++dropped == 1 || dropped % 1000 == 0)
                fprintf(stderr, "[analyzer] pid_table llena — "
                                "%llu eventos sin features (total)\n",
                        (unsigned long long)dropped);
            continue;
        }

        switch (ev.type) {
        case EV_READ:
            s->read_count++;
            break;
        case EV_WRITE:
            s->write_count++;
            s->total_bytes += ev.size;
            s->entropy_sum += ev.entropy;
            s->entropy_sq_sum += ev.entropy * ev.entropy;
            if (ev.entropy > s->entropy_max)
                s->entropy_max = ev.entropy;
            if (ev.chi2 > 0.0) {
                s->chi2_sum += ev.chi2;
                s->chi2_samples++;
            }
            s->entropy_hist[s->hist_pos] = ev.entropy;
            s->hist_pos = (s->hist_pos + 1) % ENTROPY_HIST_LEN;
            if (s->hist_count < ENTROPY_HIST_LEN)
                s->hist_count++;
            hash_set_add(s->dir_hashes, &s->dir_count, path_dir_hash(ev.path));
            hash_set_add(s->ext_hashes, &s->ext_count, path_ext_hash(ev.path));
            break;
        case EV_RENAME:
            s->rename_count++;
            if (ev.ext_changed)
                s->ext_change_count++;
            hash_set_add(s->dir_hashes, &s->dir_count, path_dir_hash(ev.path));
            hash_set_add(s->ext_hashes, &s->ext_count, path_ext_hash(ev.path));
            break;
        case EV_UNLINK:
            s->unlink_count++;
            break;
        case EV_CANARY:
            s->canary_count++;
            break;
        }

        pthread_mutex_unlock(&pid_mutex);

        flush_expired_windows(&ml_fd);
    }

    if (ml_fd >= 0) close(ml_fd);
    return NULL;
}
