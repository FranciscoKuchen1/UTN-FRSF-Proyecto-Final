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
#include "detector.h"
#include "entropy.h"

static inline uint64_t clock_gettime_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

/* Estado por proceso */
typedef struct {
    uint32_t  pid;
    uint64_t  write_count;       /* escrituras en ventana actual   */
    uint64_t  bytes_written;
    uint64_t  rename_count;
    uint64_t  unlink_count;
    uint64_t  read_count;
    uint64_t  bytes_read;
    double    entropy_sum;       /* para media móvil               */
    double    entropy_max;
    uint64_t  entropy_samples;
    int       canary_triggered;
    int       ext_change_count;
    double    score;             /* puntuación de riesgo agregada  */
    uint64_t  window_start_ns;
    /* histograma de bytes para χ² acumulado */
    uint64_t  byte_hist[256];
    uint64_t  byte_hist_total;
    int       verdict;           /* VERDICT_NORMAL / BLOCK        */
    int       attack_confirmed;  /* set by detector_confirm_attack */
} pid_state_t;

struct detector_ctx {
    pid_state_t **pids;
    size_t        n_pids;
    pthread_mutex_t lock;
    /* umbrales */
    double   entropy_thresh;
    uint64_t write_rate_thresh;
    uint64_t rename_thresh;
    uint32_t window_secs;
    /* pesos para scoring */
    double w_entropy;    /* peso entropía           */
    double w_write;      /* peso tasa escrituras    */
    double w_rename;     /* peso tasa renombrados   */
    double w_chi2;       /* peso test χ²            */
    double w_rw_ratio;   /* peso ratio read/write   */
    double score_thresh; /* umbral score → bloqueo  */
    double warn_threshold; /* umbral score → sospechoso */
};

struct detector_ctx *detector_init(uint32_t window_secs,
                                    double entropy_thresh,
                                    uint64_t write_thresh,
                                    uint64_t rename_thresh) {
    struct detector_ctx *ctx = calloc(1, sizeof(*ctx));
    ctx->window_secs      = window_secs;
    ctx->entropy_thresh   = entropy_thresh;
    ctx->write_rate_thresh= write_thresh;
    ctx->rename_thresh    = rename_thresh;
    /* Pesos calibrados experimentalmente */
    ctx->w_entropy   = 0.35;
    ctx->w_write     = 0.20;
    ctx->w_rename    = 0.15;
    ctx->w_chi2      = 0.20;
    ctx->w_rw_ratio  = 0.10;
    ctx->score_thresh= 0.65;   /* 65% → alerta */
    ctx->warn_threshold = 0.45; /* 45% → sospechoso */
    pthread_mutex_init(&ctx->lock, NULL);
    return ctx;
}

static pid_state_t *get_or_create_pid(struct detector_ctx *ctx,
                                       uint32_t pid) {
    for (size_t i = 0; i < ctx->n_pids; i++)
        if (ctx->pids[i]->pid == pid) return ctx->pids[i];

    ctx->pids = realloc(ctx->pids,
                        (ctx->n_pids + 1) * sizeof(pid_state_t *));
    pid_state_t *s = calloc(1, sizeof(pid_state_t));
    s->pid = pid;
    s->window_start_ns = clock_gettime_ns();
    ctx->pids[ctx->n_pids++] = s;
    return s;
}

/* Rota ventana si han pasado más de window_secs */
static void maybe_rotate_window(struct detector_ctx *ctx,
                                 pid_state_t *s) {
    uint64_t now = clock_gettime_ns();
    uint64_t elapsed = now - s->window_start_ns;
    if (elapsed >= (uint64_t)ctx->window_secs * 1000000000ULL) {
        s->write_count      = 0;
        s->bytes_written    = 0;
        s->rename_count     = 0;
        s->unlink_count     = 0;
        s->read_count       = 0;
        s->bytes_read       = 0;
        s->entropy_sum      = 0.0;
        s->entropy_samples  = 0;
        s->ext_change_count = 0;
        memset(s->byte_hist, 0, sizeof(s->byte_hist));
        s->byte_hist_total  = 0;
        s->window_start_ns  = now;
    }
}

/*
 * Función de scoring ponderada.
 * Cada característica se normaliza a [0,1] y se combina linealmente.
 * Extensible con más señales sin cambiar la interfaz.
 */
static double compute_score(struct detector_ctx *ctx, pid_state_t *s) {
    double score = 0.0;

    /* 1. Entropía media normalizada */
    double mean_ent = s->entropy_samples > 0
                    ? s->entropy_sum / s->entropy_samples : 0.0;
    double f_entropy = (mean_ent - 5.0) / 3.0;  /* [5.0, 8.0] → [0, 1] */
    if (f_entropy < 0) f_entropy = 0;
    if (f_entropy > 1) f_entropy = 1;
    score += ctx->w_entropy * f_entropy;

    /* 2. Tasa de escrituras normalizada */
    double f_write = (double)s->write_count / ctx->write_rate_thresh;
    if (f_write > 1) f_write = 1;
    score += ctx->w_write * f_write;

    /* 3. Tasa de renombrados normalizada */
    double f_rename = (double)s->rename_count / ctx->rename_thresh;
    if (f_rename > 1) f_rename = 1;
    score += ctx->w_rename * f_rename;

    /* 4. Test χ² (uniformidad) — bajo χ² = más uniforme = más sospechoso */
    if (s->byte_hist_total > 512) {
        double chi2 = entropy_chi2_from_hist(s->byte_hist,
                                              s->byte_hist_total);
        /* χ² < 300 con 255 g.l. → muy uniforme → score alto */
        double f_chi2 = 1.0 - (chi2 / 600.0);
        if (f_chi2 < 0) f_chi2 = 0;
        if (f_chi2 > 1) f_chi2 = 1;
        score += ctx->w_chi2 * f_chi2;
    }

    /* 5. Ratio lectura/escritura — ransomware: lee mucho luego escribe mucho */
    if (s->write_count > 10) {
        double rw = (double)s->read_count / s->write_count;
        /* rw ≈ 1.0 → patrón encrypt in-place, muy sospechoso */
        double f_rw = 1.0 - fabs(rw - 1.0) / 3.0;
        if (f_rw < 0) f_rw = 0;
        score += ctx->w_rw_ratio * f_rw;
    }

    /* 6. Canary: señal directa (override parcial) */
    if (s->canary_triggered) score += 0.5;
    if (score > 1.0) score = 1.0;

    return score;
}

int detector_check_write(struct detector_ctx *ctx, uint32_t pid,
                          const char *path, double entropy, size_t size) {
    (void)path;
    pthread_mutex_lock(&ctx->lock);
    pid_state_t *s = get_or_create_pid(ctx, pid);
    maybe_rotate_window(ctx, s);

    s->write_count++;
    s->bytes_written += size;
    s->entropy_sum   += entropy;
    s->entropy_samples++;
    if (entropy > s->entropy_max) s->entropy_max = entropy;

    s->score = compute_score(ctx, s);

    int verdict = VERDICT_NORMAL;

    /* Regla rápida: entropía máxima sobre umbral + alta tasa */
    if (entropy > ctx->entropy_thresh && s->write_count > 20)
        verdict = VERDICT_SUSPICIOUS;

    /* Score agregado supera umbral */
    if (s->score >= ctx->score_thresh)
        verdict = VERDICT_BLOCK;

    /* Canary tocado: confirmación inmediata */
    if (s->canary_triggered > 0)
        verdict = VERDICT_BLOCK;

    pthread_mutex_unlock(&ctx->lock);
    return verdict;
}

void detector_signal_canary(struct detector_ctx *ctx, const char *path,
                            uint32_t pid) {
    pthread_mutex_lock(&ctx->lock);
    pid_state_t *s = get_or_create_pid(ctx, pid);
    s->canary_triggered = 1;
    s->score += 0.8;  /* Heavy weight for canary access */
    if (s->score > 1.0) s->score = 1.0;
    fprintf(stderr, "[detector] CANARY ALERT: path=%s pid=%u\n", path, pid);
    pthread_mutex_unlock(&ctx->lock);
}

int detector_check_rename(struct detector_ctx *ctx, uint32_t pid,
                          const char *from, const char *to, int ext_changed) {
    (void)from;
    (void)to;
    pthread_mutex_lock(&ctx->lock);
    pid_state_t *s = get_or_create_pid(ctx, pid);
    maybe_rotate_window(ctx, s);

    s->rename_count++;
    if (ext_changed) {
        s->ext_change_count++;
    }

    double score = compute_score(ctx, s);
    /* Extension changes are a strong signal: each adds 0.4 to aggregate */
    score += s->ext_change_count * 0.4;
    if (score > 1.0) score = 1.0;
    s->score = score;

    int verdict = VERDICT_NORMAL;
    if (score >= ctx->score_thresh)
        verdict = VERDICT_BLOCK;
    else if (score >= ctx->warn_threshold)
        verdict = VERDICT_SUSPICIOUS;

    pthread_mutex_unlock(&ctx->lock);
    return verdict;
}

void detector_confirm_attack(struct detector_ctx *ctx, uint32_t pid) {
    pthread_mutex_lock(&ctx->lock);
    pid_state_t *s = get_or_create_pid(ctx, pid);
    s->attack_confirmed = 1;
    fprintf(stderr, "[detector] ATTACK CONFIRMED for PID=%u\n", pid);
    pthread_mutex_unlock(&ctx->lock);
}
