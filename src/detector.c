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

/* starttime del proceso (campo 22 de /proc/<pid>/stat) — identidad del PID.
 * Copia autocontenida de la de mitigation.c para mantener la compilación
 * manual por módulo (ver docs/testing-guide.md). 0 = no encontrado. */
static uint64_t read_proc_starttime(uint32_t pid) {
    char path[64];
    char line[1024];

    snprintf(path, sizeof(path), "/proc/%u/stat", pid);
    FILE *f = fopen(path, "r");
    if (!f) return 0;

    int ok = (fgets(line, sizeof(line), f) != NULL);
    fclose(f);
    if (!ok) return 0;

    char *rp = strrchr(line, ')');
    if (!rp) return 0;
    char *p = rp;
    for (int tok = 3; tok <= 22; tok++) {
        p = strchr(p + 1, ' ');
        if (!p) return 0;
    }
    return (uint64_t)strtoull(p + 1, NULL, 10);
}

/* Estado por proceso */
typedef struct {
    uint32_t  pid;
    uint64_t  write_count;       /* escrituras en ventana actual   */
    uint64_t  bytes_written;
    uint64_t  rename_count;
    uint64_t  unlink_count;
    double    entropy_sum;       /* para media móvil               */
    double    entropy_max;
    uint64_t  entropy_samples;
    double    chi2_sum;          /* χ² acumulado de escrituras     */
    uint32_t  chi2_samples;      /* válidas (size >= 256)          */
    int       canary_triggered;
    uint32_t  canary_reads;      /* lecturas read-only de canaries      */
    int       ext_change_count;
    double    score;             /* puntuación de riesgo agregada  */
    uint64_t  window_start_ns;
    uint64_t  last_event_ns;     /* para expirar PIDs muertos      */
    uint64_t  starttime;         /* /proc starttime — identidad    */
    int       verdict;           /* VERDICT_NORMAL / BLOCK        */
    int       attack_confirmed;  /* set by detector_confirm_attack */
} pid_state_t;

/* Límites de la tabla per-PID: sin esto crece sin acotar y el estado
 * (p.ej. canary_triggered) sobrevive al reuso de PIDs → kills de inocentes. */
#define DET_MAX_PIDS       256
#define DET_IDLE_EXPIRE_S   30   /* sin eventos N seg → slot liberado   */
#define DET_SWEEP_PERIOD_S  10   /* barrido de inactivos al menos c/10s */

/* Umbrales de las señales que no vienen por parámetro en detector_init */
#define DET_UNLINK_THRESH     40   /* unlinks/ventana → peso completo    */
#define DET_CHI2_UNIFORM_MAX  300  /* χ² típico de datos cifrados (≈255 g.l.) */

/* Freno global (anti-evasión multiproceso): umbrales agregados/ventana */
#define DET_GLOBAL_HENT_WRITES 100 /* writes con firma de cifrado      */
#define DET_GLOBAL_EXT_CHANGES 60   /* renames con cambio de extensión  */

/* ── Freno global ──
 * Un ransomware que forkea N workers diluye el scoring per-PID (cada
 * worker queda bajo todos los umbrales). El freno agrega en la ventana
 * la tasa de escrituras con FIRMA DE CIFRADO (entropía alta + χ²
 * uniforme — un .jpg/.zip comprimido tiene alta entropía pero χ² alto,
 * no cuenta) de TODOS los PIDs: si el agregado supera el umbral, los
 * escritores con firma de cifrado se bloquean. Un writer benigno de
 * baja entropía nunca es bloqueado por el freno. */
typedef struct {
    uint64_t window_start_ns;
    uint64_t hent_writes;      /* writes con firma de cifrado     */
    uint64_t ext_changes;      /* renames con cambio de extensión  */
    int      brake_armed;
} global_state_t;

struct detector_ctx {
    pid_state_t **pids;
    size_t        n_pids;
    pthread_mutex_t lock;
    /* umbrales */
    double   entropy_thresh;
    uint64_t write_rate_thresh;
    uint64_t rename_thresh;
    uint64_t unlink_thresh;
    uint32_t window_secs;
    /* pesos para scoring */
    double w_entropy;    /* peso entropía           */
    double w_write;      /* peso tasa escrituras    */
    double w_rename;     /* peso tasa renombrados   */
    double w_chi2;       /* peso test χ²            */
    double w_unlink;     /* peso caza de backups    */
    double score_thresh; /* umbral score → bloqueo  */
    double warn_threshold; /* umbral score → sospechoso */
    uint64_t last_sweep_ns;
    /* freno global */
    global_state_t    g;
    uint64_t global_hent_thresh;
    uint64_t global_ext_thresh;
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
    /* Pesos calibrados experimentalmente. El ratio lectura/escritura no
     * participa aquí: los EV_READ no llegan al detector síncrono, se
     * evalúa en el camino async (analyzer.c → features ML). */
    ctx->w_entropy   = 0.35;
    ctx->w_write     = 0.20;
    ctx->w_rename    = 0.15;
    ctx->w_chi2      = 0.20;
    ctx->w_unlink    = 0.10;
    ctx->unlink_thresh = DET_UNLINK_THRESH;
    ctx->score_thresh= 0.65;   /* 65% → bloqueo */
    ctx->warn_threshold = 0.45; /* 45% → sospechoso */
    ctx->last_sweep_ns = 0;
    /* Freno global */
    ctx->g.window_start_ns  = clock_gettime_ns();
    ctx->global_hent_thresh = DET_GLOBAL_HENT_WRITES;
    ctx->global_ext_thresh  = DET_GLOBAL_EXT_CHANGES;
    pthread_mutex_init(&ctx->lock, NULL);
    return ctx;
}

void detector_destroy(struct detector_ctx *ctx) {
    if (!ctx) return;
    pthread_mutex_lock(&ctx->lock);
    for (size_t i = 0; i < ctx->n_pids; i++)
        free(ctx->pids[i]);
    free(ctx->pids);
    pthread_mutex_unlock(&ctx->lock);
    pthread_mutex_destroy(&ctx->lock);
    free(ctx);
}

/* Libera entradas de PIDs sin actividad reciente — asume lock tomado.
 * Evita que estado peligroso (canary_triggered) sobreviva al reuso de PID. */
static void sweep_idle(struct detector_ctx *ctx) {
    uint64_t now = clock_gettime_ns();
    ctx->last_sweep_ns = now;
    for (size_t i = 0; i < ctx->n_pids; ) {
        pid_state_t *s = ctx->pids[i];
        if (now - s->last_event_ns >
                (uint64_t)DET_IDLE_EXPIRE_S * 1000000000ULL) {
            free(s);
            ctx->pids[i] = ctx->pids[--ctx->n_pids];
            continue;
        }
        i++;
    }
}

static pid_state_t *get_or_create_pid(struct detector_ctx *ctx,
                                       uint32_t pid) {
    uint64_t now = clock_gettime_ns();

    for (size_t i = 0; i < ctx->n_pids; i++) {
        if (ctx->pids[i]->pid == pid) {
            ctx->pids[i]->last_event_ns = now;
            return ctx->pids[i];
        }
    }

    /* Mantener la tabla acotada: barrido de inactivos y, si sigue llena,
     * reciclado de la entrada con actividad más vieja. */
    if (ctx->n_pids >= DET_MAX_PIDS ||
        now - ctx->last_sweep_ns >
            (uint64_t)DET_SWEEP_PERIOD_S * 1000000000ULL)
        sweep_idle(ctx);
    if (ctx->n_pids >= DET_MAX_PIDS) {
        size_t oldest = 0;
        for (size_t i = 1; i < ctx->n_pids; i++)
            if (ctx->pids[i]->last_event_ns < ctx->pids[oldest]->last_event_ns)
                oldest = i;
        free(ctx->pids[oldest]);
        ctx->pids[oldest] = ctx->pids[--ctx->n_pids];
    }

    ctx->pids = realloc(ctx->pids,
                        (ctx->n_pids + 1) * sizeof(pid_state_t *));
    pid_state_t *s = calloc(1, sizeof(pid_state_t));
    s->pid = pid;
    s->window_start_ns = now;
    s->last_event_ns   = now;
    s->starttime       = read_proc_starttime(pid);
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
        s->entropy_sum      = 0.0;
        s->entropy_samples  = 0;
        s->chi2_sum         = 0.0;
        s->chi2_samples     = 0;
        s->ext_change_count = 0;
        s->canary_reads     = 0;
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

    /* 4. Test χ² medio (uniformidad) — bajo χ² = más uniforme = más sospechoso.
     * Acumulado por escritura con muestra válida (size >= 256). */
    if (s->chi2_samples > 0) {
        double chi2_mean = s->chi2_sum / (double)s->chi2_samples;
        /* χ² < 300 con 255 g.l. → muy uniforme → score alto */
        double f_chi2 = 1.0 - (chi2_mean / 600.0);
        if (f_chi2 < 0) f_chi2 = 0;
        if (f_chi2 > 1) f_chi2 = 1;
        score += ctx->w_chi2 * f_chi2;
    }

    /* 5. Caza de backups: tasa de unlinks en la ventana (análogo Linux del
     * `vssadmin delete shadows` — ransomware borra backups antes/después
     * de cifrar). Sola no bloquea: rm -rf benigno (make clean) aporta
     * como máximo w_unlink (0.10) < score_thresh. */
    if (s->unlink_count > 0) {
        double f_unlink = (double)s->unlink_count / (double)ctx->unlink_thresh;
        if (f_unlink > 1) f_unlink = 1;
        score += ctx->w_unlink * f_unlink;
    }

    /* 6. Lecturas read-only de canaries: señal leve persistente en la
     * ventana (una lectura sola no arma el kill — ver FP de backups) */
    if (s->canary_reads > 0) {
        double f_canary_read = 0.05 * s->canary_reads;
        if (f_canary_read > 0.15) f_canary_read = 0.15;
        score += f_canary_read;
    }

    if (score > 1.0) score = 1.0;

    return score;
}

/* ── Helpers del freno global (lock tomado por el caller) ── */
static void global_maybe_rotate(struct detector_ctx *ctx) {
    uint64_t now = clock_gettime_ns();
    if (now - ctx->g.window_start_ns >=
            (uint64_t)ctx->window_secs * 1000000000ULL) {
        ctx->g.hent_writes     = 0;
        ctx->g.ext_changes     = 0;
        ctx->g.brake_armed     = 0;
        ctx->g.window_start_ns = now;
    }
}

/* Firma de cifrado: entropía alta + distribución uniforme (χ² bajo).
 * Un .jpg/.zip comprimido tiene alta entropía pero χ² alto (no uniforme)
 * → no cuenta para el freno global (anti-FP de cp de backups cifrados). */
static int is_uniform_high_entropy(struct detector_ctx *ctx,
                                   double entropy, double chi2) {
    return entropy > ctx->entropy_thresh &&
           chi2 > 0.0 && chi2 < (double)DET_CHI2_UNIFORM_MAX;
}

int detector_check_write(struct detector_ctx *ctx, uint32_t pid,
                          const char *path, double entropy, size_t size,
                          double chi2) {
    (void)path;   /* la discriminación canary es por entropía, no ruta */
    pthread_mutex_lock(&ctx->lock);
    pid_state_t *s = get_or_create_pid(ctx, pid);
    maybe_rotate_window(ctx, s);

    s->write_count++;
    s->bytes_written += size;
    s->entropy_sum   += entropy;
    s->entropy_samples++;
    if (entropy > s->entropy_max) s->entropy_max = entropy;
    if (chi2 > 0.0 && chi2 < 1e8) {   /* 1e9 = muestra insuficiente */
        s->chi2_sum     += chi2;
        s->chi2_samples++;
    }

    /* Freno global: contar escrituras con firma de cifrado */
    global_maybe_rotate(ctx);
    if (is_uniform_high_entropy(ctx, entropy, chi2)) {
        ctx->g.hent_writes++;
        if (!ctx->g.brake_armed &&
                ctx->g.hent_writes >= ctx->global_hent_thresh) {
            ctx->g.brake_armed = 1;
            fprintf(stderr, "[detector] GLOBAL BRAKE armed: %llu writes "
                            "con firma de cifrado en la ventana\n",
                    (unsigned long long)ctx->g.hent_writes);
        }
    }

    s->score = compute_score(ctx, s);

    int verdict = VERDICT_NORMAL;

    /* Ataque confirmado (veredicto ML o canary eliminado) → bloqueo directo */
    if (s->attack_confirmed) {
        verdict = VERDICT_BLOCK;
    }
    /* Regla rápida: entropía máxima sobre umbral + alta tasa */
    else if (entropy > ctx->entropy_thresh && s->write_count > 20) {
        verdict = VERDICT_SUSPICIOUS;
    }

    /* Score agregado supera umbral */
    if (s->score >= ctx->score_thresh)
        verdict = VERDICT_BLOCK;

    /* Canary armado: bloquear solo si esta escritura tiene firma de
     * cifrado o va al propio canary con alta entropía. Un usuario
     * editando el señuelo (baja entropía, misma u otra ruta — autosave,
     * temporales del editor) no es bloqueado. */
    if (s->canary_triggered && entropy > ctx->entropy_thresh)
        verdict = VERDICT_BLOCK;

    /* Freno global activo: bloquear a los escritores con firma de cifrado
     * aunque su scoring per-PID esté diluido entre N workers */
    if (ctx->g.brake_armed && is_uniform_high_entropy(ctx, entropy, chi2))
        verdict = VERDICT_BLOCK;

    pthread_mutex_unlock(&ctx->lock);
    return verdict;
}

void detector_signal_canary(struct detector_ctx *ctx, const char *path,
                            uint32_t pid) {
    pthread_mutex_lock(&ctx->lock);
    pid_state_t *s = get_or_create_pid(ctx, pid);
    s->canary_triggered = 1;
    fprintf(stderr, "[detector] CANARY ALERT: path=%s pid=%u\n", path, pid);
    pthread_mutex_unlock(&ctx->lock);
}

void detector_note_canary_read(struct detector_ctx *ctx, uint32_t pid) {
    pthread_mutex_lock(&ctx->lock);
    pid_state_t *s = get_or_create_pid(ctx, pid);
    s->canary_reads++;
    pthread_mutex_unlock(&ctx->lock);
}

uint64_t detector_pid_starttime(struct detector_ctx *ctx, uint32_t pid) {
    uint64_t st = 0;
    pthread_mutex_lock(&ctx->lock);
    for (size_t i = 0; i < ctx->n_pids; i++) {
        if (ctx->pids[i]->pid == pid) {
            st = ctx->pids[i]->starttime;
            break;
        }
    }
    pthread_mutex_unlock(&ctx->lock);
    return st;
}

void detector_reset_pid(struct detector_ctx *ctx, uint32_t pid) {
    pthread_mutex_lock(&ctx->lock);
    for (size_t i = 0; i < ctx->n_pids; i++) {
        if (ctx->pids[i]->pid == pid) {
            free(ctx->pids[i]);
            ctx->pids[i] = ctx->pids[--ctx->n_pids];
            break;
        }
    }
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
        /* Freno global: renames con cambio de extensión (diluidos entre
         * N workers) */
        global_maybe_rotate(ctx);
        ctx->g.ext_changes++;
        if (!ctx->g.brake_armed &&
                ctx->g.ext_changes >= ctx->global_ext_thresh) {
            ctx->g.brake_armed = 1;
            fprintf(stderr, "[detector] GLOBAL BRAKE armed: %llu renames "
                            "con cambio de extensión en la ventana\n",
                    (unsigned long long)ctx->g.ext_changes);
        }
    }

    double score = compute_score(ctx, s);
    /* Extension changes are a strong signal: each adds 0.4 to aggregate */
    score += s->ext_change_count * 0.4;
    if (score > 1.0) score = 1.0;
    s->score = score;

    int verdict = VERDICT_NORMAL;
    if (s->attack_confirmed)
        verdict = VERDICT_BLOCK;
    else if (score >= ctx->score_thresh)
        verdict = VERDICT_BLOCK;
    else if (score >= ctx->warn_threshold)
        verdict = VERDICT_SUSPICIOUS;

    /* Canary armado + rename con cambio de extensión (.docx → .locked):
     * patrón de ransomware. Mover archivos sin cambiar extensión no. */
    if (s->canary_triggered && ext_changed)
        verdict = VERDICT_BLOCK;

    /* Freno global activo: bloquear los renames con cambio de extensión */
    if (ctx->g.brake_armed && ext_changed)
        verdict = VERDICT_BLOCK;

    pthread_mutex_unlock(&ctx->lock);
    return verdict;
}

int detector_check_unlink(struct detector_ctx *ctx, uint32_t pid,
                          const char *path) {
    (void)path;
    pthread_mutex_lock(&ctx->lock);
    pid_state_t *s = get_or_create_pid(ctx, pid);
    maybe_rotate_window(ctx, s);

    s->unlink_count++;
    s->score = compute_score(ctx, s);

    int verdict = VERDICT_NORMAL;
    if (s->attack_confirmed)
        verdict = VERDICT_BLOCK;
    else if (s->canary_triggered)
        /* armado (abrió canary para escribir o lo renombró) y borrando
         * archivos = patrón de ransomware (borra originales tras cifrar) */
        verdict = VERDICT_BLOCK;
    else if (s->score >= ctx->score_thresh)
        verdict = VERDICT_BLOCK;
    else if (s->score >= ctx->warn_threshold)
        verdict = VERDICT_SUSPICIOUS;

    pthread_mutex_unlock(&ctx->lock);
    return verdict;
}

int detector_global_brake_armed(struct detector_ctx *ctx) {
    pthread_mutex_lock(&ctx->lock);
    int armed = ctx->g.brake_armed;
    pthread_mutex_unlock(&ctx->lock);
    return armed;
}

void detector_confirm_attack(struct detector_ctx *ctx, uint32_t pid) {
    pthread_mutex_lock(&ctx->lock);
    pid_state_t *s = get_or_create_pid(ctx, pid);
    s->attack_confirmed = 1;
    fprintf(stderr, "[detector] ATTACK CONFIRMED for PID=%u\n", pid);
    pthread_mutex_unlock(&ctx->lock);
}
