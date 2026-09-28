#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <time.h>
#include <errno.h>
#include <pthread.h>
#include <spawn.h>
#include <sys/wait.h>
#include "zfs_snap.h"

/*
 * Interfaz con ZFS vía el binario zfs(8).
 *
 * Sin shell: system()/popen() interpolaban strings (dataset desde env) en
 * comandos shell → riesgo de inyección y costo de fork+shell. Ahora todo va
 * por posix_spawnp con argv directo.
 *
 * El snapshot de emergencia es ASYNC (worker thread + dedup por cooldown):
 * antes se ejecutaba `zfs snapshot` síncrono dentro del handler FUSE
 * (~100-300ms de fork+shell+zfs por write bloqueado, decenas de veces con
 * un atacante multihilo).
 */

extern char **environ;

static inline uint64_t now_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

/* ── Ejecutar zfs con argv directo (sin shell) ──
 * Retorna exit status del proceso (>=0) o -1 si falló spawn/wait. */
static int run_zfs(char *const argv[]) {
    pid_t child = -1;
    int rc = posix_spawnp(&child, argv[0], NULL, NULL, argv, environ);
    if (rc != 0) {
        fprintf(stderr, "[zfs_snap] posix_spawnp(%s): %s\n",
                argv[0], strerror(rc));
        return -1;
    }
    int status = 0;
    if (waitpid(child, &status, 0) < 0)
        return -1;
    return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}

/* ── Crear un snapshot (reintenta con sufijo si colisiona el nombre) ── */
static void take_snapshot(const char *dataset, const char *prefix) {
    char ts[32];
    time_t now = time(NULL);
    struct tm *tm = gmtime(&now);
    strftime(ts, sizeof(ts), "%Y%m%dT%H%M%SZ", tm);

    for (int attempt = 0; attempt < 4; attempt++) {
        char snap[320];
        if (attempt == 0)
            snprintf(snap, sizeof(snap), "%s@%s_%s", dataset, prefix, ts);
        else
            snprintf(snap, sizeof(snap), "%s@%s_%s_r%d",
                     dataset, prefix, ts, attempt + 1);

        char *argv[] = { "zfs", "snapshot", snap, NULL };
        if (run_zfs(argv) == 0) {
            fprintf(stderr, "[guardian] Snapshot: %s\n", snap);
            return;
        }
        /* Colisión de nombre (mismo segundo) u otro error → sufijo */
    }
    fprintf(stderr, "[guardian] Snapshot FALLÓ (dataset=%s prefix=%s)\n",
            dataset, prefix);
}

/* ── Listar snapshots del dataset con el prefijo (sin shell) ──
 * Llena names[] en orden ascendente por creación (los más viejos primero).
 * Retorna el total encontrado (capado en max_names). */
static int list_snapshots(const char *dataset, const char *prefix,
                          char names[][128], int max_names) {
    int fds[2];
    if (pipe(fds) < 0)
        return -1;

    char *argv[] = { "zfs", "list", "-t", "snapshot", "-o", "name",
                     "-s", "creation", (char *)dataset, NULL };

    posix_spawn_file_actions_t fa;
    posix_spawn_file_actions_init(&fa);
    posix_spawn_file_actions_adddup2(&fa, fds[1], STDOUT_FILENO);
    posix_spawn_file_actions_addclose(&fa, fds[0]);

    pid_t child = -1;
    int rc = posix_spawnp(&child, "zfs", &fa, NULL, argv, environ);
    posix_spawn_file_actions_destroy(&fa);
    close(fds[1]);
    if (rc != 0) {
        close(fds[0]);
        return -1;
    }

    FILE *f = fdopen(fds[0], "r");
    int n = 0;
    if (f) {
        char line[256];
        while (fgets(line, sizeof(line), f)) {
            line[strcspn(line, "\n")] = '\0';
            if (!strstr(line, prefix))
                continue;
            if (n < max_names)
                snprintf(names[n], 128, "%s", line);
            n++;
        }
        fclose(f);   /* cierra fds[0] */
    } else {
        close(fds[0]);
    }

    int status = 0;
    waitpid(child, &status, 0);
    return n;
}

static int destroy_snapshot(char snap[128]) {
    char *argv[] = { "zfs", "destroy", snap, NULL };
    return run_zfs(argv);
}

/* Destruye los snapshots más viejos, conservando solo los últimos keep */
static void retain_last(const char *dataset, const char *prefix, int keep) {
    char names[256][128];
    int n = list_snapshots(dataset, prefix, names, 256);
    if (n <= keep)
        return;
    int to_destroy = n - keep;   /* names[0..] son los más viejos */
    for (int i = 0; i < to_destroy; i++) {
        if (destroy_snapshot(names[i]) == 0)
            fprintf(stderr, "[guardian] Retention: %s destruido\n", names[i]);
    }
}

/* ── Snapshot de emergencia: async + dedup por cooldown ──
 * El handler FUSE solo señaliza (µs); el worker ejecuta zfs fuera del
 * hot path. Un ataque sostenido no genera más de uno cada cooldown. */
#define EMERGENCY_COOLDOWN_S 10

static pthread_mutex_t emerg_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t  emerg_cond  = PTHREAD_COND_INITIALIZER;
static pthread_once_t  emerg_once  = PTHREAD_ONCE_INIT;
static int      emerg_pending = 0;
static uint64_t emerg_last_req_ns = 0;
static char     emerg_dataset[256] = {0};

static void *emergency_worker(void *arg) {
    (void)arg;
    char ds[256];
    for (;;) {
        pthread_mutex_lock(&emerg_mutex);
        while (!emerg_pending)
            pthread_cond_wait(&emerg_cond, &emerg_mutex);
        emerg_pending = 0;
        memcpy(ds, emerg_dataset, sizeof(ds));
        pthread_mutex_unlock(&emerg_mutex);
        take_snapshot(ds, "guardian_emergency");
        retain_last(ds, "guardian_emergency", 10);
    }
    return NULL;
}

static void emergency_thread_init(void) {
    pthread_t tid;
    if (pthread_create(&tid, NULL, emergency_worker, NULL) == 0)
        pthread_detach(tid);
}

int zfs_snapshot_emergency(const char *dataset) {
    pthread_once(&emerg_once, emergency_thread_init);

    uint64_t now = now_ns();
    pthread_mutex_lock(&emerg_mutex);
    if (!emerg_dataset[0] && dataset && *dataset)
        snprintf(emerg_dataset, sizeof(emerg_dataset), "%s", dataset);
    if (now - emerg_last_req_ns <
            (uint64_t)EMERGENCY_COOLDOWN_S * 1000000000ULL) {
        pthread_mutex_unlock(&emerg_mutex);
        return 0;   /* dedup: ya se pidió dentro del cooldown */
    }
    if (emerg_pending) {
        pthread_mutex_unlock(&emerg_mutex);
        return 0;   /* ya hay un snapshot en vuelo */
    }
    emerg_last_req_ns = now;
    emerg_pending = 1;
    pthread_cond_signal(&emerg_cond);
    pthread_mutex_unlock(&emerg_mutex);
    return 0;   /* async: lo ejecuta el worker */
}

/* ── Snapshot periódico programado ── */
static void *snapshot_scheduler(void *arg) {
    snap_thread_arg_t *a = arg;
    while (a->running) {
        sleep(a->interval_secs);
        if (!a->running)
            break;
        take_snapshot(a->dataset, "guardian_auto");
        /* Retención: últimos 20 automáticos (los de emergencia los
         * maneja su worker) */
        retain_last(a->dataset, "guardian_auto", 20);
    }
    return NULL;
}

pthread_t zfs_snapshot_schedule(const char *dataset, uint32_t interval_secs) {
    snap_thread_arg_t *a = malloc(sizeof(*a));
    a->dataset       = strdup(dataset);
    a->interval_secs = interval_secs;
    a->running       = 1;
    pthread_t tid;
    pthread_create(&tid, NULL, snapshot_scheduler, a);
    return tid;
}

/* ── Rollback al snapshot más reciente antes del ataque ── */
int zfs_rollback_latest(const char *dataset, const char *snap_prefix) {
    char names[64][128];
    int n = list_snapshots(dataset, snap_prefix, names, 64);
    if (n <= 0)
        return -1;

    char *snap = names[n - 1];   /* creación ascendente → último = más nuevo */
    char *argv[] = { "zfs", "rollback", "-r", snap, NULL };
    fprintf(stderr, "[guardian] Rollback a: %s\n", snap);
    return run_zfs(argv);
}
