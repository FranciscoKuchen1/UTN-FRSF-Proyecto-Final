#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <pthread.h>
#include "zfs_snap.h"

/*
 * Interfaz con ZFS a través de libzfs (alternativa: invocar zfs(8) vía popen)
 * Para la PoC se usa popen para simplicidad; producción usaría libzfs directa.
 */

/* Snapshot de emergencia — llamado cuando se detecta ataque */
int zfs_snapshot_emergency(const char *dataset) {
    char cmd[512];
    char ts[32];
    time_t now = time(NULL);
    struct tm *tm = gmtime(&now);
    strftime(ts, sizeof(ts), "%Y%m%dT%H%M%SZ", tm);

    snprintf(cmd, sizeof(cmd),
             "zfs snapshot %s@guardian_emergency_%s", dataset, ts);

    int ret = system(cmd);
    if (ret == 0) {
        fprintf(stderr, "[guardian] Snapshot de emergencia: %s@guardian_emergency_%s\n",
                dataset, ts);
    }
    return ret;
}

/* Snapshot periódico programado */
typedef struct {
    char    *dataset;
    uint32_t interval_secs;
    volatile int running;
} snap_thread_arg_t;

static void *snapshot_scheduler(void *arg) {
    snap_thread_arg_t *a = arg;
    int seq = 0;
    while (a->running) {
        sleep(a->interval_secs);
        char cmd[512];
        char ts[32];
        time_t now = time(NULL);
        struct tm *tm = gmtime(&now);
        strftime(ts, sizeof(ts), "%Y%m%dT%H%M%SZ", tm);
        snprintf(cmd, sizeof(cmd),
                 "zfs snapshot %s@guardian_auto_%s", a->dataset, ts);
        system(cmd);

        /* Retener solo los últimos 20 snapshots automáticos */
        snprintf(cmd, sizeof(cmd),
                 "zfs list -t snapshot -o name -s creation %s "
                 "| grep guardian_auto | head -n -20 "
                 "| xargs -r -I{} zfs destroy {}",
                 a->dataset);
        system(cmd);
        seq++;
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

/* Rollback al snapshot más reciente antes del ataque */
int zfs_rollback_latest(const char *dataset, const char *snap_prefix) {
    char cmd[512];
    /* Obtener el snapshot más reciente con el prefijo dado */
    snprintf(cmd, sizeof(cmd),
             "zfs list -t snapshot -o name -s creation %s "
             "| grep '%s' | tail -1",
             dataset, snap_prefix);

    FILE *f = popen(cmd, "r");
    if (!f) return -1;
    char snap[256] = {0};
    fgets(snap, sizeof(snap), f);
    pclose(f);

    /* Eliminar salto de línea */
    snap[strcspn(snap, "\n")] = '\0';
    if (strlen(snap) == 0) return -1;

    snprintf(cmd, sizeof(cmd), "zfs rollback -r %s", snap);
    fprintf(stderr, "[guardian] Rollback a: %s\n", snap);
    return system(cmd);
}
