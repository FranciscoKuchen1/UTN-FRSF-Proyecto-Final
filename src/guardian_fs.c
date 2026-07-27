#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#define FUSE_USE_VERSION 35
#include <fuse3/fuse.h>
#include <fuse3/fuse_lowlevel.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/xattr.h>
#include <pthread.h>
#include <time.h>
#include <dirent.h>
#include <sys/types.h>
#include <limits.h>
#include "entropy.h"
#include "detector.h"
#include "canary.h"
#include "zfs_snap.h"
#include "ring_buffer.h"
#include "mitigation.h"
#include "analyzer.h"

/* ── Logging estructurado ── */
#define LOG_PATH_DEFAULT "/var/log/guardian/events.jsonl"

static FILE  *log_fp = NULL;
static pthread_mutex_t log_mutex = PTHREAD_MUTEX_INITIALIZER;

static void log_init(void) {
    const char *path = getenv("GUARDIAN_LOG_PATH");
    if (!path) path = LOG_PATH_DEFAULT;
    log_fp = fopen(path, "a");
    if (!log_fp) {
        /* fallback: stderr si no se puede abrir el archivo */
        log_fp = stderr;
    } else {
        setvbuf(log_fp, NULL, _IONBF, 0);  /* sin buffering para inmediatez */
    }
}

static void log_event(const char *event_type, uint32_t pid,
                      const char *path, const char *extra_json) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    char ts_buf[32];
    strftime(ts_buf, sizeof(ts_buf), "%Y-%m-%dT%H:%M:%S",
             gmtime(&ts.tv_sec));

    pthread_mutex_lock(&log_mutex);
    if (log_fp) {
        fprintf(log_fp,
                "{\"ts\":\"%s.%09ld\",\"event\":\"%s\",\"pid\":%u,"
                "\"path\":\"%s\"%s%s}\n",
                ts_buf, ts.tv_nsec,
                event_type, pid, path,
                extra_json ? "," : "", extra_json ? extra_json : "");
        fflush(log_fp);
    }
    pthread_mutex_unlock(&log_mutex);
}

static inline uint64_t clock_gettime_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

/* ── Helper: env var con fallback ── */
static char *get_env_or(const char *name, const char *fallback) {
    const char *val = getenv(name);
    return strdup(val ? val : fallback);
}

/* ── Configuración global ── */
#define WINDOW_SECS       5       /* ventana de análisis en segundos */
#define ENTROPY_THRESHOLD 7.2     /* bits/byte — umbral de alerta */
#define WRITE_RATE_THRESH 500     /* escrituras/ventana — umbral */
#define RENAME_THRESH     50      /* renombrados/ventana */

typedef struct {
    char *real_root;              /* directorio ZFS subyacente      */
    char *zfs_dataset;            /* nombre del dataset ZFS         */
    struct detector_ctx *det;     /* contexto del motor de detección */
    struct canary_ctx   *can;     /* contexto de archivos canary    */
    struct ring_buf     *evbuf;   /* buffer circular de eventos     */
    pthread_t            analyzer_tid;
    volatile int         running;
} guardian_state_t;

static guardian_state_t gstate;

/* Globals for cross-module access (analyzer, mitigation) */
struct ring_buf    *evbuf;
struct detector_ctx *detector;

/* Construye la ruta real en ZFS */
static void real_path(char *dst, const char *path) {
    snprintf(dst, PATH_MAX, "%s%s", gstate.real_root, path);
}

/* ── Operaciones FUSE ── */

static int gfs_getattr(const char *path, struct stat *st,
                        struct fuse_file_info *fi) {
    (void)fi;
    char rp[PATH_MAX];
    real_path(rp, path);
    return lstat(rp, st) < 0 ? -errno : 0;
}

static int gfs_open(const char *path, struct fuse_file_info *fi) {
    char rp[PATH_MAX];
    real_path(rp, path);
    int fd = open(rp, fi->flags);
    if (fd < 0) return -errno;
    fi->fh = fd;

    /* Detectar apertura de canary */
    if (canary_is_canary(gstate.can, path)) {
        uint32_t pid = fuse_get_context()->pid;
        log_event("canary_accessed", pid, path,
                  "\"verdict\":\"SUSPICIOUS\"");
        detector_signal_canary(gstate.det, path, pid);
    }
    return 0;
}

static int gfs_read(const char *path, char *buf, size_t size,
                     off_t offset, struct fuse_file_info *fi) {
    ssize_t n = pread(fi->fh, buf, size, offset);
    if (n < 0) return -errno;

    /* Evento: lectura — para detectar read→encrypt→write */
    io_event_t ev = {
        .type   = EV_READ,
        .pid    = fuse_get_context()->pid,
        .size   = (uint64_t)n,
        .ts_ns  = clock_gettime_ns(),
    };
    strncpy(ev.path, path, sizeof(ev.path) - 1);
    ring_buf_push(gstate.evbuf, &ev);

    return (int)n;
}

static int gfs_write(const char *path, const char *buf, size_t size,
                      off_t offset, struct fuse_file_info *fi) {

    struct fuse_context *ctx = fuse_get_context();
    uint32_t pid = ctx->pid;

    /* 1. Calcular entropía del buffer entrante */
    double ent = entropy_shannon((const uint8_t *)buf, size);

    /* 2. Registrar evento */
    io_event_t ev = {
        .type    = EV_WRITE,
        .pid     = pid,
        .size    = (uint64_t)size,
        .entropy = ent,
        .ts_ns   = clock_gettime_ns(),
    };
    strncpy(ev.path, path, sizeof(ev.path) - 1);
    ring_buf_push(gstate.evbuf, &ev);

    /* 3. Evaluación sincrónica rápida (umbrales locales por proceso) */
    int verdict = detector_check_write(gstate.det, pid, path, ent, size);
    if (verdict == VERDICT_BLOCK) {
        char extra[128];
        snprintf(extra, sizeof(extra),
                 "\"entropy\":%.4f,\"size\":%zu,\"verdict\":\"BLOCK\"",
                 ent, size);
        log_event("write_blocked", pid, path, extra);
        /* Bloquear escritura y disparar snapshot de emergencia */
        zfs_snapshot_emergency(gstate.zfs_dataset);
        mitigation_kill_process(pid);
        return -EPERM;   /* permiso denegado → ransomware ve error */
    }

    /* 4. Escritura real en ZFS */
    ssize_t n = pwrite(fi->fh, buf, size, offset);
    return n < 0 ? -errno : (int)n;
}

static int gfs_rename(const char *from, const char *to, unsigned int flags) {
    char rf[PATH_MAX], rt[PATH_MAX];
    real_path(rf, from);
    real_path(rt, to);

    uint32_t pid = fuse_get_context()->pid;

    /* Detectar cambio de extensión (p.ej. .doc → .locked) */
    const char *ext_from = strrchr(from, '.');
    const char *ext_to   = strrchr(to,   '.');
    int ext_changed = (ext_from && ext_to) && strcmp(ext_from, ext_to) != 0;

    io_event_t ev = {
        .type        = EV_RENAME,
        .pid         = pid,
        .ext_changed = ext_changed,
        .ts_ns       = clock_gettime_ns(),
    };
    strncpy(ev.path, from, sizeof(ev.path) - 1);
    ring_buf_push(gstate.evbuf, &ev);

    if (detector_check_rename(gstate.det, pid, from, to, ext_changed)
            == VERDICT_BLOCK) {
        char extra[128];
        snprintf(extra, sizeof(extra),
                 "\"from\":\"%s\",\"to\":\"%s\",\"ext_changed\":%d,"
                 "\"verdict\":\"BLOCK\"",
                 from, to, ext_changed);
        log_event("rename_blocked", pid, from, extra);
        zfs_snapshot_emergency(gstate.zfs_dataset);
        mitigation_kill_process(pid);
        return -EPERM;
    }

    return renameat2(AT_FDCWD, rf, AT_FDCWD, rt, flags) < 0 ? -errno : 0;
}

static int gfs_unlink(const char *path) {
    uint32_t pid = fuse_get_context()->pid;

    if (canary_is_canary(gstate.can, path)) {
        /* Eliminación de canary = ataque confirmado */
        log_event("canary_deleted", pid, path,
                  "\"verdict\":\"ATTACK_CONFIRMED\"");
        zfs_snapshot_emergency(gstate.zfs_dataset);
        detector_confirm_attack(gstate.det, pid);
        mitigation_kill_process(pid);
        return -EPERM;
    }

    io_event_t ev = { .type = EV_UNLINK, .pid = pid,
                      .ts_ns = clock_gettime_ns() };
    strncpy(ev.path, path, sizeof(ev.path) - 1);
    ring_buf_push(gstate.evbuf, &ev);

    char rp[PATH_MAX];
    real_path(rp, path);
    return unlink(rp) < 0 ? -errno : 0;
}

static int gfs_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
                       off_t offset, struct fuse_file_info *fi,
                       enum fuse_readdir_flags flags) {
    (void)offset;
    (void)fi;
    (void)flags;
    char rpath[PATH_MAX];
    real_path(rpath, path);

    DIR *dp = opendir(rpath);
    if (!dp) return -errno;

    struct dirent *de;
    while ((de = readdir(dp)) != NULL) {
        struct stat st;
        memset(&st, 0, sizeof(st));
        st.st_ino  = de->d_ino;
        st.st_mode = de->d_type << 12;
        if (filler(buf, de->d_name, &st, 0, FUSE_FILL_DIR_PLUS))
            break;
    }
    closedir(dp);
    return 0;
}

static int gfs_mkdir(const char *path, mode_t mode) {
    char rpath[PATH_MAX];
    real_path(rpath, path);
    int ret = mkdir(rpath, mode);
    return ret == 0 ? 0 : -errno;
}

static int gfs_create(const char *path, mode_t mode, struct fuse_file_info *fi) {
    char rpath[PATH_MAX];
    real_path(rpath, path);
    int fd = open(rpath, fi->flags | O_CREAT, mode);
    if (fd < 0) return -errno;
    fi->fh = (uint64_t)fd;
    return 0;
}

static int gfs_release(const char *path, struct fuse_file_info *fi) {
    (void)path;
    if (fi->fh)
        close((int)fi->fh);
    return 0;
}

static int gfs_truncate(const char *path, off_t size, struct fuse_file_info *fi) {
    char rpath[PATH_MAX];
    real_path(rpath, path);
    int ret;
    if (fi && fi->fh)
        ret = ftruncate((int)fi->fh, size);
    else
        ret = truncate(rpath, size);
    return ret == 0 ? 0 : -errno;
}

static const struct fuse_operations guardian_ops = {
    .getattr  = gfs_getattr,
    .open     = gfs_open,
    .read     = gfs_read,
    .write    = gfs_write,
    .rename   = gfs_rename,
    .unlink   = gfs_unlink,
    .readdir  = gfs_readdir,   /* implementación estándar proxy */
    .mkdir    = gfs_mkdir,
    .create   = gfs_create,
    .release  = gfs_release,
    .truncate = gfs_truncate,
};

int main(int argc, char *argv[]) {
    /* Inicialización */
    log_init();
    gstate.real_root   = get_env_or("GUARDIAN_REAL_ROOT", "/zpool/data");
    gstate.zfs_dataset = get_env_or("GUARDIAN_ZFS_DATASET", "tank/data");
    /* NOTE: real_root and zfs_dataset are never freed — this is a
     * long-running FUSE daemon so the one-time allocation at startup
     * is negligible and the OS reclaims it on process exit. */
    gstate.det         = detector_init(WINDOW_SECS, ENTROPY_THRESHOLD,
                                       WRITE_RATE_THRESH, RENAME_THRESH);
    gstate.can         = canary_init("/zpool/data");
    gstate.evbuf       = ring_buf_create(65536, sizeof(io_event_t));
    gstate.running     = 1;

    /* Expose to cross-module globals */
    evbuf    = gstate.evbuf;
    detector = gstate.det;

    /* Thread analizador asíncrono (para ML y métricas complejas) */
    pthread_create(&gstate.analyzer_tid, NULL, analyzer_thread, &gstate);

    canary_deploy(gstate.can, 20);    /* sembrar 20 archivos canary */
    zfs_snapshot_schedule(gstate.zfs_dataset, 60); /* snap cada 60s */

    return fuse_main(argc, argv, &guardian_ops, &gstate);
}
