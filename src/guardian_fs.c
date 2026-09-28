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
#include <strings.h>
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

/* ── Modo shadow: registrar veredictos SIN bloquear/kill/snapshot ──
 * Para recolección de datos (los ataques generan features de todas sus
 * ventanas, no mueren en la primera) y medición de FPs sin riesgo.
 * Activación: GUARDIAN_SHADOW_MODE=1 (o true/yes/on). */
static int g_shadow;

static int getenv_bool(const char *name) {
    const char *v = getenv(name);
    if (!v) return 0;
    return strcasecmp(v, "1") == 0 || strcasecmp(v, "true") == 0 ||
           strcasecmp(v, "yes") == 0 || strcasecmp(v, "on") == 0;
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

/* Rate-limit del log de writes sospechosos (acceso atómico relajado —
 * best-effort entre hilos FUSE) */
static uint64_t last_susp_log_ns;

/* Mitigación con verificación de identidad: mata solo si el starttime
 * actual del PID coincide con el registrado por el detector (evita
 * matar a un inocente que reutilizó el PID de un atacante muerto).
 * El resultado va al log estructurado. */
static void mitigate_and_log(uint32_t pid, const char *path) {
    int kr = mitigation_kill_process(pid,
                                     detector_pid_starttime(gstate.det, pid));
    if (kr == MIT_PID_REUSED)
        detector_reset_pid(gstate.det, pid);   /* estado envenenado */

    const char *res = kr == MIT_KILLED ? "killed"
                    : kr == MIT_PID_REUSED ? "pid_reused"
                    : kr == MIT_NO_PROCESS ? "already_gone"
                    : "error";
    char extra[96];
    snprintf(extra, sizeof(extra), "\"result\":\"%s\"", res);
    log_event(kr == MIT_KILLED ? "process_killed" : "kill_skipped",
              pid, path, extra);
}

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

    /* Detectar apertura de canary — discriminar por intención:
     * un ransomware abre los canaries para ESCRIBIR (cifrarlos); un backup
     * (tar/cp -r/rsync), thumbnailer o AV los abre SOLO para leer.
     * Lectura read-only: señal leve (no arma el kill) — sin esto, un
     * cp -r dentro del mount que toca un canary muere en su próxima
     * escritura. */
    if (canary_is_canary(gstate.can, path)) {
        uint32_t pid = fuse_get_context()->pid;
        int write_intent = (fi->flags & O_ACCMODE) != O_RDONLY;
        io_event_t cev = { .type = EV_CANARY, .pid = pid,
                           .ts_ns = clock_gettime_ns() };
        strncpy(cev.path, path, sizeof(cev.path) - 1);
        ring_buf_push(gstate.evbuf, &cev);
        if (write_intent) {
            log_event("canary_open_write", pid, path,
                      "\"verdict\":\"SUSPICIOUS\"");
            detector_signal_canary(gstate.det, path, pid);
        } else {
            log_event("canary_read", pid, path, "\"verdict\":\"NOTE\"");
            detector_note_canary_read(gstate.det, pid);
        }
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

    /* 1. Calcular entropía y χ² del buffer entrante */
    double ent  = entropy_shannon((const uint8_t *)buf, size);
    double chi2 = size >= 256 ? entropy_chi_square((const uint8_t *)buf, size) : 0.0;

    /* 2. Registrar evento */
    io_event_t ev = {
        .type    = EV_WRITE,
        .pid     = pid,
        .size    = (uint64_t)size,
        .entropy = ent,
        .chi2    = chi2,
        .ts_ns   = clock_gettime_ns(),
    };
    strncpy(ev.path, path, sizeof(ev.path) - 1);
    ring_buf_push(gstate.evbuf, &ev);

    /* 3. Evaluación sincrónica rápida (umbrales locales por proceso) */
    int verdict = detector_check_write(gstate.det, pid, path, ent, size,
                                       chi2);
    if (verdict == VERDICT_BLOCK) {
        char extra[160];
        snprintf(extra, sizeof(extra),
                 "\"entropy\":%.4f,\"size\":%zu,\"verdict\":\"BLOCK\","
                 "\"mode\":\"%s\",\"brake\":%d",
                 ent, size, g_shadow ? "shadow" : "enforce",
                 detector_global_brake_armed(gstate.det));
        log_event("write_blocked", pid, path, extra);
        if (!g_shadow) {
            /* Bloquear escritura y disparar snapshot de emergencia */
            zfs_snapshot_emergency(gstate.zfs_dataset);
            mitigate_and_log(pid, path);
            return -EPERM;   /* permiso denegado → ransomware ve error */
        }
        /* shadow: registrar y dejar pasar */
    } else if (verdict == VERDICT_SUSPICIOUS) {
        /* Snapshot temprano (pre-daño): en el primer WARN el estado está
         * casi limpio — un snapshot acá preserva los datos previos al
         * ataque. El cooldown interno lo dedup; el costo es CoW. */
        if (!g_shadow)
            zfs_snapshot_emergency(gstate.zfs_dataset);
        uint64_t now = clock_gettime_ns();
        uint64_t last = __atomic_load_n(&last_susp_log_ns, __ATOMIC_RELAXED);
        if (now - last > 1000000000ULL) {   /* ≥1s entre logs */
            __atomic_store_n(&last_susp_log_ns, now, __ATOMIC_RELAXED);
            char extra[160];
            snprintf(extra, sizeof(extra),
                     "\"entropy\":%.4f,\"size\":%zu,"
                     "\"verdict\":\"SUSPICIOUS\"",
                     ent, size);
            log_event("write_suspicious", pid, path, extra);
        }
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

    /* Renombrar un canary: cambio de extensión (.docx → .locked) es
     * comportamiento de ransomware → señal fuerte. Un usuario moviendo
     * el archivo sin cambiar extensión → solo señal leve (misma regla
     * anti-FP que gfs_open). */
    if (canary_is_canary(gstate.can, from)) {
        io_event_t cev = { .type = EV_CANARY, .pid = pid,
                           .ts_ns = clock_gettime_ns() };
        strncpy(cev.path, from, sizeof(cev.path) - 1);
        ring_buf_push(gstate.evbuf, &cev);
        if (ext_changed) {
            log_event("canary_renamed", pid, from,
                      "\"verdict\":\"SUSPICIOUS\"");
            detector_signal_canary(gstate.det, from, pid);
        } else {
            log_event("canary_read", pid, from, "\"verdict\":\"NOTE\"");
            detector_note_canary_read(gstate.det, pid);
        }
    }

    int verdict = detector_check_rename(gstate.det, pid, from, to,
                                        ext_changed);
    if (verdict == VERDICT_BLOCK) {
        char extra[192];
        snprintf(extra, sizeof(extra),
                 "\"from\":\"%s\",\"to\":\"%s\",\"ext_changed\":%d,"
                 "\"verdict\":\"BLOCK\",\"mode\":\"%s\",\"brake\":%d",
                 from, to, ext_changed, g_shadow ? "shadow" : "enforce",
                 detector_global_brake_armed(gstate.det));
        log_event("rename_blocked", pid, from, extra);
        if (!g_shadow) {
            zfs_snapshot_emergency(gstate.zfs_dataset);
            mitigate_and_log(pid, from);
            return -EPERM;
        }
        /* shadow: registrar y dejar pasar */
    } else if (verdict == VERDICT_SUSPICIOUS) {
        /* Snapshot temprano pre-daño (dedup por cooldown interno) */
        if (!g_shadow)
            zfs_snapshot_emergency(gstate.zfs_dataset);
        char extra[192];
        snprintf(extra, sizeof(extra),
                 "\"from\":\"%s\",\"to\":\"%s\",\"ext_changed\":%d,"
                 "\"verdict\":\"SUSPICIOUS\"",
                 from, to, ext_changed);
        log_event("rename_suspicious", pid, from, extra);
    }

    return renameat2(AT_FDCWD, rf, AT_FDCWD, rt, flags) < 0 ? -errno : 0;
}

static int gfs_unlink(const char *path) {
    uint32_t pid = fuse_get_context()->pid;

    if (canary_is_canary(gstate.can, path)) {
        /* Eliminación de canary = ataque confirmado */
        io_event_t cev = { .type = EV_CANARY, .pid = pid,
                           .ts_ns = clock_gettime_ns() };
        strncpy(cev.path, path, sizeof(cev.path) - 1);
        ring_buf_push(gstate.evbuf, &cev);
        log_event("canary_deleted", pid, path,
                  "\"verdict\":\"ATTACK_CONFIRMED\"");
        detector_confirm_attack(gstate.det, pid);
        if (!g_shadow) {
            zfs_snapshot_emergency(gstate.zfs_dataset);
            mitigate_and_log(pid, path);
            return -EPERM;
        }
        /* shadow: el estado del detector ya quedó marcado; dejar pasar */
    }

    io_event_t ev = { .type = EV_UNLINK, .pid = pid,
                      .ts_ns = clock_gettime_ns() };
    strncpy(ev.path, path, sizeof(ev.path) - 1);
    ring_buf_push(gstate.evbuf, &ev);

    /* Caza de backups / borrado de originales tras cifrar: el unlink
     * alimenta el score (solo no bloquea — make clean debe pasar) */
    int verdict = detector_check_unlink(gstate.det, pid, path);
    if (verdict == VERDICT_BLOCK) {
        char extra[192];
        snprintf(extra, sizeof(extra),
                 "\"verdict\":\"BLOCK\",\"mode\":\"%s\",\"brake\":%d",
                 g_shadow ? "shadow" : "enforce",
                 detector_global_brake_armed(gstate.det));
        log_event("unlink_blocked", pid, path, extra);
        if (!g_shadow) {
            zfs_snapshot_emergency(gstate.zfs_dataset);
            mitigate_and_log(pid, path);
            return -EPERM;
        }
        /* shadow: registrar y dejar pasar */
    }

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
    g_shadow         = getenv_bool("GUARDIAN_SHADOW_MODE");
    gstate.real_root   = get_env_or("GUARDIAN_REAL_ROOT", "/zpool/data");
    gstate.zfs_dataset = get_env_or("GUARDIAN_ZFS_DATASET", "tank/data");
    /* NOTE: real_root and zfs_dataset are never freed — this is a
     * long-running FUSE daemon so the one-time allocation at startup
     * is negligible and the OS reclaims it on process exit. */
    gstate.det         = detector_init(WINDOW_SECS, ENTROPY_THRESHOLD,
                                       WRITE_RATE_THRESH, RENAME_THRESH);
    gstate.can         = canary_init(gstate.real_root);
    gstate.evbuf       = ring_buf_create(65536, sizeof(io_event_t));
    gstate.running     = 1;

    /* Expose to cross-module globals */
    evbuf    = gstate.evbuf;
    detector = gstate.det;

    /* Thread analizador asíncrono (para ML y métricas complejas) */
    pthread_create(&gstate.analyzer_tid, NULL, analyzer_thread, &gstate);

    canary_deploy(gstate.can, 20);    /* sembrar 20 archivos canary */
    zfs_snapshot_schedule(gstate.zfs_dataset, 60); /* snap cada 60s */

    /* Config visible en el log (provenance del dataset) + modo */
    {
        char extra[192];
        snprintf(extra, sizeof(extra),
                 "\"mode\":\"%s\",\"window_secs\":%d,"
                 "\"entropy_threshold\":%.1f,\"write_thresh\":%d,"
                 "\"rename_thresh\":%d",
                 g_shadow ? "shadow" : "enforce",
                 WINDOW_SECS, ENTROPY_THRESHOLD,
                 WRITE_RATE_THRESH, RENAME_THRESH);
        log_event("daemon_start", 0, gstate.real_root, extra);
    }
    if (g_shadow)
        fprintf(stderr, "[guardian] SHADOW MODE: se registran veredictos "
                        "sin bloquear (sin snapshot/kill/EPERM)\n");

    return fuse_main(argc, argv, &guardian_ops, &gstate);
}
