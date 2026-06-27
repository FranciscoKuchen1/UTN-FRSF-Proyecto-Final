#ifndef ZFS_SNAP_H
#define ZFS_SNAP_H

#include <stdint.h>
#include <pthread.h>

typedef struct {
    char     *dataset;
    uint32_t  interval_secs;
    volatile int running;
} snap_thread_arg_t;

int zfs_snapshot_emergency(const char *dataset);
pthread_t zfs_snapshot_schedule(const char *dataset, uint32_t interval_secs);
int zfs_rollback_latest(const char *dataset, const char *snap_prefix);

#endif /* ZFS_SNAP_H */
