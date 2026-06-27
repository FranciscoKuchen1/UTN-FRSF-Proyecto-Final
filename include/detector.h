#ifndef DETECTOR_H
#define DETECTOR_H

#include <stdint.h>

#define VERDICT_NORMAL     0
#define VERDICT_SUSPICIOUS 1
#define VERDICT_BLOCK      2

/* Forward-declared opaque context — definition in detector.c */
struct detector_ctx;

struct detector_ctx *detector_init(uint32_t window_secs,
                                   double entropy_thresh,
                                   uint64_t write_thresh,
                                   uint64_t rename_thresh);

int detector_check_write(struct detector_ctx *ctx, uint32_t pid,
                         const char *path, double entropy, size_t size);

int detector_check_rename(struct detector_ctx *ctx, uint32_t pid,
                          const char *from, const char *to, int ext_changed);

void detector_signal_canary(struct detector_ctx *ctx, const char *path,
                            uint32_t pid);

void detector_confirm_attack(struct detector_ctx *ctx, uint32_t pid);

#endif /* DETECTOR_H */
