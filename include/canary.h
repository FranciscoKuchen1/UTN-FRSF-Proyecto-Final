#ifndef CANARY_H
#define CANARY_H

/* Opaque context — definition in canary.c */
struct canary_ctx;

struct canary_ctx *canary_init(const char *root);
void canary_deploy(struct canary_ctx *ctx, int count);
int canary_is_canary(struct canary_ctx *ctx, const char *fuse_path);

#endif /* CANARY_H */
