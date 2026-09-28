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

void detector_destroy(struct detector_ctx *ctx);

/* chi2: estadístico χ² del buffer escrito (0.0 si la muestra es inválida,
 * p.ej. size < 256). Se acumula por ventana para el score de uniformidad. */
int detector_check_write(struct detector_ctx *ctx, uint32_t pid,
                         const char *path, double entropy, size_t size,
                         double chi2);

int detector_check_rename(struct detector_ctx *ctx, uint32_t pid,
                          const char *from, const char *to, int ext_changed);

/* Unlink por PID: alimenta la señal de backup-hunting (análogo Linux del
 * `vssadmin delete shadows` de Windows). Sola no bloquea (rm -rf benigno);
 * suma al score combinada con entropía/renames. */
int detector_check_unlink(struct detector_ctx *ctx, uint32_t pid,
                         const char *path);

/* 1 si el freno global está armado en la ventana actual (para logging). */
int detector_global_brake_armed(struct detector_ctx *ctx);

void detector_signal_canary(struct detector_ctx *ctx, const char *path,
                            uint32_t pid);

/* Lectura read-only de un canary (backup, thumbnail, AV): señal leve —
 * NO arma el kill (un cp -r / tar que toca canaries no debe morir). */
void detector_note_canary_read(struct detector_ctx *ctx, uint32_t pid);

/* starttime del PID registrado al crear su entrada (identidad del proceso
 * vía /proc; 0 si desconocido). Para verificar antes de matar. */
uint64_t detector_pid_starttime(struct detector_ctx *ctx, uint32_t pid);

/* Descarta el estado de un PID (p.ej. tras detectar reuso de PID). */
void detector_reset_pid(struct detector_ctx *ctx, uint32_t pid);

/* Marca el PID como ataque confirmado (veredicto ML o eliminación de canary).
 * Las siguientes write/rename de ese PID reciben VERDICT_BLOCK. */
void detector_confirm_attack(struct detector_ctx *ctx, uint32_t pid);

#endif /* DETECTOR_H */
