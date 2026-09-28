#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <signal.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include "mitigation.h"

/*
 * Mitigación: terminación del proceso atacante.
 *
 * Antes de matar se verifica la identidad del PID vía /proc/<pid>/stat
 * (campo 22, starttime). Sin esto, un veredicto async (ML) o un estado
 * per-PID persistente puede apuntar a un PID que ya murió y fue
 * reutilizado por un proceso inocente → SIGKILL al proceso equivocado.
 */

/* starttime del proceso (campo 22 de /proc/<pid>/stat) — identidad del
 * proceso, no cambia mientras viva y es único por encarnación del PID.
 * Retorna 0 si el PID no existe o /proc no está disponible. */
static uint64_t read_proc_starttime(uint32_t pid) {
    char path[64];
    char line[1024];

    snprintf(path, sizeof(path), "/proc/%u/stat", pid);
    FILE *f = fopen(path, "r");
    if (!f) return 0;

    int ok = (fgets(line, sizeof(line), f) != NULL);
    fclose(f);
    if (!ok) return 0;

    /* comm (campo 2) puede contener espacios y paréntesis → parsear
     * desde el último ')' de la línea. */
    char *rp = strrchr(line, ')');
    if (!rp) return 0;

    /* Tras ')' siguen los campos 3..N como tokens separados por espacios.
     * starttime es el campo 22 → el token 20 después de ')'.
     * Avanzar 20 espacios: p queda en el espacio que precede al token 20. */
    char *p = rp;
    for (int tok = 3; tok <= 22; tok++) {
        p = strchr(p + 1, ' ');
        if (!p) return 0;   /* línea truncada */
    }
    return (uint64_t)strtoull(p + 1, NULL, 10);
}

int mitigation_kill_process(uint32_t pid, uint64_t expected_starttime) {
    uint64_t cur = read_proc_starttime(pid);
    if (cur == 0) {
        fprintf(stderr, "[mitigation] PID %u ya no existe — nada que matar\n",
                pid);
        return MIT_NO_PROCESS;
    }
    if (expected_starttime != 0 && cur != expected_starttime) {
        fprintf(stderr, "[mitigation] PID %u reutilizado "
                        "(starttime %llu != %llu) — kill omitido\n",
                pid, (unsigned long long)cur,
                (unsigned long long)expected_starttime);
        return MIT_PID_REUSED;
    }
    if (kill((pid_t)pid, SIGKILL) == 0) {
        fprintf(stderr, "[mitigation] Killed process PID=%u\n", pid);
        return MIT_KILLED;
    }
    perror("[mitigation] kill failed");
    return MIT_KILL_FAILED;
}
