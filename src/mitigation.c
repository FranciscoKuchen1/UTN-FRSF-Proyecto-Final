#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <signal.h>
#include <stdio.h>
#include <sys/types.h>
#include "mitigation.h"

int mitigation_kill_process(uint32_t pid) {
    if (kill((pid_t)pid, SIGKILL) == 0) {
        fprintf(stderr, "[mitigation] Killed process PID=%u\n", pid);
        return 0;
    }
    perror("[mitigation] kill failed");
    return -1;
}
