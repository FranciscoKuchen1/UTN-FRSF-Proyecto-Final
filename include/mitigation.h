#ifndef MITIGATION_H
#define MITIGATION_H

#include <stdint.h>

/* Resultados de mitigation_kill_process() */
#define MIT_KILLED        0
#define MIT_NO_PROCESS  (-1)   /* el PID ya no existe (ESRCH) */
#define MIT_PID_REUSED  (-2)   /* starttime difiere → PID reutilizado; NO matar */
#define MIT_KILL_FAILED (-3)   /* kill() falló por otro motivo */

/* Mata el PID solo si su identidad coincide con la registrada al crear la
 * entrada del detector (starttime). expected_starttime = 0 desactiva la
 * verificación. Evita matar a un proceso inocente que reutilizó el PID de
 * un atacante ya muerto (el veredicto async del ML abre esa ventana). */
int mitigation_kill_process(uint32_t pid, uint64_t expected_starttime);

#endif /* MITIGATION_H */
