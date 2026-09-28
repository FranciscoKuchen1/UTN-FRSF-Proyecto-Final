#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include "canary.h"

/*
 * Estrategia de despliegue:
 * - Nombres con prefijos "A_", "ZZ_" (primeros/últimos en orden lexicográfico)
 *   porque ransomware suele procesar en orden alfabético
 * - Extensiones objetivo: .docx, .pdf, .jpg (las más atacadas)
 * - Distribuidos en subdirectorios a distintas profundidades
 * - Contenido aparenta ser real (unos KB de datos plausibles)
 * - Atributos: último acceso muy reciente (para no parecer artificiales)
 */

static const char *CANARY_NAMES[] = {
    "A_important_report.docx",
    "A_financials_2025.xlsx",
    "ZZ_backup_keys.txt",
    "ZZ_passwords_old.pdf",
    ".hidden_canary_01.dat",     /* oculto, algunos ransomware los procesan */
    "resume_final_v3.docx",
    "family_photos_2024.jpg",
};
#define N_CANARY_NAMES 7

static const char *CANARY_DIRS[] = { "", "docs", "finanzas", "backup" };
#define N_CANARY_DIRS 4

struct canary_ctx {
    char   **paths;        /* rutas absolutas de canaries desplegados */
    size_t   n_paths;
    char    *root;
};

struct canary_ctx *canary_init(const char *root) {
    struct canary_ctx *ctx = calloc(1, sizeof(*ctx));
    ctx->root = strdup(root);
    return ctx;
}

void canary_deploy(struct canary_ctx *ctx, int count) {
    /* Contenido simulado: bytes semi-aleatorios con baja entropía
     * para que parezca texto real, no datos cifrados */
    const char *fake_content =
        "Project Summary - Q4 2025\n"
        "Revenue: $2.4M | Growth: 18%\n"
        "Key metrics attached. Please review.\n"
        "Confidential - Internal Use Only\n";
    size_t fake_len = strlen(fake_content);

    if (count <= 0) return;

    for (int i = 0; i < count; i++) {
        const char *tpl = CANARY_NAMES[i % N_CANARY_NAMES];
        const char *dir = CANARY_DIRS[i % N_CANARY_DIRS];
        char name[512];

        if (i < N_CANARY_NAMES) {
            snprintf(name, sizeof(name), "%s", tpl);
        } else {
            /* Sufijo incremental antes de la extensión para nombres únicos
             * cuando count > N_CANARY_NAMES */
            const char *dot = strrchr(tpl, '.');
            if (dot && dot != tpl) {
                snprintf(name, sizeof(name), "%.*s_%d%s",
                         (int)(dot - tpl), tpl,
                         i / N_CANARY_NAMES + 1, dot);
            } else {
                snprintf(name, sizeof(name), "%s_%d", tpl,
                         i / N_CANARY_NAMES + 1);
            }
        }

        char path[4096];
        if (*dir) {
            snprintf(path, sizeof(path), "%s/%s", ctx->root, dir);
            mkdir(path, 0755);   /* EEXIST esperado en re-deploy */
            snprintf(path, sizeof(path), "%s/%s/%s", ctx->root, dir, name);
        } else {
            snprintf(path, sizeof(path), "%s/%s", ctx->root, name);
        }

        int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
        if (fd < 0) continue;

        /* Rellenar con KB de contenido plausible */
        for (int k = 0; k < 4; k++)
            write(fd, fake_content, fake_len);
        close(fd);

        ctx->paths = realloc(ctx->paths,
                             (ctx->n_paths + 1) * sizeof(char *));
        ctx->paths[ctx->n_paths++] = strdup(path);
    }
}

int canary_is_canary(struct canary_ctx *ctx, const char *fuse_path) {
    for (size_t i = 0; i < ctx->n_paths; i++) {
        /* Comparar la parte del path relativo al mountpoint */
        const char *rel = ctx->paths[i] + strlen(ctx->root);
        if (strcmp(rel, fuse_path) == 0)
            return 1;
    }
    return 0;
}
