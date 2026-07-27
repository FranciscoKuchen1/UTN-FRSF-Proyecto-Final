#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <stdint.h>
#include <stdlib.h>
#include <math.h>
#include "entropy.h"

/*
 * Entropía de Shannon sobre un buffer de bytes.
 * Retorna valor en [0.0, 8.0] bits/byte.
 * Complejidad: O(n) tiempo, O(256) espacio.
 */
double entropy_shannon(const uint8_t *buf, size_t len) {
    if (len == 0) return 0.0;

    uint64_t freq[256] = {0};
    for (size_t i = 0; i < len; i++)
        freq[buf[i]]++;

    double H = 0.0;
    double inv_len = 1.0 / (double)len;
    for (int i = 0; i < 256; i++) {
        if (freq[i] == 0) continue;
        double p = freq[i] * inv_len;
        H -= p * log2(p);
    }
    return H;
}

/*
 * Test Chi-cuadrado para uniformidad de bytes.
 * Si X ~ Uniform(0,255), los bytes cifrados tienen distribución casi uniforme.
 * Retorna el estadístico χ² (cuanto menor, más uniforme → más sospechoso).
 *
 * Umbral típico: χ² < 300 con 255 grados de libertad → sospechoso
 * (p-value > 0.05 → no se rechaza hipótesis de uniformidad)
 */
double entropy_chi_square(const uint8_t *buf, size_t len) {
    if (len < 256) return 1e9;  /* muestra insuficiente */

    uint64_t obs[256] = {0};
    for (size_t i = 0; i < len; i++)
        obs[buf[i]]++;

    double expected = (double)len / 256.0;
    double chi2 = 0.0;
    for (int i = 0; i < 256; i++) {
        double diff = (double)obs[i] - expected;
        chi2 += (diff * diff) / expected;
    }
    return chi2;
}

/*
 * Entropía sobre bloques deslizantes — detecta cifrado parcial de archivo.
 * Ransomware a veces cifra solo los primeros N bytes para mayor velocidad.
 * Retorna array de entropías por bloque (caller libera memoria).
 */
double *entropy_sliding_window(const uint8_t *buf, size_t len,
                                size_t block_sz, size_t *n_blocks) {
    *n_blocks = len / block_sz;
    if (*n_blocks == 0) return NULL;

    double *arr = malloc(*n_blocks * sizeof(double));
    for (size_t i = 0; i < *n_blocks; i++)
        arr[i] = entropy_shannon(buf + i * block_sz, block_sz);
    return arr;
}

/*
 * Correlación de Pearson entre vector de entropías consecutivas.
 * Ransomware tiende a producir entropía uniformemente alta (baja correlación).
 * Archivos normales tienen variaciones de entropía correlacionadas.
 */
double entropy_autocorrelation(const double *H, size_t n) {
    if (n < 2) return 0.0;
    double mean = 0.0;
    for (size_t i = 0; i < n; i++) mean += H[i];
    mean /= n;

    double num = 0.0, den = 0.0;
    for (size_t i = 0; i < n - 1; i++) {
        num += (H[i] - mean) * (H[i+1] - mean);
        den += (H[i] - mean) * (H[i] - mean);
    }
    return den > 0 ? num / den : 0.0;
}

double entropy_chi2_from_hist(const uint64_t hist[256], uint64_t total) {
    if (total == 0) return 0.0;
    double expected = (double)total / 256.0;
    double chi2 = 0.0;
    for (int i = 0; i < 256; i++) {
        double diff = (double)hist[i] - expected;
        chi2 += (diff * diff) / expected;
    }
    return chi2;
}
