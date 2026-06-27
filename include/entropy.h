#ifndef ENTROPY_H
#define ENTROPY_H

#include <stdint.h>
#include <stddef.h>

double entropy_shannon(const uint8_t *buf, size_t len);
double entropy_chi_square(const uint8_t *buf, size_t len);
double *entropy_sliding_window(const uint8_t *buf, size_t len, size_t block_sz, size_t *n_blocks);
double entropy_autocorrelation(const double *H, size_t n);
double entropy_chi2_from_hist(const uint64_t hist[256], uint64_t total);

#endif /* ENTROPY_H */
