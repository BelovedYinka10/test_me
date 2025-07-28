#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include "kem.h"        // Kyber KEM API (from PQClean or your implementation)
#include "cpucycles.h"  // CPU cycle measurement

#ifdef __APPLE__
#include <malloc/malloc.h>
#else
#include <malloc.h>
#endif

#define ITERATIONS 1000

// ===== Function Prototypes =====
static void update_stats(uint64_t cycles, uint64_t *min, uint64_t *max, uint64_t *sum);
double calculate_stddev(uint64_t *data, int n, double mean);

// ===== Main Benchmark Tool =====
int main() {
    printf("=== Kyber Memory & Cycle Benchmark ===\n");

    // Allocate on heap for profiling
    uint8_t *pk  = malloc(CRYPTO_PUBLICKEYBYTES);
    uint8_t *sk  = malloc(CRYPTO_SECRETKEYBYTES);
    uint8_t *ct  = malloc(CRYPTO_CIPHERTEXTBYTES);
    uint8_t *ss1 = malloc(CRYPTO_BYTES);
    uint8_t *ss2 = malloc(CRYPTO_BYTES);

    if (!pk || !sk || !ct || !ss1 || !ss2) {
        fprintf(stderr, "Memory allocation failed\n");
        return 1;
    }

    printf("[Heap] PK:  %zu bytes\n", malloc_usable_size(pk));
    printf("[Heap] SK:  %zu bytes\n", malloc_usable_size(sk));
    printf("[Heap] CT:  %zu bytes\n", malloc_usable_size(ct));
    printf("[Heap] SS1: %zu bytes\n", malloc_usable_size(ss1));
    printf("[Heap] SS2: %zu bytes\n", malloc_usable_size(ss2));

    // Estimated stack sizes (static, not precise)
    size_t stack_keypair = CRYPTO_PUBLICKEYBYTES + CRYPTO_SECRETKEYBYTES;
    size_t stack_encap   = CRYPTO_PUBLICKEYBYTES + CRYPTO_CIPHERTEXTBYTES + CRYPTO_BYTES;
    size_t stack_decap   = CRYPTO_SECRETKEYBYTES + CRYPTO_CIPHERTEXTBYTES + CRYPTO_BYTES;

    printf("\n[Static Stack Estimate]\n");
    printf("  Keypair:       ~ %zu bytes\n", stack_keypair);
    printf("  Encapsulation: ~ %zu bytes\n", stack_encap);
    printf("  Decapsulation: ~ %zu bytes\n", stack_decap);

    // Suggest using -fstack-usage for real stack profiling
    printf("\n[Tip] Use compiler flag -fstack-usage to generate .su files with accurate per-function stack usage.\n");

    // ===== Warm-up =====
    for (int i = 0; i < 10; i++) {
        crypto_kem_keypair(pk, sk);
        crypto_kem_enc(ct, ss1, pk);
        crypto_kem_dec(ss2, ct, sk);
    }

    // ===== Cycle Benchmark =====
    uint64_t min_kp = -1, max_kp = 0, sum_kp = 0;
    uint64_t min_enc = -1, max_enc = 0, sum_enc = 0;
    uint64_t min_dec = -1, max_dec = 0, sum_dec = 0;

    uint64_t cycles_kp[ITERATIONS], cycles_enc[ITERATIONS], cycles_dec[ITERATIONS];

    uint64_t overhead = cpucycles_overhead();
    printf("\n[Info] cpucycles overhead: %llu cycles\n", (unsigned long long)overhead);

    uint64_t start, end, diff;

    for (int i = 0; i < ITERATIONS; i++) {
        // Keypair
        start = cpucycles();
        crypto_kem_keypair(pk, sk);
        end = cpucycles();
        diff = end - start;
        update_stats(diff, &min_kp, &max_kp, &sum_kp);
        cycles_kp[i] = diff;

        // Encapsulation
        start = cpucycles();
        crypto_kem_enc(ct, ss1, pk);
        end = cpucycles();
        diff = end - start;
        update_stats(diff, &min_enc, &max_enc, &sum_enc);
        cycles_enc[i] = diff;

        // Decapsulation
        start = cpucycles();
        crypto_kem_dec(ss2, ct, sk);
        end = cpucycles();
        diff = end - start;
        update_stats(diff, &min_dec, &max_dec, &sum_dec);
        cycles_dec[i] = diff;
    }

    // ===== Final Stats =====
    double avg_kp = sum_kp / (double)ITERATIONS;
    double avg_enc = sum_enc / (double)ITERATIONS;
    double avg_dec = sum_dec / (double)ITERATIONS;

    double std_kp = calculate_stddev(cycles_kp, ITERATIONS, avg_kp);
    double std_enc = calculate_stddev(cycles_enc, ITERATIONS, avg_enc);
    double std_dec = calculate_stddev(cycles_dec, ITERATIONS, avg_dec);

    printf("\n[Cycle Benchmark: %d iterations]\n", ITERATIONS);
    printf("  Keypair:       min %llu, max %llu, avg %.2f, stddev %.2f\n",
           min_kp, max_kp, avg_kp, std_kp);
    printf("  Encapsulation: min %llu, max %llu, avg %.2f, stddev %.2f\n",
           min_enc, max_enc, avg_enc, std_enc);
    printf("  Decapsulation: min %llu, max %llu, avg %.2f, stddev %.2f\n",
           min_dec, max_dec, avg_dec, std_dec);

    printf("\nShared Secret Match: %s\n",
           (memcmp(ss1, ss2, CRYPTO_BYTES) == 0) ? "YES" : "NO");

    // ===== Clean Up =====
    free(pk); free(sk); free(ct); free(ss1); free(ss2);
    return 0;
}

// ===== Helpers =====
static void update_stats(uint64_t cycles, uint64_t *min, uint64_t *max, uint64_t *sum) {
    if (cycles < *min) *min = cycles;
    if (cycles > *max) *max = cycles;
    *sum += cycles;
}

double calculate_stddev(uint64_t *data, int n, double mean) {
    double variance = 0;
    for (int i = 0; i < n; i++) {
        variance += (data[i] - mean) * (data[i] - mean);
    }
    return sqrt(variance / n);
}
