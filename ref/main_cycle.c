#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "kem.h"        // Kyber KEM API (Crystal or PQClean)
#include "cpucycles.h"  // CPU cycle measurement

#ifdef __APPLE__
#include <malloc/malloc.h>
#else
#include <malloc.h>
#endif

#define ITERATIONS 1000

// Helper function to update stats
static void update_stats(uint64_t cycles, uint64_t *min, uint64_t *max, uint64_t *sum) {
    if (cycles < *min) *min = cycles;
    if (cycles > *max) *max = cycles;
    *sum += cycles;
}

int main() {
    printf("=== Kyber Memory & Cycle Benchmark ===\n");

    // Allocate on heap for tracking heap memory usage
    uint8_t *pk  = malloc(CRYPTO_PUBLICKEYBYTES);
    uint8_t *sk  = malloc(CRYPTO_SECRETKEYBYTES);
    uint8_t *ct  = malloc(CRYPTO_CIPHERTEXTBYTES);
    uint8_t *ss1 = malloc(CRYPTO_BYTES);
    uint8_t *ss2 = malloc(CRYPTO_BYTES);

    if (!pk || !sk || !ct || !ss1 || !ss2) {
        fprintf(stderr, "Memory allocation failed\n");
        return 1;
    }

    printf("[Heap] PK:  %zu bytes\n", malloc_size(pk));
    printf("[Heap] SK:  %zu bytes\n", malloc_size(sk));
    printf("[Heap] CT:  %zu bytes\n", malloc_size(ct));
    printf("[Heap] SS1: %zu bytes\n", malloc_size(ss1));
    printf("[Heap] SS2: %zu bytes\n", malloc_size(ss2));

    // Stack usage (static sizeof)
    size_t stack_keypair = CRYPTO_PUBLICKEYBYTES + CRYPTO_SECRETKEYBYTES;
    size_t stack_encap   = CRYPTO_PUBLICKEYBYTES + CRYPTO_CIPHERTEXTBYTES + CRYPTO_BYTES;
    size_t stack_decap   = CRYPTO_PUBLICKEYBYTES + CRYPTO_SECRETKEYBYTES + CRYPTO_CIPHERTEXTBYTES + CRYPTO_BYTES;

    printf("\n[Stack Estimate]\n");
    printf("  Keypair stack ~ %zu bytes\n", stack_keypair);
    printf("  Encapsulation stack ~ %zu bytes\n", stack_encap);
    printf("  Decapsulation stack ~ %zu bytes\n", stack_decap);

    // Cycle measurement
    uint64_t min_kp = (uint64_t)-1, max_kp = 0, sum_kp = 0;
    uint64_t min_enc = (uint64_t)-1, max_enc = 0, sum_enc = 0;
    uint64_t min_dec = (uint64_t)-1, max_dec = 0, sum_dec = 0;

    uint64_t start, end, diff;

    printf("\n[Info] cpucycles overhead: %llu cycles\n", (unsigned long long)cpucycles_overhead());

    for (int i = 0; i < ITERATIONS; i++) {
        // Keypair
        start = cpucycles();
        crypto_kem_keypair(pk, sk);
        end = cpucycles();
        diff = end - start;
        update_stats(diff, &min_kp, &max_kp, &sum_kp);

        // Encapsulation
        start = cpucycles();
        crypto_kem_enc(ct, ss1, pk);
        end = cpucycles();
        diff = end - start;
        update_stats(diff, &min_enc, &max_enc, &sum_enc);

        // Decapsulation
        start = cpucycles();
        crypto_kem_dec(ss2, ct, sk);
        end = cpucycles();
        diff = end - start;
        update_stats(diff, &min_dec, &max_dec, &sum_dec);
    }

    printf("\n[Cycles Benchmark over %d iterations]\n", ITERATIONS);
    printf("  Keypair:       min %llu, max %llu, avg %llu\n",
           (unsigned long long)min_kp, (unsigned long long)max_kp, (unsigned long long)(sum_kp / ITERATIONS));
    printf("  Encapsulation: min %llu, max %llu, avg %llu\n",
           (unsigned long long)min_enc, (unsigned long long)max_enc, (unsigned long long)(sum_enc / ITERATIONS));
    printf("  Decapsulation: min %llu, max %llu, avg %llu\n",
           (unsigned long long)min_dec, (unsigned long long)max_dec, (unsigned long long)(sum_dec / ITERATIONS));

    printf("\nShared Secret Match: %s\n",
           (memcmp(ss1, ss2, CRYPTO_BYTES) == 0) ? "YES" : "NO");

    free(pk);
    free(sk);
    free(ct);
    free(ss1);
    free(ss2);

    return 0;
}
