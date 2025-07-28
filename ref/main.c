#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "kem.h"        // Crystal Kyber KEM functions
#include "cpucycles.h"  // CPU cycle counter

#define ITERATIONS 1000

// Helper function to update stats
static void update_stats(uint64_t cycles, uint64_t *min, uint64_t *max, uint64_t *sum) {
    if (cycles < *min) *min = cycles;
    if (cycles > *max) *max = cycles;
    *sum += cycles;
}

int main() {
    uint8_t pk[CRYPTO_PUBLICKEYBYTES];
    uint8_t sk[CRYPTO_SECRETKEYBYTES];
    uint8_t ct[CRYPTO_CIPHERTEXTBYTES];
    uint8_t ss1[CRYPTO_BYTES];
    uint8_t ss2[CRYPTO_BYTES];

    uint64_t start, end, diff;
    uint64_t min_kp = (uint64_t)-1, max_kp = 0, sum_kp = 0;
    uint64_t min_enc = (uint64_t)-1, max_enc = 0, sum_enc = 0;
    uint64_t min_dec = (uint64_t)-1, max_dec = 0, sum_dec = 0;

    printf("[Info] cpucycles overhead: %llu cycles\n", (unsigned long long)cpucycles_overhead());

    for (int i = 0; i < ITERATIONS; i++) {
        // --- Keypair ---
        start = cpucycles();
        crypto_kem_keypair(pk, sk);
        end = cpucycles();
        diff = end - start;
        update_stats(diff, &min_kp, &max_kp, &sum_kp);

        // --- Encapsulation ---
        start = cpucycles();
        crypto_kem_enc(ct, ss1, pk);
        end = cpucycles();
        diff = end - start;
        update_stats(diff, &min_enc, &max_enc, &sum_enc);

        // --- Decapsulation ---
        start = cpucycles();
        crypto_kem_dec(ss2, ct, sk);
        end = cpucycles();
        diff = end - start;
        update_stats(diff, &min_dec, &max_dec, &sum_dec);
    }

    // --- Print results ---
    printf("\n=== Crystal Kyber Benchmark (%d iterations) ===\n", ITERATIONS);

    printf("\n[Keypair]");
    printf("\n  Min Cycles: %llu", (unsigned long long)min_kp);
    printf("\n  Max Cycles: %llu", (unsigned long long)max_kp);
    printf("\n  Avg Cycles: %llu", (unsigned long long)(sum_kp / ITERATIONS));

    printf("\n\n[Encapsulation]");
    printf("\n  Min Cycles: %llu", (unsigned long long)min_enc);
    printf("\n  Max Cycles: %llu", (unsigned long long)max_enc);
    printf("\n  Avg Cycles: %llu", (unsigned long long)(sum_enc / ITERATIONS));

    printf("\n\n[Decapsulation]");
    printf("\n  Min Cycles: %llu", (unsigned long long)min_dec);
    printf("\n  Max Cycles: %llu", (unsigned long long)max_dec);
    printf("\n  Avg Cycles: %llu\n", (unsigned long long)(sum_dec / ITERATIONS));

    // --- Verification ---
    crypto_kem_keypair(pk, sk);
    crypto_kem_enc(ct, ss1, pk);
    crypto_kem_dec(ss2, ct, sk);
    printf("\nShared Secret Match: %s\n",
           (memcmp(ss1, ss2, CRYPTO_BYTES) == 0) ? "YES" : "NO");

    return 0;
}
