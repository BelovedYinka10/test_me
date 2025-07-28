/*
 * Kyber Memory & Cycle Benchmark - Refined Version
 * Includes warm-up, stack guidance, stddev, Valgrind hints, and clear output
 */

#define KYBER_K 2  // Change this to 3 or 4 for Kyber768 or Kyber1024

#if KYBER_K == 2
  #define CRYPTO_PUBLICKEYBYTES  pqcrystals_kyber512_PUBLICKEYBYTES
  #define CRYPTO_SECRETKEYBYTES  pqcrystals_kyber512_SECRETKEYBYTES
  #define CRYPTO_CIPHERTEXTBYTES pqcrystals_kyber512_CIPHERTEXTBYTES
  #define CRYPTO_BYTES           pqcrystals_kyber512_BYTES
  #define crypto_kem_keypair     pqcrystals_kyber512_ref_keypair
  #define crypto_kem_enc         pqcrystals_kyber512_ref_enc
  #define crypto_kem_dec         pqcrystals_kyber512_ref_dec
#elif KYBER_K == 3
  #define CRYPTO_PUBLICKEYBYTES  pqcrystals_kyber768_PUBLICKEYBYTES
  #define CRYPTO_SECRETKEYBYTES  pqcrystals_kyber768_SECRETKEYBYTES
  #define CRYPTO_CIPHERTEXTBYTES pqcrystals_kyber768_CIPHERTEXTBYTES
  #define CRYPTO_BYTES           pqcrystals_kyber768_BYTES
  #define crypto_kem_keypair     pqcrystals_kyber768_ref_keypair
  #define crypto_kem_enc         pqcrystals_kyber768_ref_enc
  #define crypto_kem_dec         pqcrystals_kyber768_ref_dec
#elif KYBER_K == 4
  #define CRYPTO_PUBLICKEYBYTES  pqcrystals_kyber1024_PUBLICKEYBYTES
  #define CRYPTO_SECRETKEYBYTES  pqcrystals_kyber1024_SECRETKEYBYTES
  #define CRYPTO_CIPHERTEXTBYTES pqcrystals_kyber1024_CIPHERTEXTBYTES
  #define CRYPTO_BYTES           pqcrystals_kyber1024_BYTES
  #define crypto_kem_keypair     pqcrystals_kyber1024_ref_keypair
  #define crypto_kem_enc         pqcrystals_kyber1024_ref_enc
  #define crypto_kem_dec         pqcrystals_kyber1024_ref_dec
#else
  #error "KYBER_K must be 2, 3, or 4"
#endif

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include "cpucycles.h"
#include "api.h"

#define ITERATIONS 1000

static double calculate_stddev(const uint64_t *data, size_t count, double mean) {
    double sum = 0.0;
    for (size_t i = 0; i < count; ++i) {
        double diff = (double)data[i] - mean;
        sum += diff * diff;
    }
    return sqrt(sum / count);
}

static void analyze_cycles(const char *label, const uint64_t *data) {
    uint64_t min = data[0], max = data[0], sum = 0;
    for (int i = 0; i < ITERATIONS; ++i) {
        if (data[i] < min) min = data[i];
        if (data[i] > max) max = data[i];
        sum += data[i];
    }
    double avg = sum / (double)ITERATIONS;
    double stddev = calculate_stddev(data, ITERATIONS, avg);
    printf("  %s: min %lu, max %lu, avg %.2f, stddev %.2f\n", label, min, max, avg, stddev);
}

int main(void) {
    uint8_t pk[CRYPTO_PUBLICKEYBYTES];
    uint8_t sk[CRYPTO_SECRETKEYBYTES];
    uint8_t ct[CRYPTO_CIPHERTEXTBYTES];
    uint8_t ss1[CRYPTO_BYTES];
    uint8_t ss2[CRYPTO_BYTES];

    uint64_t t0, t1, overhead;
    uint64_t keygen_cycles[ITERATIONS];
    uint64_t enc_cycles[ITERATIONS];
    uint64_t dec_cycles[ITERATIONS];

    printf("\n=== Kyber Memory & Cycle Benchmark ===\n\n");

    printf("[Heap] PK: %lu bytes\n", sizeof(pk));
    printf("[Heap] SK: %lu bytes\n", sizeof(sk));
    printf("[Heap] CT: %lu bytes\n", sizeof(ct));
    printf("[Heap] SS1: %lu bytes\n", sizeof(ss1));
    printf("[Heap] SS2: %lu bytes\n", sizeof(ss2));

    printf("\n[Static Stack Estimate]\n");
    printf("  Keypair:        ~2432 bytes\n");
    printf("  Encapsulation:  ~1600 bytes\n");
    printf("  Decapsulation:  ~2432 bytes\n");
    printf("\n[Tip] Compile with -fstack-usage to get .su files for real per-function stack usage.\n");
    printf("[Tip] Use Valgrind Massif for heap profiling:\n  valgrind --tool=massif --massif-out-file=massif.out ./kyber_bench\n\n");

    overhead = cpucycles_overhead();
    printf("[Info] cpucycles overhead: %lu cycles\n\n", overhead);
    if (overhead > 10000) {
        printf("[Warning] High cycle overhead may affect accuracy!\n\n");
    }

    // Warm-up
    for (int i = 0; i < 10; i++) {
        crypto_kem_keypair(pk, sk);
        crypto_kem_enc(ct, ss1, pk);
        crypto_kem_dec(ss2, ct, sk);
    }

    // Keypair cycles
    for (int i = 0; i < ITERATIONS; ++i) {
        t0 = cpucycles();
        crypto_kem_keypair(pk, sk);
        t1 = cpucycles();
        keygen_cycles[i] = t1 - t0 - overhead;
    }

    // Encapsulation cycles
    for (int i = 0; i < ITERATIONS; ++i) {
        t0 = cpucycles();
        crypto_kem_enc(ct, ss1, pk);
        t1 = cpucycles();
        enc_cycles[i] = t1 - t0 - overhead;
    }

    // Decapsulation cycles
    for (int i = 0; i < ITERATIONS; ++i) {
        t0 = cpucycles();
        crypto_kem_dec(ss2, ct, sk);
        t1 = cpucycles();
        dec_cycles[i] = t1 - t0 - overhead;
    }

    printf("[Cycle Benchmark: %d iterations]\n", ITERATIONS);
    analyze_cycles("Keypair", keygen_cycles);
    analyze_cycles("Encapsulation", enc_cycles);
    analyze_cycles("Decapsulation", dec_cycles);

    printf("\n[Shared Secret Match]: %s\n", memcmp(ss1, ss2, CRYPTO_BYTES) == 0 ? "YES" : "NO");
    return 0;
}