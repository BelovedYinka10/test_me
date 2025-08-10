#define _GNU_SOURCE
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <sched.h>
#include <unistd.h>
#include <sys/resource.h>
#include <sys/ioctl.h>
#include <linux/perf_event.h>
#include <asm/unistd.h>
#include <time.h>

#include "kem.h"  // Crystal Kyber
#define ITERATIONS 1000

// Time difference in nanoseconds
double time_diff_ns(struct timespec start, struct timespec end) {
    return (end.tv_sec - start.tv_sec) * 1e9 + (end.tv_nsec - start.tv_nsec);
}

// perf_event_open syscall wrapper
static long perf_event_open(struct perf_event_attr *hw_event, pid_t pid,
                            int cpu, int group_fd, unsigned long flags) {
    return syscall(__NR_perf_event_open, hw_event, pid, cpu, group_fd, flags);
}

int main() {
    // Pin to CPU 0
    cpu_set_t mask;
    CPU_ZERO(&mask);
    CPU_SET(0, &mask);
    sched_setaffinity(0, sizeof(mask), &mask);

    // Setup perf counter
    struct perf_event_attr pe;
    memset(&pe, 0, sizeof(struct perf_event_attr));
    pe.type = PERF_TYPE_HARDWARE;
    pe.size = sizeof(struct perf_event_attr);
    pe.config = PERF_COUNT_HW_CPU_CYCLES;
    pe.disabled = 1;
    pe.exclude_kernel = 1;
    pe.exclude_hv = 1;

    uint8_t pk[CRYPTO_PUBLICKEYBYTES];
    uint8_t sk[CRYPTO_SECRETKEYBYTES];
    uint8_t ct[CRYPTO_CIPHERTEXTBYTES];
    uint8_t ss1[CRYPTO_BYTES];
    uint8_t ss2[CRYPTO_BYTES];

    uint64_t total_cycles_kp = 0, total_cycles_enc = 0, total_cycles_dec = 0;
    double total_time_kp = 0, total_time_enc = 0, total_time_dec = 0;
    long mem_kp = 0, mem_enc = 0, mem_dec = 0;

    for (int i = 0; i < ITERATIONS; i++) {
        // === Keypair ===
        int fd = perf_event_open(&pe, 0, 0, -1, 0);
        struct timespec start, end;
        struct rusage ru_before, ru_after;

        getrusage(RUSAGE_SELF, &ru_before);
        clock_gettime(CLOCK_MONOTONIC, &start);
        ioctl(fd, PERF_EVENT_IOC_RESET, 0);
        ioctl(fd, PERF_EVENT_IOC_ENABLE, 0);

        crypto_kem_keypair(pk, sk);

        ioctl(fd, PERF_EVENT_IOC_DISABLE, 0);
        clock_gettime(CLOCK_MONOTONIC, &end);
        getrusage(RUSAGE_SELF, &ru_after);

        uint64_t cycles = 0;
        read(fd, &cycles, sizeof(cycles));
        close(fd);

        total_cycles_kp += cycles;
        total_time_kp += time_diff_ns(start, end) / 1e6; // ms
        mem_kp += (ru_after.ru_maxrss - ru_before.ru_maxrss);

        // === Encapsulation ===
        fd = perf_event_open(&pe, 0, 0, -1, 0);
        getrusage(RUSAGE_SELF, &ru_before);
        clock_gettime(CLOCK_MONOTONIC, &start);
        ioctl(fd, PERF_EVENT_IOC_RESET, 0);
        ioctl(fd, PERF_EVENT_IOC_ENABLE, 0);

        crypto_kem_enc(ct, ss1, pk);

        ioctl(fd, PERF_EVENT_IOC_DISABLE, 0);
        clock_gettime(CLOCK_MONOTONIC, &end);
        getrusage(RUSAGE_SELF, &ru_after);
        read(fd, &cycles, sizeof(cycles));
        close(fd);

        total_cycles_enc += cycles;
        total_time_enc += time_diff_ns(start, end) / 1e6;
        mem_enc += (ru_after.ru_maxrss - ru_before.ru_maxrss);

        // === Decapsulation ===
        fd = perf_event_open(&pe, 0, 0, -1, 0);
        getrusage(RUSAGE_SELF, &ru_before);
        clock_gettime(CLOCK_MONOTONIC, &start);
        ioctl(fd, PERF_EVENT_IOC_RESET, 0);
        ioctl(fd, PERF_EVENT_IOC_ENABLE, 0);

        crypto_kem_dec(ss2, ct, sk);

        ioctl(fd, PERF_EVENT_IOC_DISABLE, 0);
        clock_gettime(CLOCK_MONOTONIC, &end);
        getrusage(RUSAGE_SELF, &ru_after);
        read(fd, &cycles, sizeof(cycles));
        close(fd);

        total_cycles_dec += cycles;
        total_time_dec += time_diff_ns(start, end) / 1e6;
        mem_dec += (ru_after.ru_maxrss - ru_before.ru_maxrss);
    }

    // Print averages
    printf("\n=== Crystal Kyber Benchmark (%d iterations) ===\n", ITERATIONS);

    printf("\n[Keypair]");
    printf("\n  Avg Time:   %.3f ms", total_time_kp / ITERATIONS);
    printf("\n  Avg Cycles: %llu", (unsigned long long)(total_cycles_kp / ITERATIONS));
    printf("\n  Avg Mem:    %ld KB", mem_kp / ITERATIONS);

    printf("\n\n[Encapsulation]");
    printf("\n  Avg Time:   %.3f ms", total_time_enc / ITERATIONS);
    printf("\n  Avg Cycles: %llu", (unsigned long long)(total_cycles_enc / ITERATIONS));
    printf("\n  Avg Mem:    %ld KB", mem_enc / ITERATIONS);

    printf("\n\n[Decapsulation]");
    printf("\n  Avg Time:   %.3f ms", total_time_dec / ITERATIONS);
    printf("\n  Avg Cycles: %llu", (unsigned long long)(total_cycles_dec / ITERATIONS));
    printf("\n  Avg Mem:    %ld KB", mem_dec / ITERATIONS);

    // Final shared secret check
    crypto_kem_keypair(pk, sk);
    crypto_kem_enc(ct, ss1, pk);
    crypto_kem_dec(ss2, ct, sk);

    printf("\n\n✅ Shared Secret Match: %s\n",
           (memcmp(ss1, ss2, CRYPTO_BYTES) == 0) ? "YES" : "❌ NO");

    return 0;
}
