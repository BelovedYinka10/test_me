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
#include <errno.h>

#include "kem.h"  // PQCrystals Kyber API

#ifndef ITERATIONS
#define ITERATIONS 1000
#endif

// --- timing helpers ---
static inline double time_diff_ns(struct timespec s, struct timespec e) {
    return (e.tv_sec - s.tv_sec) * 1e9 + (e.tv_nsec - s.tv_nsec);
}

// --- perf_event_open wrapper ---
static long perf_event_open(struct perf_event_attr *hw_event, pid_t pid,
                            int cpu, int group_fd, unsigned long flags) {
    return syscall(__NR_perf_event_open, hw_event, pid, cpu, group_fd, flags);
}

// --- pin to CPU 0 (optional) ---
static int pin_to_cpu0(void) {
    cpu_set_t mask;
    CPU_ZERO(&mask);
    CPU_SET(0, &mask);
    if (sched_setaffinity(0, sizeof(mask), &mask) != 0) {
        perror("sched_setaffinity");
        return -1;
    }
    return 0;
}

// --- current RSS in KB via /proc/self/statm ---
static long current_rss_kb(void) {
    static long page_kb = 0;
    if (page_kb == 0) {
        long ps = sysconf(_SC_PAGESIZE);
        if (ps <= 0) return -1;
        page_kb = ps / 1024;
        if (page_kb == 0) page_kb = 1; // avoid div-by-zero
    }
    FILE *f = fopen("/proc/self/statm", "r");
    if (!f) return -1;
    unsigned long size_pages = 0, resident_pages = 0;
    int n = fscanf(f, "%lu %lu", &size_pages, &resident_pages);
    fclose(f);
    if (n != 2) return -1;
    return (long)(resident_pages * page_kb);
}

int main(void) {
    pin_to_cpu0();

    // Setup perf (cycles); if unavailable, we’ll still report time/mem
    struct perf_event_attr pe;
    memset(&pe, 0, sizeof(pe));
    pe.type = PERF_TYPE_HARDWARE;
    pe.size = sizeof(pe);
    pe.config = PERF_COUNT_HW_CPU_CYCLES;
    pe.disabled = 1;
    pe.exclude_kernel = 1;
    pe.exclude_hv = 1;

    int perf_ok = 1;
    int fd_probe = perf_event_open(&pe, 0, 0, -1, 0);
    if (fd_probe == -1) {
        perf_ok = 0;
        fprintf(stderr,
            "Warning: perf_event_open failed (%s). Cycles will be N/A.\n"
            "Hint: try: sudo sh -c 'echo 1 > /proc/sys/kernel/perf_event_paranoid'\n",
            strerror(errno));
    } else {
        close(fd_probe);
    }

    uint8_t pk[CRYPTO_PUBLICKEYBYTES];
    uint8_t sk[CRYPTO_SECRETKEYBYTES];
    uint8_t ct[CRYPTO_CIPHERTEXTBYTES];
    uint8_t ss1[CRYPTO_BYTES];
    uint8_t ss2[CRYPTO_BYTES];

    unsigned long long total_cycles_kp = 0, total_cycles_enc = 0, total_cycles_dec = 0;
    double total_time_kp = 0.0, total_time_enc = 0.0, total_time_dec = 0.0;
    long mem_kp = 0, mem_enc = 0, mem_dec = 0;

    // Warm-up
    for (int i = 0; i < 5; i++) {
        crypto_kem_keypair(pk, sk);
        crypto_kem_enc(ct, ss1, pk);
        crypto_kem_dec(ss2, ct, sk);
    }

    for (int i = 0; i < ITERATIONS; i++) {
        // === Keypair ===
        int fd = -1;
        if (perf_ok) {
            fd = perf_event_open(&pe, 0, 0, -1, 0);
            if (fd == -1) perf_ok = 0;
        }

        long rss_before = current_rss_kb();

        struct timespec start, end;
        clock_gettime(CLOCK_MONOTONIC, &start);
        if (perf_ok) { ioctl(fd, PERF_EVENT_IOC_RESET, 0); ioctl(fd, PERF_EVENT_IOC_ENABLE, 0); }

        crypto_kem_keypair(pk, sk);

        if (perf_ok) { ioctl(fd, PERF_EVENT_IOC_DISABLE, 0); }
        clock_gettime(CLOCK_MONOTONIC, &end);

        long rss_after = current_rss_kb();
        long delta_kb = (rss_after >= 0 && rss_before >= 0) ? (rss_after - rss_before) : 0;

        unsigned long long cycles = 0ULL;
        if (perf_ok) {
            if (read(fd, &cycles, sizeof(cycles)) != (ssize_t)sizeof(cycles)) cycles = 0ULL;
            close(fd);
        }
        total_cycles_kp += cycles;
        total_time_kp += time_diff_ns(start, end) / 1e6;
        mem_kp += delta_kb;

        // === Encapsulation ===
        fd = -1;
        if (perf_ok) {
            fd = perf_event_open(&pe, 0, 0, -1, 0);
            if (fd == -1) perf_ok = 0;
        }

        rss_before = current_rss_kb();

        clock_gettime(CLOCK_MONOTONIC, &start);
        if (perf_ok) { ioctl(fd, PERF_EVENT_IOC_RESET, 0); ioctl(fd, PERF_EVENT_IOC_ENABLE, 0); }

        crypto_kem_enc(ct, ss1, pk);

        if (perf_ok) { ioctl(fd, PERF_EVENT_IOC_DISABLE, 0); }
        clock_gettime(CLOCK_MONOTONIC, &end);

        rss_after = current_rss_kb();
        delta_kb = (rss_after >= 0 && rss_before >= 0) ? (rss_after - rss_before) : 0;

        cycles = 0ULL;
        if (perf_ok) {
            if (read(fd, &cycles, sizeof(cycles)) != (ssize_t)sizeof(cycles)) cycles = 0ULL;
            close(fd);
        }
        total_cycles_enc += cycles;
        total_time_enc += time_diff_ns(start, end) / 1e6;
        mem_enc += delta_kb;

        // === Decapsulation ===
        fd = -1;
        if (perf_ok) {
            fd = perf_event_open(&pe, 0, 0, -1, 0);
            if (fd == -1) perf_ok = 0;
        }

        rss_before = current_rss_kb();

        clock_gettime(CLOCK_MONOTONIC, &start);
        if (perf_ok) { ioctl(fd, PERF_EVENT_IOC_RESET, 0); ioctl(fd, PERF_EVENT_IOC_ENABLE, 0); }

        crypto_kem_dec(ss2, ct, sk);

        if (perf_ok) { ioctl(fd, PERF_EVENT_IOC_DISABLE, 0); }
        clock_gettime(CLOCK_MONOTONIC, &end);

        rss_after = current_rss_kb();
        delta_kb = (rss_after >= 0 && rss_before >= 0) ? (rss_after - rss_before) : 0;

        cycles = 0ULL;
        if (perf_ok) {
            if (read(fd, &cycles, sizeof(cycles)) != (ssize_t)sizeof(cycles)) cycles = 0ULL;
            close(fd);
        }
        total_cycles_dec += cycles;
        total_time_dec += time_diff_ns(start, end) / 1e6;
        mem_dec += delta_kb;
    }

    // Print averages
    printf("\n=== CRYSTALS-Kyber Benchmark (%d iterations) ===\n", ITERATIONS);

    printf("\n[Keypair]");
    printf("\n  Avg Time:   %.3f ms", total_time_kp / ITERATIONS);
    if (total_cycles_kp) printf("\n  Avg Cycles: %llu", (unsigned long long)(total_cycles_kp / ITERATIONS)); else printf("\n  Avg Cycles: N/A");
    printf("\n  Avg Mem Δ:  %.2f KB", (double)mem_kp / ITERATIONS);

    printf("\n\n[Encapsulation]");
    printf("\n  Avg Time:   %.3f ms", total_time_enc / ITERATIONS);
    if (total_cycles_enc) printf("\n  Avg Cycles: %llu", (unsigned long long)(total_cycles_enc / ITERATIONS)); else printf("\n  Avg Cycles: N/A");
    printf("\n  Avg Mem Δ:  %.2f KB", (double)mem_enc / ITERATIONS);

    printf("\n\n[Decapsulation]");
    printf("\n  Avg Time:   %.3f ms", total_time_dec / ITERATIONS);
    if (total_cycles_dec) printf("\n  Avg Cycles: %llu", (unsigned long long)(total_cycles_dec / ITERATIONS)); else printf("\n  Avg Cycles: N/A");
    printf("\n  Avg Mem Δ:  %.2f KB", (double)mem_dec / ITERATIONS);

    // Sanity: shared secret match
    crypto_kem_keypair(pk, sk);
    crypto_kem_enc(ct, ss1, pk);
    crypto_kem_dec(ss2, ct, sk);
    printf("\n\nShared Secret Match: %s\n",
           (memcmp(ss1, ss2, CRYPTO_BYTES) == 0) ? "YES" : "NO");
    return 0;
}
