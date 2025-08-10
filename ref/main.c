// main.c — Kyber benchmark with memory *consumption* (RSS) + peak (VmHWM)
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

// ---------- timing ----------
static inline double time_diff_ns(struct timespec s, struct timespec e) {
    return (e.tv_sec - s.tv_sec) * 1e9 + (e.tv_nsec - s.tv_nsec);
}

// ---------- perf_event_open wrapper ----------
static long perf_event_open(struct perf_event_attr *hw_event, pid_t pid,
                            int cpu, int group_fd, unsigned long flags) {
    return syscall(__NR_perf_event_open, hw_event, pid, cpu, group_fd, flags);
}

// ---------- optional: pin to CPU 0 ----------
static void pin_to_cpu0(void) {
    cpu_set_t mask;
    CPU_ZERO(&mask);
    CPU_SET(0, &mask);
    (void)sched_setaffinity(0, sizeof(mask), &mask);
}

// ---------- /proc/self/status helpers ----------
static long read_status_kb(const char *key) {
    FILE *f = fopen("/proc/self/status", "r");
    if (!f) return -1;
    char line[256];
    long val = -1;
    size_t keylen = strlen(key);
    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, key, keylen) == 0) {
            // expected format: "Key:   <num> kB"
            long tmp = -1;
            if (sscanf(line + keylen, " %ld", &tmp) == 1) {
                val = tmp; // already in KB
            }
            break;
        }
    }
    fclose(f);
    return val;
}

static long current_rss_kb(void) { return read_status_kb("VmRSS:"); }  // total RAM in use now
static long peak_hwm_kb(void)     { return read_status_kb("VmHWM:"); }  // peak RAM (high-water)

// ---------- main ----------
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

    // Memory *consumption* (KB) sampled *after* each op
    double sum_rss_after_kp = 0.0, sum_rss_after_enc = 0.0, sum_rss_after_dec = 0.0;
    long observed_peak_kb = peak_hwm_kb(); // baseline peak at start

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

        struct timespec start, end;
        clock_gettime(CLOCK_MONOTONIC, &start);
        if (perf_ok) { ioctl(fd, PERF_EVENT_IOC_RESET, 0); ioctl(fd, PERF_EVENT_IOC_ENABLE, 0); }

        crypto_kem_keypair(pk, sk);

        if (perf_ok) { ioctl(fd, PERF_EVENT_IOC_DISABLE, 0); }
        clock_gettime(CLOCK_MONOTONIC, &end);

        unsigned long long cycles = 0ULL;
        if (perf_ok) {
            if (read(fd, &cycles, sizeof(cycles)) != (ssize_t)sizeof(cycles)) cycles = 0ULL;
            close(fd);
        }

        total_cycles_kp += cycles;
        total_time_kp += time_diff_ns(start, end) / 1e6;
        long rss_now = current_rss_kb();
        if (rss_now > 0) sum_rss_after_kp += (double)rss_now;
        long hwm_now = peak_hwm_kb();
        if (hwm_now > observed_peak_kb) observed_peak_kb = hwm_now;

        // === Encapsulation ===
        fd = -1;
        if (perf_ok) {
            fd = perf_event_open(&pe, 0, 0, -1, 0);
            if (fd == -1) perf_ok = 0;
        }

        clock_gettime(CLOCK_MONOTONIC, &start);
        if (perf_ok) { ioctl(fd, PERF_EVENT_IOC_RESET, 0); ioctl(fd, PERF_EVENT_IOC_ENABLE, 0); }

        crypto_kem_enc(ct, ss1, pk);

        if (perf_ok) { ioctl(fd, PERF_EVENT_IOC_DISABLE, 0); }
        clock_gettime(CLOCK_MONOTONIC, &end);

        cycles = 0ULL;
        if (perf_ok) {
            if (read(fd, &cycles, sizeof(cycles)) != (ssize_t)sizeof(cycles)) cycles = 0ULL;
            close(fd);
        }

        total_cycles_enc += cycles;
        total_time_enc += time_diff_ns(start, end) / 1e6;
        rss_now = current_rss_kb();
        if (rss_now > 0) sum_rss_after_enc += (double)rss_now;
        hwm_now = peak_hwm_kb();
        if (hwm_now > observed_peak_kb) observed_peak_kb = hwm_now;

        // === Decapsulation ===
        fd = -1;
        if (perf_ok) {
            fd = perf_event_open(&pe, 0, 0, -1, 0);
            if (fd == -1) perf_ok = 0;
        }

        clock_gettime(CLOCK_MONOTONIC, &start);
        if (perf_ok) { ioctl(fd, PERF_EVENT_IOC_RESET, 0); ioctl(fd, PERF_EVENT_IOC_ENABLE, 0); }

        crypto_kem_dec(ss2, ct, sk);

        if (perf_ok) { ioctl(fd, PERF_EVENT_IOC_DISABLE, 0); }
        clock_gettime(CLOCK_MONOTONIC, &end);

        cycles = 0ULL;
        if (perf_ok) {
            if (read(fd, &cycles, sizeof(cycles)) != (ssize_t)sizeof(cycles)) cycles = 0ULL;
            close(fd);
        }

        total_cycles_dec += cycles;
        total_time_dec += time_diff_ns(start, end) / 1e6;
        rss_now = current_rss_kb();
        if (rss_now > 0) sum_rss_after_dec += (double)rss_now;
        hwm_now = peak_hwm_kb();
        if (hwm_now > observed_peak_kb) observed_peak_kb = hwm_now;
    }

    // Averages
    double avg_rss_kp  = sum_rss_after_kp  / ITERATIONS;
    double avg_rss_enc = sum_rss_after_enc / ITERATIONS;
    double avg_rss_dec = sum_rss_after_dec / ITERATIONS;

    printf("\n=== CRYSTALS-Kyber Benchmark (%d iterations) ===\n", ITERATIONS);

    printf("\n[Keypair]");
    printf("\n  Avg Time:   %.3f ms", total_time_kp / ITERATIONS);
    if (total_cycles_kp) printf("\n  Avg Cycles: %llu", (unsigned long long)(total_cycles_kp / ITERATIONS)); else printf("\n  Avg Cycles: N/A");
    printf("\n  Avg RSS:    %.2f KB", avg_rss_kp);

    printf("\n\n[Encapsulation]");
    printf("\n  Avg Time:   %.3f ms", total_time_enc / ITERATIONS);
    if (total_cycles_enc) printf("\n  Avg Cycles: %llu", (unsigned long long)(total_cycles_enc / ITERATIONS)); else printf("\n  Avg Cycles: N/A");
    printf("\n  Avg RSS:    %.2f KB", avg_rss_enc);

    printf("\n\n[Decapsulation]");
    printf("\n  Avg Time:   %.3f ms", total_time_dec / ITERATIONS);
    if (total_cycles_dec) printf("\n  Avg Cycles: %llu", (unsigned long long)(total_cycles_dec / ITERATIONS)); else printf("\n  Avg Cycles: N/A");
    printf("\n  Avg RSS:    %.2f KB", avg_rss_dec);

    // Peak memory across the whole run
    long final_peak = peak_hwm_kb();
    if (final_peak < observed_peak_kb) final_peak = observed_peak_kb;
    printf("\n\n[Process Memory]");
    printf("\n  Peak VmHWM:  %ld KB", final_peak);

    // Sanity: shared secret match
    uint8_t ct2[CRYPTO_CIPHERTEXTBYTES];
    uint8_t ssA[CRYPTO_BYTES], ssB[CRYPTO_BYTES];
    crypto_kem_keypair(pk, sk);
    crypto_kem_enc(ct2, ssA, pk);
    crypto_kem_dec(ssB, ct2, sk);
    printf("\n\nShared Secret Match: %s\n",
           (memcmp(ssA, ssB, CRYPTO_BYTES) == 0) ? "YES" : "NO");
    return 0;
}
