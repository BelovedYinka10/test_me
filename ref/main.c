// main.c — Kyber benchmark with time, cycles, and HEAP + STACK usage
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
#include <pthread.h>

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

// ---------- HEAP usage (KB) ----------
#if defined(__GLIBC__) && (__GLIBC__ > 2 || (__GLIBC__ == 2 && __GLIBC_MINOR__ >= 33))
#define HAVE_MALLINFO2 1
#endif

#ifdef HAVE_MALLINFO2
#include <malloc.h>
static long current_heap_kb(void) {
    struct mallinfo2 mi = mallinfo2();
    return (long)(mi.uordblks / 1024); // bytes -> KB
}
#else
#include <malloc.h>
static long current_heap_kb(void) {
    struct mallinfo mi = mallinfo();
    return (long)(mi.uordblks / 1024); // bytes -> KB (may truncate on 32-bit)
}
#endif

// ---------- STACK usage (KB) ----------
// Uses pthread_getattr_np to get base + size of the current (main) thread's stack.
// POSIX defines attr.stackaddr as the *lowest* address; for downward-growing stacks,
// current usage ~= (stack_base + stack_size) - current_sp.
static long current_stack_kb(void) {
    pthread_attr_t attr;
    if (pthread_getattr_np(pthread_self(), &attr) != 0) return -1;

    void *stack_base = NULL; // lowest address
    size_t stack_size = 0;
    int r = pthread_attr_getstack(&attr, &stack_base, &stack_size);
    pthread_attr_destroy(&attr);
    if (r != 0 || stack_base == NULL || stack_size == 0) return -1;

    volatile int marker = 0;
    void *sp = (void *)&marker;

    // Compute distance between "top" (base + size) and current SP.
    char *low  = (char *)stack_base;
    char *high = low + stack_size; // expected upper bound for downward growth
    char *csp  = (char *)sp;

    long used_bytes;
    if (csp <= high && csp >= low) {
        // Common case: downward-growing within bounds
        used_bytes = (long)(high - csp);
    } else {
        // Fallback if addresses are unexpected (different growth direction)
        // Use absolute distance to nearest bound as a conservative estimate.
        long d1 = (long)llabs((long)(csp - low));
        long d2 = (long)llabs((long)(high - csp));
        used_bytes = d1 < d2 ? d1 : d2;
    }
    if (used_bytes < 0) used_bytes = 0;
    return used_bytes / 1024; // KB
}

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

    // Memory stats (averages + peaks)
    double sum_heap_kp = 0.0, sum_heap_enc = 0.0, sum_heap_dec = 0.0;
    double sum_stack_kp = 0.0, sum_stack_enc = 0.0, sum_stack_dec = 0.0;
    long peak_heap_kb = 0, peak_stack_kb = 0;

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

        long heap_kb = current_heap_kb();
        long stack_kb = current_stack_kb();
        if (heap_kb > 0) { sum_heap_kp += heap_kb; if (heap_kb > peak_heap_kb) peak_heap_kb = heap_kb; }
        if (stack_kb > 0) { sum_stack_kp += stack_kb; if (stack_kb > peak_stack_kb) peak_stack_kb = stack_kb; }

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

        heap_kb = current_heap_kb();
        stack_kb = current_stack_kb();
        if (heap_kb > 0) { sum_heap_enc += heap_kb; if (heap_kb > peak_heap_kb) peak_heap_kb = heap_kb; }
        if (stack_kb > 0) { sum_stack_enc += stack_kb; if (stack_kb > peak_stack_kb) peak_stack_kb = stack_kb; }

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

        heap_kb = current_heap_kb();
        stack_kb = current_stack_kb();
        if (heap_kb > 0) { sum_heap_dec += heap_kb; if (heap_kb > peak_heap_kb) peak_heap_kb = heap_kb; }
        if (stack_kb > 0) { sum_stack_dec += stack_kb; if (stack_kb > peak_stack_kb) peak_stack_kb = stack_kb; }
    }

    // Averages
    double avg_heap_kp  = sum_heap_kp  / ITERATIONS;
    double avg_heap_enc = sum_heap_enc / ITERATIONS;
    double avg_heap_dec = sum_heap_dec / ITERATIONS;

    double avg_stack_kp  = sum_stack_kp  / ITERATIONS;
    double avg_stack_enc = sum_stack_enc / ITERATIONS;
    double avg_stack_dec = sum_stack_dec / ITERATIONS;

    printf("\n=== CRYSTALS-Kyber Benchmark (%d iterations) ===\n", ITERATIONS);

    printf("\n[Keypair]");
    printf("\n  Avg Time:    %.3f ms", total_time_kp / ITERATIONS);
    if (total_cycles_kp) printf("\n  Avg Cycles:  %llu", (unsigned long long)(total_cycles_kp / ITERATIONS)); else printf("\n  Avg Cycles:  N/A");
    printf("\n  Avg HEAP:    %.2f KB", avg_heap_kp);
    printf("\n  Avg STACK:   %.2f KB", avg_stack_kp);

    printf("\n\n[Encapsulation]");
    printf("\n  Avg Time:    %.3f ms", total_time_enc / ITERATIONS);
    if (total_cycles_enc) printf("\n  Avg Cycles:  %llu", (unsigned long long)(total_cycles_enc / ITERATIONS)); else printf("\n  Avg Cycles:  N/A");
    printf("\n  Avg HEAP:    %.2f KB", avg_heap_enc);
    printf("\n  Avg STACK:   %.2f KB", avg_stack_enc);

    printf("\n\n[Decapsulation]");
    printf("\n  Avg Time:    %.3f ms", total_time_dec / ITERATIONS);
    if (total_cycles_dec) printf("\n  Avg Cycles:  %llu", (unsigned long long)(total_cycles_dec / ITERATIONS)); else printf("\n  Avg Cycles:  N/A");
    printf("\n  Avg HEAP:    %.2f KB", avg_heap_dec);
    printf("\n  Avg STACK:   %.2f KB", avg_stack_dec);

    printf("\n\n[Peaks Observed During Run]");
    printf("\n  Peak HEAP:   %ld KB", peak_heap_kb);
    printf("\n  Peak STACK:  %ld KB", peak_stack_kb);

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
