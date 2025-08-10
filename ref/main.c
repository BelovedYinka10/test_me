// kyber_mem_time_cycles.c — Kyber per-op Peak Memory + Avg Time + (scaled) Avg Cycles
#define _GNU_SOURCE
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <linux/perf_event.h>
#include <asm/unistd.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <errno.h>

#include "kem.h"  // PQCrystals Kyber API

#ifndef NUM_ITERATIONS
#define NUM_ITERATIONS 1000
#endif

// -------- timing --------
static inline double tdiff_ns(struct timespec s, struct timespec e){
    return (e.tv_sec - s.tv_sec)*1e9 + (e.tv_nsec - s.tv_nsec);
}

// -------- perf_event_open --------
static long perf_event_open_sys(struct perf_event_attr *a, pid_t pid, int cpu, int g, unsigned long f){
    return syscall(__NR_perf_event_open, a, pid, cpu, g, f);
}

// -------- /proc/self/status helpers (KB) --------
static long read_status_kb(const char *key){
    FILE *f = fopen("/proc/self/status","r");
    if(!f) return -1;
    char line[256]; long val=-1; size_t k=strlen(key);
    while(fgets(line,sizeof line,f)) {
        if(strncmp(line,key,k)==0){
            if(sscanf(line+k," %ld",&val)==1) break;
        }
    }
    fclose(f); return val;
}

// -------- perf setup helper (per-thread, scaled read) --------
static int perf_open_cycles_scaled(struct perf_event_attr *pe_out){
    struct perf_event_attr pe;
    memset(&pe, 0, sizeof(pe));
    pe.type = PERF_TYPE_HARDWARE;
    pe.size = sizeof(pe);
    pe.config = PERF_COUNT_HW_CPU_CYCLES;
    pe.disabled = 1;
    pe.exclude_kernel = 1;
    pe.exclude_hv = 1;
    pe.read_format = PERF_FORMAT_TOTAL_TIME_ENABLED | PERF_FORMAT_TOTAL_TIME_RUNNING;
    *pe_out = pe;
    // per-thread counting (pid=0 self, cpu=-1 any)
    int fd = perf_event_open_sys(&pe, 0, -1, -1, 0);
    return fd;
}

static double perf_read_avg_cycles(int fd){
    struct {
        uint64_t value;
        uint64_t time_enabled;
        uint64_t time_running;
    } rd = {0};
    ssize_t r = read(fd, &rd, sizeof(rd));
    if (r != (ssize_t)sizeof(rd) || rd.time_running == 0) return 0.0;
    double scaled = (double)rd.value;
    if (rd.time_enabled && rd.time_running && rd.time_running != rd.time_enabled) {
        scaled *= (double)rd.time_enabled / (double)rd.time_running;
    }
    return scaled / (double)NUM_ITERATIONS;
}

/* ===================== child runners ===================== */

static void child_keypair(int wfd){
    uint8_t pk[CRYPTO_PUBLICKEYBYTES];
    uint8_t sk[CRYPTO_SECRETKEYBYTES];

    // warm-up
    crypto_kem_keypair(pk, sk);

    struct perf_event_attr pe;
    int perf_ok = 1;
    int fd = perf_open_cycles_scaled(&pe);
    if (fd == -1) { perror("perf_event_open keypair"); perf_ok = 0; }

    struct timespec s,e;
    clock_gettime(CLOCK_MONOTONIC, &s);
    if (perf_ok) { ioctl(fd, PERF_EVENT_IOC_RESET, 0); ioctl(fd, PERF_EVENT_IOC_ENABLE, 0); }

    for (int i=0; i<NUM_ITERATIONS; ++i) crypto_kem_keypair(pk, sk);

    if (perf_ok) { ioctl(fd, PERF_EVENT_IOC_DISABLE, 0); }
    clock_gettime(CLOCK_MONOTONIC, &e);

    double avg_ms = (tdiff_ns(s,e)/1e6)/NUM_ITERATIONS;
    double avg_cycles = perf_ok ? perf_read_avg_cycles(fd) : 0.0;
    if (perf_ok) close(fd);

    long peak_kb = read_status_kb("VmHWM:");
    dprintf(wfd, "KPY %.6f %.0f %ld\n", avg_ms, avg_cycles, peak_kb);
    _exit(0);
}

static void child_encaps(int wfd){
    uint8_t pk[CRYPTO_PUBLICKEYBYTES];
    uint8_t sk[CRYPTO_SECRETKEYBYTES];
    uint8_t ct[CRYPTO_CIPHERTEXTBYTES];
    uint8_t ss[CRYPTO_BYTES];

    // warm-up
    crypto_kem_keypair(pk, sk);
    crypto_kem_enc(ct, ss, pk);

    struct perf_event_attr pe;
    int perf_ok = 1;
    int fd = perf_open_cycles_scaled(&pe);
    if (fd == -1) { perror("perf_event_open encaps"); perf_ok = 0; }

    struct timespec s,e;
    clock_gettime(CLOCK_MONOTONIC, &s);
    if (perf_ok) { ioctl(fd, PERF_EVENT_IOC_RESET, 0); ioctl(fd, PERF_EVENT_IOC_ENABLE, 0); }

    for (int i=0; i<NUM_ITERATIONS; ++i) crypto_kem_enc(ct, ss, pk);

    if (perf_ok) { ioctl(fd, PERF_EVENT_IOC_DISABLE, 0); }
    clock_gettime(CLOCK_MONOTONIC, &e);

    double avg_ms = (tdiff_ns(s,e)/1e6)/NUM_ITERATIONS;
    double avg_cycles = perf_ok ? perf_read_avg_cycles(fd) : 0.0;
    if (perf_ok) close(fd);

    long peak_kb = read_status_kb("VmHWM:");
    dprintf(wfd, "ENC %.6f %.0f %ld\n", avg_ms, avg_cycles, peak_kb);
    _exit(0);
}

static void child_decaps(int wfd){
    uint8_t pk[CRYPTO_PUBLICKEYBYTES];
    uint8_t sk[CRYPTO_SECRETKEYBYTES];
    uint8_t ct[CRYPTO_CIPHERTEXTBYTES];
    uint8_t ss1[CRYPTO_BYTES], ss2[CRYPTO_BYTES];

    // warm-up
    crypto_kem_keypair(pk, sk);
    crypto_kem_enc(ct, ss1, pk);
    crypto_kem_dec(ss2, ct, sk);

    struct perf_event_attr pe;
    int perf_ok = 1;
    int fd = perf_open_cycles_scaled(&pe);
    if (fd == -1) { perror("perf_event_open decaps"); perf_ok = 0; }

    struct timespec s,e;
    clock_gettime(CLOCK_MONOTONIC, &s);
    if (perf_ok) { ioctl(fd, PERF_EVENT_IOC_RESET, 0); ioctl(fd, PERF_EVENT_IOC_ENABLE, 0); }

    for (int i=0; i<NUM_ITERATIONS; ++i) crypto_kem_dec(ss2, ct, sk);

    if (perf_ok) { ioctl(fd, PERF_EVENT_IOC_DISABLE, 0); }
    clock_gettime(CLOCK_MONOTONIC, &e);

    double avg_ms = (tdiff_ns(s,e)/1e6)/NUM_ITERATIONS;
    double avg_cycles = perf_ok ? perf_read_avg_cycles(fd) : 0.0;
    if (perf_ok) close(fd);

    long peak_kb = read_status_kb("VmHWM:");
    dprintf(wfd, "DEC %.6f %.0f %ld\n", avg_ms, avg_cycles, peak_kb);
    _exit(0);
}

/* ===================== parent ===================== */

static int fork_and_capture(void (*child_fn)(int), char *outbuf, size_t outlen){
    int p[2]; if (pipe(p)!=0) { perror("pipe"); return -1; }
    pid_t c = fork();
    if (c==0) { close(p[0]); child_fn(p[1]); }
    close(p[1]);
    ssize_t n = read(p[0], outbuf, outlen-1);
    if (n>0) outbuf[n]=0;
    close(p[0]);
    int st; waitpid(c, &st, 0);
    return 0;
}

int main(void){
    char kbuf[128]={0}, ebuf[128]={0}, dbuf[128]={0};

    fork_and_capture(child_keypair, kbuf, sizeof kbuf);
    fork_and_capture(child_encaps, ebuf, sizeof ebuf);
    fork_and_capture(child_decaps, dbuf, sizeof dbuf);

    char t1[4]={0}, t2[4]={0}, t3[4]={0};
    double kp_ms=0, en_ms=0, de_ms=0, kp_cyc=0, en_cyc=0, de_cyc=0;
    long kp_peak=0, en_peak=0, de_peak=0;

    sscanf(kbuf, "%3s %lf %lf %ld", t1, &kp_ms, &kp_cyc, &kp_peak);
    sscanf(ebuf, "%3s %lf %lf %ld", t2, &en_ms, &en_cyc, &en_peak);
    sscanf(dbuf, "%3s %lf %lf %ld", t3, &de_ms, &de_cyc, &de_peak);

    printf("\n| Operation     | Avg Time (ms) |   Avg Cycles | Peak Memory (KB) |\n");
    printf("|---------------|--------------:|-------------:|------------------:|\n");

    if (kp_cyc>0) printf("| Keypair       | %13.3f | %13.0f | %16ld |\n", kp_ms, kp_cyc, kp_peak);
    else          printf("| Keypair       | %13.3f | %13s | %16ld |\n", kp_ms, "N/A", kp_peak);

    if (en_cyc>0) printf("| Encapsulation | %13.3f | %13.0f | %16ld |\n", en_ms, en_cyc, en_peak);
    else          printf("| Encapsulation | %13.3f | %13s | %16ld |\n", en_ms, "N/A", en_peak);

    if (de_cyc>0) printf("| Decapsulation | %13.3f | %13.0f | %16ld |\n\n", de_ms, de_cyc, de_peak);
    else          printf("| Decapsulation | %13.3f | %13s | %16ld |\n\n", de_ms, "N/A", de_peak);

    return 0;
}
