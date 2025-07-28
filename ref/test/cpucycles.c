#include <stdint.h>
#include "cpucycles.h"

uint64_t cpucycles_overhead(void) {
  uint64_t t0, t1, overhead = -1ULL;
  unsigned int i;

  for (i = 0; i < 100000; i++) {
    t0 = cpucycles();
    __asm__ volatile ("" ::: "memory");  // Optional: prevent reordering
    t1 = cpucycles();
    if (t1 - t0 < overhead)
      overhead = t1 - t0;
  }

  return overhead;
}
