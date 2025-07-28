// kyber_wrapper.c
#include <stdio.h>
#include "ref/kem.h"

void keypair(unsigned char *pk, unsigned char *sk) {
    printf("keypair start\n");
    crypto_kem_keypair(pk, sk);
    printf("keypair end\n");
}

void encapsulate(const unsigned char *pk, unsigned char *ct, unsigned char *ss) {
    printf("encapsulate start\n");
    crypto_kem_enc(ct, ss, pk);
    printf("encapsulate end\n");
}

void decapsulate(const unsigned char *ct, const unsigned char *sk, unsigned char *ss) {
    printf("decapsulate start\n");
    crypto_kem_dec(ss, ct, sk);
    printf("decapsulate end\n");
}
