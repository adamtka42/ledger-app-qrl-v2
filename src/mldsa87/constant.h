#ifndef CONSTANT_H
#define CONSTANT_H

#include <stdint.h>

#define CRYPTO_PUBLIC_KEY_BYTES (SEED_BYTES + K * POLY_T1_PACKED_BYTES)
#define CRYPTO_SECRET_KEY_BYTES                                                          \
    (2 * SEED_BYTES + TR_BYTES + L * POLY_ETA_PACKED_BYTES + K * POLY_ETA_PACKED_BYTES + \
     K * POLY_T0_PACKED_BYTES)
#define CRYPTO_BYTES                          \
    (CTILDE_BYTES + L * POLY_Z_PACKED_BYTES + \
     POLY_VEC_H_PACKED_BYTES)  // CryptoBytes is the signature size in bytes
#define SHAKE_128_RATE            168
#define SHAKE_256_RATE            136
#define STREAM_128_BLOCK_BYTES    (SHAKE_128_RATE)
#define STREAM_256_BLOCK_BYTES    (SHAKE_256_RATE)
#define POLY_UNIFORM_N_BLOCKS     ((768 + STREAM_128_BLOCK_BYTES - 1) / STREAM_128_BLOCK_BYTES)
#define POLY_UNIFORM_ETA_N_BLOCKS ((136 + STREAM_256_BLOCK_BYTES - 1) / STREAM_256_BLOCK_BYTES)
#define POLY_UNIFORM_GAMMA1_N_BLOCKS \
    ((POLY_Z_PACKED_BYTES + STREAM_256_BLOCK_BYTES - 1) / STREAM_256_BLOCK_BYTES)

#define ADDRESS_SIZE     64
#define DESCRIPTOR_BYTES 3
#define SEED_BYTES       32
#define CRH_BYTES        64  // hash of public key
#define TR_BYTES         64
#define RND_BYTES        32
#define N                256
#define Q_CONST          8380417
#define Q_INV            58728449  // -q^(-1) mod 2^32
#define D                13

#define K            8
#define L            7
#define ETA          2
#define TAU          60
#define BETA         120
#define GAMMA1       (1 << 19)
#define GAMMA2       ((Q_CONST - 1) / 32)
#define OMEGA        75
#define CTILDE_BYTES 64

// Polynomial sizes
#define POLY_T1_PACKED_BYTES    320
#define POLY_T0_PACKED_BYTES    416
#define POLY_ETA_PACKED_BYTES   96
#define POLY_Z_PACKED_BYTES     640
#define POLY_VEC_H_PACKED_BYTES (OMEGA + K)
#define POLY_W1_PACKED_BYTES    128

#define CTX_LEN     8
#define MESSAGE_LEN 500

#define SIGNATURE_CHUNK_SIZE       258
#define SIGNATURE_LAST_CHUNK_SIZE  241
#define SIGNATURE_CHUNKS           18
#define SIGNATURE_LAST_CHUNK_INDEX (SIGNATURE_CHUNKS - 1)

_Static_assert(CRYPTO_BYTES ==
                   SIGNATURE_LAST_CHUNK_INDEX * SIGNATURE_CHUNK_SIZE + SIGNATURE_LAST_CHUNK_SIZE,
               "signature chunks must cover the signature exactly");

#define PK_CHUNK_SIZE      258
#define PK_LAST_CHUNK_SIZE 12
#define PK_CHUNKS          11

extern const int ZETAS[N];
extern const uint8_t CTX[CTX_LEN];

#endif