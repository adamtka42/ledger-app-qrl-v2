#pragma once
#include <stddef.h>
#include <stdint.h>

typedef uint32_t cx_err_t;
#define CX_OK              0u
#define CX_INTERNAL_ERROR  0xFFFFFF85u
#define CX_CURVE_SECP256K1 0x21u

cx_err_t cx_get_random_bytes(void *buffer, size_t len);
unsigned char *cx_rng(uint8_t *buffer, size_t len);
