#pragma once
#include <stddef.h>
#include <stdint.h>

typedef struct {
    uint8_t *ptr;
    size_t size, offset;
} buffer_t;
