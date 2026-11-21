#pragma once
#include <stddef.h>
#include <stdint.h>

int io_send_sw(uint16_t status);
int io_send_response_pointer(const uint8_t *data, size_t length, uint16_t status);
