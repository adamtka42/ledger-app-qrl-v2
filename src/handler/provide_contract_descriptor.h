#pragma once

#include <stddef.h>
#include <stdint.h>

/* Authenticate one session-local operation description before any transaction bytes. */
int handler_provide_contract_descriptor(const uint8_t *data, size_t len, uint8_t p1, uint8_t p2);
