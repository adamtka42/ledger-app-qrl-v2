#pragma once
#include "cx.h"
#include "os_pic.h"

#define PRINTF(...) ((void) 0)

cx_err_t os_derive_bip32_no_throw(unsigned int curve,
                                  const uint32_t *path,
                                  size_t path_len,
                                  uint8_t *private_key,
                                  uint8_t *chain_code);
