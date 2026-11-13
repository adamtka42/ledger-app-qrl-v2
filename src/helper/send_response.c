/*****************************************************************************
 *   Ledger App Boilerplate.
 *   (c) 2020 Ledger SAS.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *****************************************************************************/

#include <stddef.h>  // size_t
#include <stdint.h>  // uint*_t
#include <string.h>  // memmove

#include "buffer.h"

#include "send_response.h"
#include "constants.h"
#include "globals.h"
#include "sw.h"
#include "constant.h"

int helper_send_response_address() {
    uint8_t resp[1 + ADDRESS_SIZE] = {0};
    size_t offset = 0;

    resp[offset++] = ZOND_ADDRESS_PREFIX;
    memmove(resp + offset, G_context.address, ADDRESS_SIZE);
    offset += ADDRESS_SIZE;

    return io_send_response_pointer(resp, offset, SW_OK);
}

int helper_send_response_sig(uint8_t index) {
    if (index < SIGNATURE_LAST_CHUNK_INDEX) {
        uint8_t resp[SIGNATURE_CHUNK_SIZE] = {0};
        size_t offset = 0;

        for (int i = 0; i < SIGNATURE_CHUNK_SIZE; i++) {
            resp[i] = N_storage.sig[i + index * SIGNATURE_CHUNK_SIZE];
        }
        offset += SIGNATURE_CHUNK_SIZE;

        io_send_response_pointer(resp, offset, SW_OK);
    } else {
        uint8_t resp[SIGNATURE_LAST_CHUNK_SIZE] = {0};
        size_t offset = 0;

        for (int i = 0; i < SIGNATURE_LAST_CHUNK_SIZE; i++) {
            resp[i] = N_storage.sig[i + index * SIGNATURE_CHUNK_SIZE];
        }
        offset += SIGNATURE_LAST_CHUNK_SIZE;

        io_send_response_pointer(resp, offset, SW_OK);
    }

    if (index == 0) {
        uint8_t temp = 1;
        nvm_write((void *) &N_storage.is_sending_signature, &temp, sizeof(uint8_t));
    } else if (index == SIGNATURE_LAST_CHUNK_INDEX) {
        uint8_t temp = 0;
        nvm_write((void *) &N_storage.is_sending_signature, &temp, sizeof(uint8_t));
    }

    return 0;
}

int helper_send_response_pk_chunk(uint8_t index) {
    if (index >= PK_CHUNKS) {
        return io_send_sw(SW_WRONG_DATA_LENGTH);
    }

    size_t chunk_size = (index < PK_CHUNKS - 1) ? PK_CHUNK_SIZE : PK_LAST_CHUNK_SIZE;
    uint8_t resp[PK_CHUNK_SIZE] = {0};
    for (size_t i = 0; i < chunk_size; i++) {
        resp[i] = N_storage.pk[i + index * PK_CHUNK_SIZE];
    }
    io_send_response_pointer(resp, chunk_size, SW_OK);
    return 0;
}
