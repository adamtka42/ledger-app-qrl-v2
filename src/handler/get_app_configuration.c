#include <stdint.h>

#include "os.h"
#include "io.h"
#include "globals.h"
#include "sw.h"
#include "get_app_configuration.h"

int handler_get_app_configuration(void) {
    uint8_t flags = 0;
    if (N_storage.enable_blind_signing) flags |= APP_CONFIGURATION_BLIND_SIGNING;
    if (N_storage.display_nonce) flags |= APP_CONFIGURATION_DISPLAY_NONCE;
    if (N_storage.display_tx_hash) flags |= APP_CONFIGURATION_DISPLAY_TX_HASH;

    const uint8_t response[] = {APP_CONFIGURATION_FORMAT_VERSION,
                                flags,
                                MAJOR_VERSION,
                                MINOR_VERSION,
                                PATCH_VERSION};
    _Static_assert(sizeof(response) == APP_CONFIGURATION_RESPONSE_LEN,
                   "Unexpected application configuration response length");
    return io_send_response_pointer(response, sizeof(response), SW_OK);
}
