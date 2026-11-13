#include "request_context.h"

#include <string.h>

#include "os.h"
#include "os_nvm.h"
#include "globals.h"

void reset_request_context(void) {
    /* Revoke RAM authorization before touching persistent state. */
    explicit_bzero(&G_context, sizeof(G_context));
    if (N_storage.is_sending_signature != 0) {
        uint8_t inactive = 0;
        nvm_write((void *) &N_storage.is_sending_signature, &inactive, sizeof(inactive));
    }
}
