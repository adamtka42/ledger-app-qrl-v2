#include <string.h>

#include "os.h"
#include "cx.h"
#include "display.h"
#include "address.h"
#include "globals.h"
#include "request_context.h"
#include "glyphs.h"
#include "menu.h"
#include "nbgl_use_case.h"
#include "sw.h"
#include "validate.h"

/* Field/value fragments are bounded in the parser; none are hidden summaries. */
static nbgl_contentTagValueList_t list;
static char account[1 + 2 * ADDRESS_SIZE + 1];

static int abort_display(uint16_t status) {
    reset_request_context();
    return io_send_sw(status);
}

static void review_choice(bool confirm) {
    if (!confirm) {
        validate_typed_data(false);
        nbgl_useCaseReviewStatus(STATUS_TYPE_MESSAGE_REJECTED, ui_menu_main);
        return;
    }
    nbgl_useCaseSpinner("Signing");
    if (validate_typed_data(true))
        nbgl_useCaseReviewStatus(STATUS_TYPE_MESSAGE_SIGNED, ui_menu_main);
    else
        nbgl_useCaseStatus("Message signing failed", false, ui_menu_main);
}

/* Release the pair array before calling any code that derives/signs a key. */
__attribute__((noinline)) static bool prepare_pairs(const typed_data_session_t *data) {
    nbgl_contentTagValue_t pairs[4 + TYPED_DATA_MAX_PAIRS];
    _Static_assert(sizeof(pairs) <= TYPED_DATA_UI_BYTES,
                   "NBGL descriptors exceed temporary storage");
    const char *review = typed_data_review();
    memset(pairs, 0, sizeof(pairs));
    memset(&list, 0, sizeof(list));
    size_t count = 0;
    pairs[count].item = "Account";
    pairs[count++].value = account;
    pairs[count].item = "Primary type";
    pairs[count++].value = data->primary_type;
    if (!data->has_chain_id) {
        pairs[count].item = "Chain ID";
        pairs[count++].value = "Not specified";
    }
    if (!data->has_verifying_contract) {
        pairs[count].item = "Verifying contract";
        pairs[count++].value = "Not specified";
    }
    for (size_t i = 0; i < data->pair_count; i++) {
        pairs[count].item = review + data->pairs[i].label;
        pairs[count].value = review + data->pairs[i].value;
        pairs[count++].forcePageStart = true;
    }
    if (!typed_data_store_ui(pairs, count * sizeof(pairs[0]))) return false;
    list.pairs = typed_data_ui();
    list.nbPairs = count;
    list.wrapping = true;
    return true;
}

int ui_display_typed_data(void) {
    if (G_context.req_type != CONFIRM_TYPED_DATA || G_context.state != STATE_PARSED ||
        !G_context.typed_data.finished)
        return abort_display(SW_BAD_STATE);
    nbgl_useCaseSpinner("Getting address");
    if (address_from_bip32_path(G_context.bip32_path,
                                G_context.bip32_path_len,
                                G_context.address) != CX_OK ||
        !format_checksummed_address(G_context.address, account, sizeof(account))) {
        return abort_display(SW_DISPLAY_ADDRESS_FAIL);
    }
    if (!prepare_pairs(&G_context.typed_data)) return abort_display(SW_BAD_STATE);
    nbgl_useCaseReview(TYPE_MESSAGE,
                       &list,
                       &ICON_APP_BOILERPLATE,
                       "Review typed data",
                       NULL,
                       "Sign message",
                       review_choice);
    return 0;
}
