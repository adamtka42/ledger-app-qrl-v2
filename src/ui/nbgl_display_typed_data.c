#include <stdio.h>
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

#ifdef SCREEN_SIZE_WALLET
#include "nbgl_fonts.h"
#include "nbgl_layout.h"

/* Measure with the longest possible fragment suffix. Confirm against NBGL's
 * layout as well as its font metrics so the entire value is on the review path. */
size_t ui_typed_data_page_length(const char *label, char *text) {
    char title[48];
    int written = snprintf(title,
                           sizeof(title),
                           "%s (%u/%u)",
                           label,
                           TYPED_DATA_MAX_PAIRS,
                           TYPED_DATA_MAX_PAIRS);
    if (written < 0 || (size_t) written >= sizeof(title)) return 0;
    for (uint8_t lines = NB_MAX_LINES_IN_REVIEW; lines > 0; lines--) {
        uint16_t length = 0;
        nbgl_getTextMaxLenInNbLines(LARGE_MEDIUM_FONT, text, AVAILABLE_WIDTH, lines, &length, true);
        if (length == 0 || length > strlen(text)) return 0;
        char saved = text[length];
        text[length] = '\0';
        nbgl_contentTagValue_t pair = {.item = title, .value = text};
        nbgl_contentTagValueList_t candidate = {.nbPairs = 1, .pairs = &pair, .wrapping = true};
        bool needs_details = false;
        uint8_t pairs_in_page = nbgl_useCaseGetNbTagValuesInPage(1, &candidate, 0, &needs_details);
        text[length] = saved;
        if (pairs_in_page == 1 && !needs_details) return length;
    }
    return 0;
}
#endif

/* Complete values on Nano; mandatory page-sized fragments on touch devices. */
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
    _Static_assert(4 + TYPED_DATA_MAX_PAIRS <= UINT8_MAX, "review pair index must fit NBGL");
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
