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
#endif

static char account[1 + ADDRESS_SIZE * 2 + 1];
static char byte_length[11];
/* NBGL requests pairs on demand. Only one message fragment starts on each
 * page, so one generated label remains valid for the displayed page. Account
 * and length use constant labels and never overwrite this label buffer. */
static char review_label[24];
static nbgl_contentTagValue_t review_pair;
static uint16_t review_offsets[PERSONAL_MESSAGE_MAX_PARTS];
static nbgl_contentTagValueList_t list;

_Static_assert(2 + PERSONAL_MESSAGE_MAX_PARTS <= UINT8_MAX, "review pair index must fit NBGL");
_Static_assert(sizeof(review_label) + sizeof(review_pair) + sizeof(review_offsets) <= 128,
               "personal-message review cache exceeds its RAM budget");

#ifdef SCREEN_SIZE_WALLET
/* Use the same font, width and wrapping as the review. Confirm the proposed
 * fragment with NBGL's layout calculation so no optional More view is needed.
 * Temporary termination is restored before the next fragment is measured. */
static size_t review_page_length(char *text) {
    for (uint8_t lines = NB_MAX_LINES_IN_REVIEW; lines > 0; lines--) {
        uint16_t length = 0;
        nbgl_getTextMaxLenInNbLines(LARGE_MEDIUM_FONT, text, AVAILABLE_WIDTH, lines, &length, true);
        if (length == 0 || length > strlen(text)) return 0;
        char saved = text[length];
        text[length] = '\0';
        nbgl_contentTagValue_t pair = {.item = "Message (33/33)", .value = text};
        nbgl_contentTagValueList_t candidate = {.nbPairs = 1, .pairs = &pair, .wrapping = true};
        bool needs_details = false;
        uint8_t pairs_in_page = nbgl_useCaseGetNbTagValuesInPage(1, &candidate, 0, &needs_details);
        text[length] = saved;
        if (pairs_in_page == 1 && !needs_details) return length;
    }
    return 0;
}
#endif

static nbgl_contentTagValue_t *get_review_pair(uint8_t index) {
    personal_message_t *message = &G_context.message_info;
    if (G_context.req_type != CONFIRM_MESSAGE || G_context.state != STATE_PARSED ||
        !message->review_prepared || index >= list.nbPairs) {
        return NULL;
    }
    memset(&review_pair, 0, sizeof(review_pair));
    if (index == 0) {
        review_pair.item = "Account";
        review_pair.value = account;
    } else if (index == 1) {
        review_pair.item = "Length (bytes)";
        review_pair.value = byte_length;
    } else {
        size_t part = index - 2;
        size_t parts = list.nbPairs - 2;
        snprintf(review_label,
                 sizeof(review_label),
                 "Message (%u/%u)",
                 (unsigned) part + 1,
                 (unsigned) parts);
        review_pair.item = parts == 1 ? "Message" : review_label;
        review_pair.value =
            message->expected_len == 0 ? "<empty message>" : message->text + review_offsets[part];
        review_pair.forcePageStart = true;
    }
    return &review_pair;
}

static int abort_display(uint16_t status) {
    reset_request_context();
    ui_menu_main();
    return io_send_sw(status);
}

static void review_choice(bool confirm) {
    if (!confirm) {
        validate_personal_message(false);
        nbgl_useCaseReviewStatus(STATUS_TYPE_MESSAGE_REJECTED, ui_menu_main);
        return;
    }
    nbgl_useCaseSpinner("Signing");
    if (validate_personal_message(true)) {
        nbgl_useCaseReviewStatus(STATUS_TYPE_MESSAGE_SIGNED, ui_menu_main);
    } else {
        nbgl_useCaseStatus("Message signing failed", false, ui_menu_main);
    }
}

int ui_display_personal_message(void) {
    if (G_context.req_type != CONFIRM_MESSAGE || G_context.state != STATE_PARSED) {
        return abort_display(SW_BAD_STATE);
    }
    nbgl_useCaseSpinner("Getting address");
    if (address_from_bip32_path(G_context.bip32_path,
                                G_context.bip32_path_len,
                                G_context.address) != CX_OK ||
        !format_checksummed_address(G_context.address, account, sizeof(account))) {
        return abort_display(SW_DISPLAY_ADDRESS_FAIL);
    }
    personal_message_t *message = &G_context.message_info;
    size_t parts;
#ifdef SCREEN_SIZE_WALLET
    personal_message_page_length_t page_length = review_page_length;
#else
    personal_message_page_length_t page_length = NULL;
#endif
    if (!personal_message_prepare_review(message, review_offsets, &parts, page_length)) {
        return abort_display(SW_BAD_STATE);
    }
    snprintf(byte_length, sizeof(byte_length), "%u", (unsigned) message->expected_len);
    memset(&list, 0, sizeof(list));
    list.nbPairs = 2 + parts;
    list.callback = get_review_pair;
    list.wrapping = true;
    nbgl_useCaseReview(TYPE_MESSAGE,
                       &list,
                       &ICON_APP_BOILERPLATE,
                       "Review message",
                       NULL,
                       "Sign message",
                       review_choice);
    return 0;
}
