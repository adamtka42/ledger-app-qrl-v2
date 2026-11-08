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

static char account[1 + ADDRESS_SIZE * 2 + 1];
static char byte_length[11];
static char labels[PERSONAL_MESSAGE_MAX_PARTS][24];
static nbgl_contentTagValue_t pairs[2 + PERSONAL_MESSAGE_MAX_PARTS];
static nbgl_contentTagValueList_t list;

static int abort_display(uint16_t status) {
    reset_request_context();
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
    uint16_t offsets[PERSONAL_MESSAGE_MAX_PARTS];
    size_t parts;
    if (!personal_message_prepare_review(message, offsets, &parts)) {
        return abort_display(SW_BAD_STATE);
    }
    snprintf(byte_length, sizeof(byte_length), "%u", (unsigned) message->expected_len);
    memset(pairs, 0, sizeof(pairs));
    memset(&list, 0, sizeof(list));
    pairs[0].item = "Account";
    pairs[0].value = account;
    pairs[1].item = "Length (bytes)";
    pairs[1].value = byte_length;
    for (size_t i = 0; i < parts; i++) {
        snprintf(labels[i],
                 sizeof(labels[i]),
                 "Message (%u/%u)",
                 (unsigned) i + 1,
                 (unsigned) parts);
        pairs[2 + i].item = parts == 1 ? "Message" : labels[i];
        pairs[2 + i].value =
            message->expected_len == 0 ? "<empty message>" : message->text + offsets[i];
        pairs[2 + i].forcePageStart = true;
    }
    list.nbPairs = 2 + parts;
    list.pairs = pairs;
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
