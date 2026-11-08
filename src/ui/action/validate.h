#pragma once

#include <stdbool.h>  // bool

/**
 * Action for public key validation and export.
 *
 * @param[in] choice
 *   User choice (either approved or rejected).
 *
 */
void validate_pubkey(bool choice);

/**
 * Action for transaction information validation.
 *
 * @param[in] choice
 *   User choice (either approved or rejected).
 *
 * @return true only after signing and signature self-verification succeed.
 */
bool validate_transaction(bool choice);

/** Sign and verify the reviewed personal-message digest; return true on success. */
bool validate_personal_message(bool choice);
