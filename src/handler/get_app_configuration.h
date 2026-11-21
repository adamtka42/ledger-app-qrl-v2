#pragma once

#define APP_CONFIGURATION_FORMAT_VERSION 1
#define APP_CONFIGURATION_RESPONSE_LEN   5

#define APP_CONFIGURATION_BLIND_SIGNING   (1u << 0)
#define APP_CONFIGURATION_DISPLAY_NONCE   (1u << 1)
#define APP_CONFIGURATION_DISPLAY_TX_HASH (1u << 2)

/**
 * Return format version, settings flags, and MAJOR || MINOR || PATCH.
 * Reads settings only; preserves the current request and signature export.
 */
int handler_get_app_configuration(void);
