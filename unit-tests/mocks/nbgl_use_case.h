#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef struct {
    const char *item;
    const char *value;
    bool forcePageStart;
} nbgl_contentTagValue_t;

typedef nbgl_contentTagValue_t *(*nbgl_contentTagValueCallback_t)(uint8_t index);

typedef struct {
    uint8_t nbMaxLinesForValue;
    size_t nbPairs;
    const nbgl_contentTagValue_t *pairs;
    nbgl_contentTagValueCallback_t callback;
    bool wrapping;
} nbgl_contentTagValueList_t;

enum {
    TYPE_TRANSACTION,
    TYPE_MESSAGE,
    STATUS_TYPE_MESSAGE_SIGNED,
    STATUS_TYPE_MESSAGE_REJECTED,
    STATUS_TYPE_TRANSACTION_SIGNED,
    STATUS_TYPE_TRANSACTION_REJECTED,
};

void nbgl_useCaseSpinner(const char *text);
void nbgl_useCaseReview(int type,
                        const nbgl_contentTagValueList_t *pairs,
                        const void *icon,
                        const char *title,
                        const char *subtitle,
                        const char *finish,
                        void (*choice)(bool));
void nbgl_useCaseReviewBlindSigning(int type,
                                    const nbgl_contentTagValueList_t *pairs,
                                    const void *icon,
                                    const char *title,
                                    const char *subtitle,
                                    const char *finish,
                                    const void *warning,
                                    void (*choice)(bool));
void nbgl_useCaseReviewStatus(int status, void (*done)(void));
void nbgl_useCaseStatus(const char *text, bool success, void (*done)(void));

#ifdef SCREEN_SIZE_WALLET
#define NB_MAX_LINES_IN_REVIEW 9u
#else
#define NB_MAX_LINES_IN_REVIEW 3u
#endif
uint8_t nbgl_useCaseGetNbTagValuesInPage(uint8_t nbPairs,
                                         const nbgl_contentTagValueList_t *list,
                                         uint8_t startIndex,
                                         bool *requireSpecificDisplay);
