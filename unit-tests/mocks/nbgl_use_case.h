#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef struct {
    const char *item;
    const char *value;
} nbgl_contentTagValue_t;

typedef struct {
    uint8_t nbMaxLinesForValue;
    size_t nbPairs;
    const nbgl_contentTagValue_t *pairs;
} nbgl_contentTagValueList_t;

enum {
    TYPE_TRANSACTION,
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
