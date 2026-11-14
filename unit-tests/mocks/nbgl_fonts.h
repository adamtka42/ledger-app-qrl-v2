#pragma once
#include <stdbool.h>
#include <stdint.h>

typedef unsigned nbgl_font_id_e;
#define LARGE_MEDIUM_FONT 1u
bool nbgl_getTextMaxLenInNbLines(nbgl_font_id_e font,
                                 const char *text,
                                 uint16_t width,
                                 uint16_t lines,
                                 uint16_t *length,
                                 bool wrapping);
