#pragma once
#include <stdbool.h>
#include <stdint.h>

typedef unsigned nbgl_font_id_e;
#define LARGE_MEDIUM_FONT                     1u
#define BAGL_FONT_OPEN_SANS_REGULAR_11px_1bpp 2u
bool nbgl_getTextMaxLenInNbLines(nbgl_font_id_e font,
                                 const char *text,
                                 uint16_t width,
                                 uint16_t lines,
                                 uint16_t *length,
                                 bool wrapping);
uint8_t nbgl_getTextNbPagesInWidth(nbgl_font_id_e font,
                                   const char *text,
                                   uint8_t lines,
                                   uint16_t width);
