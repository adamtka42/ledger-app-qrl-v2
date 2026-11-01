#pragma once

void *test_pic(const void *address);
#define PIC(address) test_pic(address)
