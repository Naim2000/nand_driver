#pragma once
#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>

#define CHECK_STRUCT_SIZE(X, Y) _Static_assert(sizeof(X) == Y, "sizeof(" #X ") is incorrect! (should be " #Y ")")

extern int debug_level;
#define debug_printf(level, fmt, ...) if (level <= debug_level) { fprintf(stderr, "%s:%d: %s(): " fmt "\n", __FILE__, __LINE__, __PRETTY_FUNCTION__, ##__VA_ARGS__); }
#define my_assert(cond) { if (!(cond)) { debug_printf(-1, "assertion failed (" #cond ")"); abort(); } }

static inline void hexdump(const char * title, const void * x, size_t len) {
    puts(title);

    const uint8_t* data = (const uint8_t *)x;
    for (int i = 0; i < len; i++) {
        printf(" %02X", data[i]);

        if ((i+1) % 16 == 0 || i + 1 >= len)
            putchar('\n');
        else if ((i+1) % 4 == 0)
            printf(" |");
    }
}
