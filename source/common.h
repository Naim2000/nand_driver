#pragma once
#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>

#define CHECK_STRUCT_SIZE(X, Y) _Static_assert(sizeof(X) == Y, "sizeof(" #X ") is incorrect! (should be " #Y ")")

#define debug_printf(level, fmt, ...) { fprintf(stderr, "%s:%d: %s(): " fmt "\n", __FILE__, __LINE__, __PRETTY_FUNCTION__, ##__VA_ARGS__); }
#define my_assert(cond) { if (!(cond)) { debug_printf(-1, "assertion failed (" #cond ")"); abort(); } }
