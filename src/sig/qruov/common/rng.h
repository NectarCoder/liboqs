// SPDX-License-Identifier: MIT
#pragma once

#include <stddef.h>
#include <stdint.h>

/* Minimal RNG interface expected by the QRUOV reference implementation. */

void randombytes_init(unsigned char *entropy_input, unsigned char *personalization_string, int security_strength);
int randombytes(unsigned char *x, unsigned long long xlen);
