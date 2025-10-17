// SPDX-License-Identifier: MIT
#include "rng.h"

#include <stddef.h>
#include <oqs/rand.h>

void randombytes_init(unsigned char *entropy_input, unsigned char *personalization_string, int security_strength) {
	(void) entropy_input;
	(void) personalization_string;
	(void) security_strength;
	/* QRUOV draws randomness directly from liboqs's RNG, so there is nothing to initialize. */
}

int randombytes(unsigned char *x, unsigned long long xlen) {
	if (xlen == 0) {
		return 0;
	}
	OQS_randombytes(x, (size_t) xlen);
	return 0;
}
