#include "helpers.h"

void block_output (uint8_t block[AES_BLOCK_SIZE]) {
    unsigned int i;

    for (i = 0; i < AES_BLOCK_SIZE; ++i)
        printf("%02x ", block[i]);
}

int equal_bc(uint8_t bc1[AES_BLOCK_SIZE], uint8_t bc2[AES_BLOCK_SIZE]) {
    unsigned int i;

    for (i = 0; i < AES_BLOCK_SIZE; ++i)
	if (bc1[i] != bc2[i])
	    return 0;

    return 1;
}

void copy_bc(uint8_t bc1[AES_BLOCK_SIZE], uint8_t bc2[AES_BLOCK_SIZE]) {
    unsigned int i;

    for (i = 0; i < AES_BLOCK_SIZE; ++i)
	bc2[i] = bc1[i];
}


void swap(uint8_t *a, uint8_t *b) {
	uint8_t temp = *a;
	*a = *b;
	*b = temp;
}

// used in generating random Sbox
void shuffle(uint8_t Sbox[256]) {
	for (int i = 255; i > 0; --i) {
		int j = rand() % (i + 1);
		swap(&Sbox[i], &Sbox[j]);
	}
}

void generate_random_sbox(uint8_t Sbox[256]) {
	for (uint16_t i = 0; i < 256; ++i) {
		Sbox[i] = i;
	}
	// shuffle the s-box
	shuffle(Sbox);
}

// inverse of the Sbox
void inverse_sbox(const uint8_t Sbox[256], uint8_t Sbox_inv[256]) {
	for (uint16_t i = 0; i < 256; ++i) {
		Sbox_inv[Sbox[i]] = i;
	}
}