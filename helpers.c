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