#include <stdio.h>
#include "aes-128_enc.h"

void block_output(uint8_t block[AES_BLOCK_SIZE]);
int equal_bc(uint8_t block1[AES_BLOCK_SIZE], uint8_t block2[AES_BLOCK_SIZE]);
void copy_bc(uint8_t from[AES_BLOCK_SIZE], uint8_t to[AES_BLOCK_SIZE]);
void generate_lambda_set(uint8_t set[256][AES_BLOCK_SIZE], uint8_t c);
void generate_random_sbox(uint8_t Sbox[256]);
void inverse_sbox(const uint8_t Sbox[256], uint8_t Sbox_inv[256]);