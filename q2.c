#include "helpers.h"

/*
    Testing key expansion functions 
	key values provided in the standard document

*/

int main () {

const uint8_t prev_key[AES_128_KEY_SIZE] = {
		0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab,
		0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c}; // 
												   // 
	uint8_t next_key[AES_128_KEY_SIZE];

	printf("Test for a round on the key:\n");
	printf("Original key\n");
	block_output(prev_key);

	// prev_key is the master key because round = 0
	printf("\nNext key\n");
	next_aes128_round_key(prev_key, next_key, 0,S);
	block_output(next_key);

	uint8_t prev_key_computed[AES_128_KEY_SIZE];

	printf("\nPrev key\n");
	prev_aes128_round_key(next_key, prev_key_computed, 0,S);
	block_output(prev_key_computed);

	printf("\n");
    return 0;
}