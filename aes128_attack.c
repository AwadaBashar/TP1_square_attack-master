#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "aes-128_enc.h"
#include "helpers.h"

#define NUMBER_OF_TRIALS 20

void vector_print(uint8_t *v, int n)
{
    int i;
    printf("0x%02x", v[0]);
    for (i = 1; i < n; i++)
    {
        printf(", 0x%02x", v[i]);
    }
    printf(".\n");
}

/**
 * substracts x-y then calculation of the modulo 16
*/
int modulo_sub(int x, int y)
{
    return ((x - y) % 16) + ((x >= y) ? 0 : 16);
}

/**
 * @original_byte: needed to look up the original byte (before shift)
 * @byte_ind: the byte_ind of the byte to decrypt (expected to be in [0-15])
 * @key_byte: byte of the key that was xored with the original_byte to decrypt, must be determined before call
 * ex: to decrypt the 2nd byte ie original_byte[1] -> key_byte = key[13], for original_byte[5] -> key[1] ...
*/
uint8_t decrypt_half_round(uint8_t original_byte[AES_BLOCK_SIZE], int byte_ind, uint8_t key_byte,const uint8_t Sbox_inv[256])
{
    uint8_t dec = 0;

    if (byte_ind % 4 != 0)
    {
        // inverting the shift
        dec = original_byte[modulo_sub(byte_ind, 4)];
    }
    else // byte_ind in first row
    {
        dec = original_byte[byte_ind];
    }

    dec ^= key_byte;
    dec = Sbox_inv[dec];
    return dec;
}

/**
 Getting a random key from urandom.
 It terminates the program if error detected
*/
void get_random_k_from_urandom(uint8_t *key)
{
    FILE *fp = fopen("/dev/urandom", "r");
    if (fp == NULL)
    {
        fprintf(stderr, "Failed to open file /dev/urandom.\n");
        exit(1);
    }
    int bytes_read = fread(key, sizeof(uint8_t), AES_128_KEY_SIZE, fp);
    if (bytes_read < 0)
    {
        fprintf(stderr, "Failed to read 16 bytes from file /dev/urandom.\n");
        exit(1);
    }
    fclose(fp);
    return;
}

/**
 * Generates a lambda-set same as used in q3
*/
void generate_lambda_set(uint8_t set[256][AES_BLOCK_SIZE], uint8_t c)
{
    int i = 0, j = 0;
    for (i = 0; i < 256; i++)
    {
        set[i][0] = i;
        for (j = 1; j < AES_BLOCK_SIZE; j++)
        {
            set[i][j] = c;
        }
    }

    return;
}

/**
 * Computes a possible 4th round key and puts in @ key_res 
 * the function akes an encrypted lambda-set @ set_encrypted and the set that we save in ot key_res
 * the computation may lead to false positive
*/
void compute_possible_key(uint8_t set_encrypted[256][AES_BLOCK_SIZE], uint8_t key_res[AES_128_KEY_SIZE],const uint8_t Sbox_inv[256])
{
    int i = 0, j = 0, k = 0;
    for (i = 0; i < AES_128_KEY_SIZE; i++)
    {
        for (j = 0; j < 256; j++)
        {
            int sum = 0;
            for (k = 0; k < 256; k++)
            {
                sum ^= decrypt_half_round(set_encrypted[k], i, j,Sbox_inv);
            }
            if (sum == 0)
            {
                if (i % 4 == 0)
                {
                    key_res[i] = j;
                }
                else
                {
                    key_res[modulo_sub(i, 4)] = j;
                }
                break;
            }
        }
    }
}
/**
 * returns the byte that occurs the most between all possible keys
*/
uint8_t max_repeating_byte(uint8_t vec[NUMBER_OF_TRIALS][AES_128_KEY_SIZE], int ind)
{
    uint8_t maxelem;
    int i, j, maxCount, count;
    maxCount = -1;
    for (i = 0; i < NUMBER_OF_TRIALS; i++)
    {
        count = 1;
        for (j = i + 1; j < NUMBER_OF_TRIALS; j++)
        {
            if (vec[j][ind] == vec[i][ind])
            {
                count++;
                if (count > maxCount)
                {
                    maxCount = count;
                    maxelem = vec[j][ind];
                }
            }
        }
    }
    return maxelem;
}

/**
 * Performing attack
*/
int attack(uint8_t (*xtime)(uint8_t), const uint8_t Sbox[256],const uint8_t Sbox_inv[256])
{
    int i = 0, j = 0;
    uint8_t set[256][AES_BLOCK_SIZE];
    uint8_t poss_keys[NUMBER_OF_TRIALS][AES_128_KEY_SIZE];
    uint8_t master_key[AES_128_KEY_SIZE];
    uint8_t ekey[AES_128_KEY_SIZE * 2];
    int nk, pk;

    get_random_k_from_urandom(master_key);
    printf("Fetching a random key for encryption has been done successfully see it below.\n");
    printf("Master key is : ");
    printf("\033[0;32m");
    vector_print(master_key, AES_128_KEY_SIZE);
    printf("\033[0m");
    for (i = 0; i < NUMBER_OF_TRIALS; i++)
    {
        generate_lambda_set(set, (i * 52) % 256); // (i * 52) % 256 random constant (in the set) value.
        for (j = 0; j < 256; j++)
        {
            aes128_enc(set[j], master_key, 4, 0,xtime,Sbox);
        }
        compute_possible_key(set, poss_keys[i],Sbox_inv);
    }

    printf("%d Delta sets were encrypted,\n%d possible keys were computed.\n", NUMBER_OF_TRIALS, NUMBER_OF_TRIALS);
    printf("Will now try to know the actual master key !!!\n");
    nk = 0;
    pk = 16;
    for (i = 0; i < AES_128_KEY_SIZE; i++)
    {
        ekey[i + nk] = max_repeating_byte(poss_keys, i);
    }

    nk = 16;
    pk = 0;

    for (i = 0; i < 4; i++)
    {
        pk = (pk + 16) & 0x10;
        nk = (nk + 16) & 0x10;
        prev_aes128_round_key(ekey + nk, ekey + pk, 3 - i,Sbox);
    }

    if (strncmp((const char *)master_key, (const char *)(ekey + pk), AES_128_KEY_SIZE) == 0)
    {
        printf("\033[0;32m");
        printf("Master key found.\n");
        printf("\033[0m");
        printf("Found key is : ");
        printf("\033[0;31m");
        vector_print(ekey + pk, AES_128_KEY_SIZE);
        printf("\033[0m");
        printf("Attack successful.\n");
        printf("The found key and the master key are identical!!.\n");
        printf("\033[0m");
        return 0;
    }
    return 1;
}

// Full encryption testing purposes...
void encryption(uint8_t block[AES_BLOCK_SIZE],
					 const uint8_t key[AES_128_KEY_SIZE],
					 uint8_t (*xtime)(uint8_t)) {
	uint8_t temp[AES_BLOCK_SIZE];

	printf("Test for the encryption of a block with a key:\n");

	printf("\nBefore encryting, block and key :\n");
    // copy_bc(block,temp);
	memcpy(temp, block, sizeof(uint8_t) * AES_BLOCK_SIZE);
	block_output(temp);
	block_output(key);

	aes128_enc(temp, key, 10, 0, xtime, S);

	printf("\nAfter encrypting, block and key:\n");
	block_output(temp);
	block_output(key);
	printf("\n\n");
}

int main(int argc, char *argv[])
{
    int i=0, count=0, n = 0;
    printf("=============================================================================================\n");                                     
    printf("Exercise 2 Question 1: perform the attack as you want!!\n");
    printf("=============================================================================================\n");  
    printf("Enter number of times you want to try the attack (The key is fetched randomly from urandom):\n");
    scanf("%d", &n);
    printf("Test n is %d\n", n);

    puts("");
    while (i < n)
    {
        printf("Try #%d\n", i+1);
        if (attack(xtime,S,Sinv) == 0)
            count++;

        i++;
        puts("");
    }
    // printf("Test n is %d\n", n);
    // printf("Test n is %d\n", count);
    
    if (count == n)
    {
        printf("\033[0;32m");
        printf("All attacks were successful.\n");
        printf("\033[0m");
        printf("\n");
    }

// Test with test values provided in the standard document
	uint8_t block[AES_BLOCK_SIZE] = {0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a,
									 0x30, 0x8d, 0x31, 0x31, 0x98, 0xa2,
									 0xe0, 0x37, 0x07, 0x34};
	const uint8_t key[AES_128_KEY_SIZE] = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae,
										   0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88,
										   0x09, 0xcf, 0x4f, 0x3c};
                                           
    printf("=============================================================================================\n");                                     
    printf("TESTING For Exercise 2 Question 2 (using values provided in the standard document:)\n");
    printf("=============================================================================================\n");                                     

    printf("Block: \n");
    block_output(block);
    printf("\nKey:\n");
    block_output(key);
    printf("\n---------------------------------------------------------------------------------------------\n");
    printf("\nTesting different cypher for different xtime representation: \n");

    printf("With xtime:\n");
	encryption(block, key, xtime);
	printf("With xtime_variant:\n");
	encryption(block, key, xtime_new);
    printf("\033[0;32m");
    printf("As we see here using different xtime functions lead to get different cypher for the same block and key.");
    printf("\033[0m");
    printf("\n---------------------------------------------------------------------------------------------\n");

    printf("\n*********************************************************************************************\n");

    printf("Testing the same attack with xtime variant\n");
    attack(xtime_new,S,Sinv);
    printf("\033[0;32m");
    printf("As we see here even while changing the xtime function from xtime to xtime_variant (xtime_new) \nWe can also perform the same attack successfully.");
    printf("\033[0m");
    printf("\n*********************************************************************************************\n");

    printf("\n+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\n");
    printf("Testing the attack with different Sbox same xtime:\n");
    printf("Generating a new Sbox and it's inverse:\n");
    uint8_t Sbox_rand[256] = {0};
    uint8_t Sbox_rand_inv[256] = {0};
    generate_random_sbox(Sbox_rand);
	inverse_sbox(Sbox_rand, Sbox_rand_inv);
    printf("Generated Successfully!!\n\n");

    

    attack(xtime,Sbox_rand,Sbox_rand_inv);

    printf("\033[0;32m");
    printf("After changing the Sbox to a random one, we can also perform a successfull attack as you see above.");
    printf("\033[0m");
    printf("\n+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\n");


    printf("\n###############################################################################################\n");
    printf("Testing the attack with different Sbox different xtime:\n");
    printf("Generating a new Sbox and it's inverse:\n");
    uint8_t Sbox_rand1[256] = {0};
    uint8_t Sbox_rand_inv1[256] = {0};
    generate_random_sbox(Sbox_rand1);
	inverse_sbox(Sbox_rand1, Sbox_rand_inv1);
    printf("Generated Successfully!!\n\n");

    

    attack(xtime_new,Sbox_rand1,Sbox_rand_inv1);

    printf("\033[0;32m");
    printf("After changing the Sbox to a random one and changing the xtime in order to change the MDS matrix used in MixColumn, we can also perform a successfull attack as you see above.");
    printf("\033[0m");
    printf("\n###############################################################################################\n");

    return 0;
}