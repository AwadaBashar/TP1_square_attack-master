#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "aes-128_enc.h"

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
 * @byte_index: the byte_index of the byte to decrypt (expected to be in [0-15])
 * @key_byte: byte of the key that was xored with the original_byte to decrypt, must be determined before call
 * ex: to decrypt the 2nd byte ie original_byte[1] -> key_byte = key[13], for original_byte[5] -> key[1] ...
*/
uint8_t decrypt_half_round(uint8_t original_byte[AES_BLOCK_SIZE], int byte_index, uint8_t key_byte)
{
    uint8_t dec = 0;

    if (byte_index % 4 != 0)
    {
        // inverting the shift
        dec = original_byte[modulo_sub(byte_index, 4)];
    }
    else // byte_index in first row
    {
        dec = original_byte[byte_index];
    }

    dec ^= key_byte;
    dec = Sinv[dec];
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
void compute_possible_key(uint8_t set_encrypted[256][AES_BLOCK_SIZE], uint8_t key_res[AES_128_KEY_SIZE])
{
    int i = 0, j = 0, k = 0;
    for (i = 0; i < AES_128_KEY_SIZE; i++)
    {
        for (j = 0; j < 256; j++)
        {
            int sum = 0;
            for (k = 0; k < 256; k++)
            {
                sum ^= decrypt_half_round(set_encrypted[k], i, j);
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
uint8_t max_repeating_byte(uint8_t vectors[NUMBER_OF_TRIALS][AES_128_KEY_SIZE], int index)
{
    uint8_t maxelem;
    int i, j, maxCount, count;
    maxCount = -1;
    for (i = 0; i < NUMBER_OF_TRIALS; i++)
    {
        count = 1;
        for (j = i + 1; j < NUMBER_OF_TRIALS; j++)
        {
            if (vectors[j][index] == vectors[i][index])
            {
                count++;
                if (count > maxCount)
                {
                    maxCount = count;
                    maxelem = vectors[j][index];
                }
            }
        }
    }
    return maxelem;
}

/**
 * Performing attack
*/
int attack()
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
            aes128_enc(set[j], master_key, 4, 0);
        }
        compute_possible_key(set, poss_keys[i]);
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
        prev_aes128_round_key(ekey + nk, ekey + pk, 3 - i);
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

int main(int argc, char *argv[])
{
    int i=0, count=0, n = 0;
    printf("Enter number of times you want to try the attack :\n");
    scanf("%d", &n);
    printf("Test n is %d\n", n);

    puts("");
    while (i < n)
    {
        printf("Try #%d\n", i+1);
        if (attack() == 0)
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
    }

    return 0;
}