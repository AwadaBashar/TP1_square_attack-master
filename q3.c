#include "helpers.h"

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

void aes3rounds_keyed_function (
    uint8_t block[AES_BLOCK_SIZE], 
    const uint8_t key1[AES_128_KEY_SIZE], 
    const uint8_t key2[AES_128_KEY_SIZE])
{
    uint8_t block_enc_k1[AES_BLOCK_SIZE], block_enc_k2[AES_BLOCK_SIZE];
    unsigned int i;

    for (i = 0; i < AES_BLOCK_SIZE; ++i) {
        block_enc_k1[i] = block[i];
        block_enc_k2[i] = block[i];
    }

    aes128_enc(block_enc_k1, key1, 3, 1);
    aes128_enc(block_enc_k2, key2, 3, 1);

    for (i = 0; i < AES_BLOCK_SIZE; ++i) {
        block[i] = block_enc_k1[i] ^ block_enc_k2[i];
    }
    return;
}

int main(int argc, char const *argv[]){
    uint8_t lambda_set[256][AES_BLOCK_SIZE];
    uint8_t key1[AES_128_KEY_SIZE] = {0x75, 0xc6, 0xa6, 0xe8, 0x26, 0x15,
                                      0x83, 0x4e, 0x6b, 0xd0, 0xc1, 0x71, 0x81, 0xe2, 0xcf, 0x0a};

    uint8_t key2[AES_128_KEY_SIZE] = {0x52, 0xe9, 0x0c, 0x72, 0xd6, 0xb2,
                                      0x49, 0x14, 0x4a, 0xdd, 0x40, 0x12, 0xc1, 0x88, 0x48, 0x95};

    int i = 0, sum = 0;
    printf("Test of the distinguisher on the keyed function.\n");
    printf("Generating lambda set...\n");
    generate_lambda_set(lambda_set, 69); // "random" set
    printf("Lambda set has been generated successfully.\n");
    for (i = 0; i < 256; i++)
    {
        aes3rounds_keyed_function(lambda_set[i], key1, key2);
    }
    printf("aes3rounds_keyed_function applied on all blocks of the set.\n");
    for (i = 0; i < 256; i++)
    {
        sum ^= lambda_set[i][0];
    }

    printf("The sum of all the bytes of index 0 in the lambda set = %d\n", sum);
    if (sum == 0)
    {
        printf("Sucess!! After successful testing, the distinguisher operates with the aes3rounds_keyed_function..\n");
    }
    return 0;
}