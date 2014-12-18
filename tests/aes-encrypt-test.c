
#include "aes.h"
#include "aes-print-block.h"

#include <string.h>
#include <stdbool.h>


static const uint8_t key_0[AES128_KEY_SIZE] =
{
    0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};
static const uint8_t plain_0[AES128_KEY_SIZE] =
{
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};
static const uint8_t encrypt_0_ref[AES128_KEY_SCHEDULE_SIZE] =
{
    0x0e, 0xdd, 0x33, 0xd3, 0xc6, 0x21, 0xe5, 0x46, 0x45, 0x5b, 0xd8, 0xba, 0x14, 0x18, 0xbe, 0xc8
};

static bool encrypt_test(const uint8_t p_key[AES128_KEY_SIZE],
                              const uint8_t p_plain[AES_BLOCK_SIZE],
                              const uint8_t p_encrypted[AES_BLOCK_SIZE],
                              const char * p_id)
{
    size_t  i;
    uint8_t key_schedule[AES128_KEY_SCHEDULE_SIZE];
    uint8_t block[AES_BLOCK_SIZE];

    aes128_key_schedule(key_schedule, p_key);

    memcpy(block, p_plain, AES_BLOCK_SIZE);
    aes128_encrypt(block, key_schedule);

    printf("Key schedule %s output:\n", p_id);
    for (i = 0; i < AES_BLOCK_SIZE; i += 16u)
    {
        print_block_hex(&block[i], 16u);
    }
    printf("\n");

    return (memcmp(block, p_encrypted, AES_BLOCK_SIZE) == 0);
}

int main(int argc, char **argv)
{
    bool    is_okay;

    (void)argc;
    (void)argv;

    is_okay = encrypt_test(key_0, plain_0, encrypt_0_ref, "0");
    if (!is_okay)
        return 1;
    return 0;
}
