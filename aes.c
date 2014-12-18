
#include "aes.h"
#include "aes-sbox.h"
#include "aes-shift-rows.h"
#include "aes-mix-columns.h"
#include "aes-mul2.h"

#include <string.h>

static void aes_add_round_key(uint8_t p_block[AES_BLOCK_SIZE], const uint8_t p_round_key[AES_BLOCK_SIZE])
{
    uint_fast8_t    i;

    for (i = 0; i < AES_BLOCK_SIZE; ++i)
    {
        p_block[i] ^= p_round_key[i];
    }
}

void aes128_encrypt(uint8_t p_block[AES_BLOCK_SIZE], const uint8_t p_key_schedule[AES128_KEY_SCHEDULE_SIZE])
{
    uint_fast8_t    round;

    aes_add_round_key(p_block, p_key_schedule);
    for (round = 1; round < AES128_NUM_ROUNDS; ++round)
    {
        aes_sbox_apply_block(p_block);
        aes_shift_rows(p_block);
        aes_mix_columns(p_block);
        aes_add_round_key(p_block, &p_key_schedule[round * AES_BLOCK_SIZE]);
    }
    aes_sbox_apply_block(p_block);
    aes_shift_rows(p_block);
    aes_add_round_key(p_block, &p_key_schedule[round * AES_BLOCK_SIZE]);
}

void aes128_decrypt(uint8_t p_block[AES_BLOCK_SIZE], const uint8_t p_key_schedule[AES128_KEY_SCHEDULE_SIZE])
{

}

void aes128_key_schedule(uint8_t p_key_schedule[AES128_KEY_SCHEDULE_SIZE], const uint8_t p_key[AES128_KEY_SIZE])
{
    uint_fast8_t    round;
    uint8_t       * p_key_0 = p_key_schedule;
    uint8_t         temp_word[AES_KEY_SCHEDULE_WORD_SIZE];
    uint8_t         temp_byte;
    uint8_t         rcon = 1u;

    memcpy(p_key_0, p_key, AES128_KEY_SIZE);
    p_key_0 += AES128_KEY_SIZE;
    for (round = 0; round < (AES128_KEY_SCHEDULE_SIZE - AES128_KEY_SIZE) / AES_KEY_SCHEDULE_WORD_SIZE; ++round)
    {
        memcpy(p_key_0, p_key_0 - AES_KEY_SCHEDULE_WORD_SIZE, AES_KEY_SCHEDULE_WORD_SIZE);

        if ((round % (AES128_KEY_SIZE / AES_KEY_SCHEDULE_WORD_SIZE)) == 0)
        {
            /* Rotate previous word and apply S-box. Also XOR Rcon for first byte. */
            temp_byte = p_key_0[0];
            p_key_0[0] = aes_sbox(p_key_0[1]) ^ rcon;
            p_key_0[1] = aes_sbox(p_key_0[2]);
            p_key_0[2] = aes_sbox(p_key_0[3]);
            p_key_0[3] = aes_sbox(temp_byte);

            /* Next rcon */
            rcon = aes_mul2(rcon);
        }

        /* XOR in bytes from AES128_KEY_SIZE bytes ago */
        p_key_0[0] ^= p_key_0[0 - (signed)AES128_KEY_SIZE];
        p_key_0[1] ^= p_key_0[1 - (signed)AES128_KEY_SIZE];
        p_key_0[2] ^= p_key_0[2 - (signed)AES128_KEY_SIZE];
        p_key_0[3] ^= p_key_0[3 - (signed)AES128_KEY_SIZE];

        p_key_0 += AES_KEY_SCHEDULE_WORD_SIZE;
    }
}
