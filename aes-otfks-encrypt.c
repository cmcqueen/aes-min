
#include "aes.h"
#include "aes-add-round-key.h"
#include "aes-sbox.h"
#include "aes-shift-rows.h"
#include "aes-mix-columns.h"
#include "aes-mul2.h"

static void aes128_key_schedule_round(uint8_t p_key[AES128_KEY_SIZE], uint8_t rcon)
{
    uint_fast8_t    round;
    uint8_t       * p_key_0 = p_key;
    uint8_t       * p_key_m1 = p_key + AES128_KEY_SIZE - AES_KEY_SCHEDULE_WORD_SIZE;

    /* Rotate previous word and apply S-box. Also XOR Rcon for first byte. */
    p_key_0[0] ^= aes_sbox(p_key_m1[1]) ^ rcon;
    p_key_0[1] ^= aes_sbox(p_key_m1[2]);
    p_key_0[2] ^= aes_sbox(p_key_m1[3]);
    p_key_0[3] ^= aes_sbox(p_key_m1[0]);

    for (round = 1; round < AES128_KEY_SIZE / AES_KEY_SCHEDULE_WORD_SIZE; ++round)
    {
        p_key_m1 = p_key_0;
        p_key_0 += AES_KEY_SCHEDULE_WORD_SIZE;

        /* XOR in previous word */
        p_key_0[0] ^= p_key_m1[0];
        p_key_0[1] ^= p_key_m1[1];
        p_key_0[2] ^= p_key_m1[2];
        p_key_0[3] ^= p_key_m1[3];
    }
}

void aes128_otfks_encrypt(uint8_t p_block[AES_BLOCK_SIZE], uint8_t p_key[AES128_KEY_SIZE])
{
    uint_fast8_t    round;
    uint8_t         rcon = 1u;

    aes_add_round_key(p_block, p_key);
    for (round = 1; round < AES128_NUM_ROUNDS; ++round)
    {
        aes128_key_schedule_round(p_key, rcon);
        aes_sbox_apply_block(p_block);
        aes_shift_rows(p_block);
        aes_mix_columns(p_block);
        aes_add_round_key(p_block, p_key);

        /* Next rcon */
        rcon = aes_mul2(rcon);
    }
    aes128_key_schedule_round(p_key, rcon);
    aes_sbox_apply_block(p_block);
    aes_shift_rows(p_block);
    aes_add_round_key(p_block, p_key);
}
