
#include "aes.h"
#include "aes-add-round-key.h"
#include "aes-key-schedule-round.h"
#include "aes-sbox.h"
#include "aes-shift-rows.h"
#include "aes-mix-columns.h"
#include "aes-mul2.h"       /* For aes_mul2() and aes_div2() */

static void aes128_key_schedule_inv_round(uint8_t p_key[AES128_KEY_SIZE], uint8_t rcon)
{
    uint_fast8_t    round;
    uint8_t       * p_key_0 = p_key + AES128_KEY_SIZE - AES_KEY_SCHEDULE_WORD_SIZE;
    uint8_t       * p_key_m1 = p_key_0 - AES_KEY_SCHEDULE_WORD_SIZE;

    for (round = 1; round < AES128_KEY_SIZE / AES_KEY_SCHEDULE_WORD_SIZE; ++round)
    {
        /* XOR in previous word */
        p_key_0[0] ^= p_key_m1[0];
        p_key_0[1] ^= p_key_m1[1];
        p_key_0[2] ^= p_key_m1[2];
        p_key_0[3] ^= p_key_m1[3];

        p_key_0 = p_key_m1;
        p_key_m1 -= AES_KEY_SCHEDULE_WORD_SIZE;
    }

    /* Rotate previous word and apply S-box. Also XOR Rcon for first byte. */
    p_key_m1 = p_key + AES128_KEY_SIZE - AES_KEY_SCHEDULE_WORD_SIZE;
    p_key_0[0] ^= aes_sbox(p_key_m1[1]) ^ rcon;
    p_key_0[1] ^= aes_sbox(p_key_m1[2]);
    p_key_0[2] ^= aes_sbox(p_key_m1[3]);
    p_key_0[3] ^= aes_sbox(p_key_m1[0]);
}

void aes128_otfks_decrypt_start_key(uint8_t p_key[AES128_KEY_SIZE])
{
    uint_fast8_t    round;
    uint8_t         rcon = 1u;

    for (round = 0; round < AES128_NUM_ROUNDS; ++round)
    {
        aes128_key_schedule_round(p_key, rcon);

        /* Next rcon */
        rcon = aes_mul2(rcon);
    }
}

void aes128_otfks_decrypt(uint8_t p_block[AES_BLOCK_SIZE], uint8_t p_key[AES128_KEY_SIZE])
{
    uint_fast8_t    round;
    uint8_t         rcon = 54u;

    aes_add_round_key(p_block, p_key);
    aes_shift_rows_inv(p_block);
    aes_sbox_inv_apply_block(p_block);
    for (round = AES128_NUM_ROUNDS - 1u; round >= 1; --round)
    {
        aes128_key_schedule_inv_round(p_key, rcon);
        aes_add_round_key(p_block, p_key);
        aes_mix_columns_inv(p_block);
        aes_shift_rows_inv(p_block);
        aes_sbox_inv_apply_block(p_block);

        /* Previous rcon */
        rcon = aes_div2(rcon);
    }
    aes128_key_schedule_inv_round(p_key, rcon);
    aes_add_round_key(p_block, p_key);
}
