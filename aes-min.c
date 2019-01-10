/*****************************************************************************
 * aes-min.c
 *
 * Minimal byte-oriented AES-128 encryption/decryption implementation suitable
 * for small microprocessors.
 ****************************************************************************/

/*****************************************************************************
 * Includes
 ****************************************************************************/

#include "aes-min.h"
#include "aes-block-xor.h"
#include "aes-mul2.h"
#include "aes-sbox.h"
#include "aes-shift-rows.h"
#include "aes-mix-columns.h"

#include <string.h>

/*****************************************************************************
 * Defines
 ****************************************************************************/

#define AES_KEY_SCHEDULE_FIRST_RCON     1u
#define AES128_KEY_SCHEDULE_LAST_RCON   54u

/*****************************************************************************
 * Local function prototypes
 ****************************************************************************/

static void aes128_key_schedule_round(uint8_t p_key[AES128_KEY_SIZE], uint8_t rcon);
static void aes128_key_schedule_inv_round(uint8_t p_key[AES128_KEY_SIZE], uint8_t rcon);

/*****************************************************************************
 * Functions
 ****************************************************************************/

/* AES-128 encryption.
 *
 * p_block points to a 16-byte buffer of plain data to encrypt. Encryption
 * is done in-place in that buffer.
 * p_key_schedule points to a pre-calculated key schedule, which can be
 * calculated by aes128_key_schedule().
 */
void aes128_encrypt(uint8_t p_block[AES_BLOCK_SIZE], const uint8_t p_key_schedule[AES128_KEY_SCHEDULE_SIZE])
{
    uint_fast8_t    round;

    aes_block_xor(p_block, p_key_schedule);
    for (round = 1; round < AES128_NUM_ROUNDS; ++round)
    {
        aes_sbox_apply_block(p_block);
        aes_shift_rows(p_block);
        aes_mix_columns(p_block);
        aes_block_xor(p_block, &p_key_schedule[round * AES_BLOCK_SIZE]);
    }
    aes_sbox_apply_block(p_block);
    aes_shift_rows(p_block);
    aes_block_xor(p_block, &p_key_schedule[AES128_NUM_ROUNDS * AES_BLOCK_SIZE]);
}

/* AES-128 decryption.
 *
 * p_block points to a 16-byte buffer of encrypted data to decrypt. Decryption
 * is done in-place in that buffer.
 * p_key_schedule points to a pre-calculated key schedule, which can be
 * calculated by aes128_key_schedule().
 */
void aes128_decrypt(uint8_t p_block[AES_BLOCK_SIZE], const uint8_t p_key_schedule[AES128_KEY_SCHEDULE_SIZE])
{
    uint_fast8_t    round;

    aes_block_xor(p_block, &p_key_schedule[AES128_NUM_ROUNDS * AES_BLOCK_SIZE]);
    aes_shift_rows_inv(p_block);
    aes_sbox_inv_apply_block(p_block);
    for (round = AES128_NUM_ROUNDS - 1u; round >= 1; --round)
    {
        aes_block_xor(p_block, &p_key_schedule[round * AES_BLOCK_SIZE]);
        aes_mix_columns_inv(p_block);
        aes_shift_rows_inv(p_block);
        aes_sbox_inv_apply_block(p_block);
    }
    aes_block_xor(p_block, p_key_schedule);
}

void aes128_key_schedule(uint8_t p_key_schedule[AES128_KEY_SCHEDULE_SIZE], const uint8_t p_key[AES128_KEY_SIZE])
{
    uint_fast8_t    round;
    uint8_t       * p_key_0 = p_key_schedule + AES128_KEY_SIZE;
    uint8_t         temp_byte;
    uint8_t         rcon = AES_KEY_SCHEDULE_FIRST_RCON;

    /* Initial part of key schedule is simply the AES-128 key copied verbatim. */
    memcpy(p_key_schedule, p_key, AES128_KEY_SIZE);

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

/* AES-128 encryption with on-the-fly key schedule calculation.
 *
 * p_block points to a 16-byte buffer of plain data to encrypt. Encryption
 * is done in-place in that buffer.
 * p_key must initially point to a starting key state for encryption, which is
 * simply the 16 bytes of the AES-128 key. Key schedule is calculated on-the-
 * fly in that buffer, so the buffer must re-initialised for subsequent
 * encryption operations.
 */
void aes128_otfks_encrypt(uint8_t p_block[AES_BLOCK_SIZE], uint8_t p_key[AES128_KEY_SIZE])
{
    uint_fast8_t    round;
    uint8_t         rcon = AES_KEY_SCHEDULE_FIRST_RCON;

    aes_block_xor(p_block, p_key);
    for (round = 1; round < AES128_NUM_ROUNDS; ++round)
    {
        aes128_key_schedule_round(p_key, rcon);
        aes_sbox_apply_block(p_block);
        aes_shift_rows(p_block);
        aes_mix_columns(p_block);
        aes_block_xor(p_block, p_key);

        /* Next rcon */
        rcon = aes_mul2(rcon);
    }
    aes128_key_schedule_round(p_key, rcon);
    aes_sbox_apply_block(p_block);
    aes_shift_rows(p_block);
    aes_block_xor(p_block, p_key);
}

/* Calculate the starting key state needed for decryption with on-the-fly key
 * schedule calculation. The starting decryption key state is the last 16 bytes
 * of the AES-128 key schedule.
 * The decryption start key calculation is done in-place in the buffer p_key[].
 * So p_key points to a 16-byte buffer containing the AES-128 key. On exit, it
 * contains the decryption start key state suitable for aes128_otfks_decrypt().
 */
void aes128_otfks_decrypt_start_key(uint8_t p_key[AES128_KEY_SIZE])
{
    uint_fast8_t    round;
    uint8_t         rcon = AES_KEY_SCHEDULE_FIRST_RCON;

    for (round = 0; round < AES128_NUM_ROUNDS; ++round)
    {
        aes128_key_schedule_round(p_key, rcon);

        /* Next rcon */
        rcon = aes_mul2(rcon);
    }
}

/* AES-128 decryption with on-the-fly key schedule calculation.
 *
 * p_block points to a 16-byte buffer of encrypted data to decrypt. Decryption
 * is done in-place in that buffer.
 * p_key must initially point to a starting key state for decryption, which is
 * the last 16 bytes of the AES-128 key schedule. It can be calculated from the
 * AES-128 16-byte key by aes128_otfks_decrypt_start_key(). Key schedule is
 * calculated on-the-fly in that buffer, so the buffer must re-initialised for
 * subsequent decryption operations.
 */
void aes128_otfks_decrypt(uint8_t p_block[AES_BLOCK_SIZE], uint8_t p_key[AES128_KEY_SIZE])
{
    uint_fast8_t    round;
    uint8_t         rcon = AES128_KEY_SCHEDULE_LAST_RCON;

    aes_block_xor(p_block, p_key);
    aes_shift_rows_inv(p_block);
    aes_sbox_inv_apply_block(p_block);
    for (round = AES128_NUM_ROUNDS - 1u; round >= 1; --round)
    {
        aes128_key_schedule_inv_round(p_key, rcon);
        aes_block_xor(p_block, p_key);
        aes_mix_columns_inv(p_block);
        aes_shift_rows_inv(p_block);
        aes_sbox_inv_apply_block(p_block);

        /* Previous rcon */
        rcon = aes_div2(rcon);
    }
    aes128_key_schedule_inv_round(p_key, rcon);
    aes_block_xor(p_block, p_key);
}

/*****************************************************************************
 * Local functions
 ****************************************************************************/

/* This is used for aes128_otfks_encrypt(), on-the-fly key schedule encryption.
 * It is also used by aes128_otfks_decrypt_start_key() to calculate the
 * starting key state for decryption with on-the-fly key schedule calculation.
 * rcon for the round must be provided, out of the sequence:
 *     1, 2, 4, 8, 16, 32, 64, 128, 27, 54
 * Subsequent values can be calculated with aes_mul2().
 */
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

/* This is used for aes128_otfks_decrypt(), on-the-fly key schedule decryption.
 * rcon for the round must be provided, out of the sequence:
 *     54, 27, 128, 64, 32, 16, 8, 4, 2, 1
 * Subsequent values can be calculated with aes_div2().
 */
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
