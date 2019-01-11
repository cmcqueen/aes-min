/*****************************************************************************
 * aes-min.h
 *
 * Minimal byte-oriented AES-128 encryption/decryption implementation suitable
 * for small microprocessors.
 ****************************************************************************/

#ifndef AES_MIN_H
#define AES_MIN_H

/*****************************************************************************
 * Includes
 ****************************************************************************/

#include <stdint.h>

/*****************************************************************************
 * Defines
 ****************************************************************************/

#define AES_BLOCK_SIZE              16u
#define AES_COLUMN_SIZE             4u
#define AES_NUM_COLUMNS             4u

#define AES_KEY_SCHEDULE_WORD_SIZE  4u

#define AES128_NUM_ROUNDS           10u
#define AES128_KEY_SIZE             16u
#define AES128_KEY_SCHEDULE_SIZE    (AES_BLOCK_SIZE * (AES128_NUM_ROUNDS + 1u))

/*****************************************************************************
 * Inline functions
 ****************************************************************************/

/*
 * XOR the specified round key into the AES block.
 * Fixed block size.
 */
static inline void aes_block_xor(uint8_t p_block[AES_BLOCK_SIZE], const uint8_t p_data[AES_BLOCK_SIZE])
{
    uint_fast8_t    i;

    for (i = 0; i < AES_BLOCK_SIZE; ++i)
    {
        p_block[i] ^= p_data[i];
    }
}

/*****************************************************************************
 * Function prototypes
 ****************************************************************************/

void aes128_encrypt(uint8_t p_block[AES_BLOCK_SIZE], const uint8_t p_key_schedule[AES128_KEY_SCHEDULE_SIZE]);
void aes128_decrypt(uint8_t p_block[AES_BLOCK_SIZE], const uint8_t p_key_schedule[AES128_KEY_SCHEDULE_SIZE]);

void aes128_key_schedule(uint8_t p_key_schedule[AES128_KEY_SCHEDULE_SIZE], const uint8_t p_key[AES128_KEY_SIZE]);

void aes128_otfks_encrypt(uint8_t p_block[AES_BLOCK_SIZE], uint8_t p_key[AES128_KEY_SIZE]);
void aes128_otfks_decrypt(uint8_t p_block[AES_BLOCK_SIZE], uint8_t p_decrypt_start_key[AES128_KEY_SIZE]);

void aes128_otfks_decrypt_start_key(uint8_t p_key[AES128_KEY_SIZE]);


#endif /* !defined(AES_MIN_H) */
