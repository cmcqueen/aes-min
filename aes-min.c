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

#include <string.h>

/*****************************************************************************
 * Defines
 ****************************************************************************/

#define AES_KEY_SCHEDULE_FIRST_RCON     1u
#define AES128_KEY_SCHEDULE_LAST_RCON   54u

#define AES_REDUCE_BYTE                 0x1Bu
#define AES_2_INVERSE                   141u

#define AES_INV_CHAIN_LEN               11u

/*****************************************************************************
 * Look-up tables
 ****************************************************************************/

#ifndef ENABLE_SBOX_SMALL

static const uint8_t aes_sbox_table[256u] =
{
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16
};

static const uint8_t aes_sbox_inv_table[256u] =
{
    0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
    0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
    0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
    0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
    0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
    0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
    0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
    0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
    0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
    0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
    0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
    0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
    0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
    0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
    0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D
};

#endif

/*****************************************************************************
 * Local function prototypes
 ****************************************************************************/

static void aes128_key_schedule_round(uint8_t p_key[AES128_KEY_SIZE], uint8_t rcon);
static void aes128_key_schedule_inv_round(uint8_t p_key[AES128_KEY_SIZE], uint8_t rcon);
static uint8_t aes_mul(uint8_t a, uint8_t b);
static uint8_t aes_inv(uint8_t a);
static uint8_t aes_sbox(uint8_t a);
static uint8_t aes_sbox_inv(uint8_t a);
static void aes_sbox_apply_block(uint8_t p_block[AES_BLOCK_SIZE]);
static void aes_sbox_inv_apply_block(uint8_t p_block[AES_BLOCK_SIZE]);
static void aes_shift_rows(uint8_t p_block[AES_BLOCK_SIZE]);
static void aes_shift_rows_inv(uint8_t p_block[AES_BLOCK_SIZE]);
static void aes_mix_columns(uint8_t p_block[AES_BLOCK_SIZE]);
static void aes_mix_columns_inv(uint8_t p_block[AES_BLOCK_SIZE]);

/*****************************************************************************
 * Inline functions
 ****************************************************************************/

#if 0

/* This is probably the most straight-forward expression of the algorithm.
 * This seems more likely to have variable timing, although inspection
 * of compiled code would be needed to confirm it.
 * It is more likely to have variable timing when no optimisations are
 * enabled. */
static inline uint8_t aes_mul2(uint8_t a)
{
    uint8_t result;

    result = a << 1u;
    if (a & 0x80u)
        result ^= AES_REDUCE_BYTE;
    return result;
}

static inline uint8_t aes_div2(uint8_t a)
{
    uint8_t result;

    result = a >> 1u;
    if (a & 1u)
        result ^= AES_2_INVERSE;
    return result;
}

#elif 0

/* This hopefully has fixed timing, although inspection
 * of compiled code would be needed to confirm it. */
static inline uint8_t aes_mul2(uint8_t a)
{
    static const uint8_t reduce[2] = { 0, AES_REDUCE_BYTE };

    return (a << 1u) ^ reduce[a >= 0x80u];
}

static inline uint8_t aes_div2(uint8_t a)
{
    static const uint8_t reduce[2] = { 0, AES_2_INVERSE };

    return (a >> 1u) ^ reduce[a & 1u];
}

#else

/* This hopefully has fixed timing, although inspection
 * of compiled code would be needed to confirm it. */
static inline uint8_t aes_mul2(uint8_t a)
{
    return (a << 1u) ^ ((-(a >= 0x80u)) & AES_REDUCE_BYTE);
}

static inline uint8_t aes_div2(uint8_t a)
{
    return (a >> 1u) ^ ((-(a & 1u)) & AES_2_INVERSE);
}

#endif

/* Hopefully the compiler reduces this to a single rotate instruction.
 * However in testing with gcc on x86-64, it didn't happen. But it is target-
 * and compiler-specific.
 *
 * Alternatively for a particular platform:
 *     - Use an intrinsic 8-bit rotate function provided by the compiler.
 *     - Use inline assembler.
 *
 * TODO: Examine code produced on the target platform.
 */
static inline uint8_t aes_rotate_left_uint8(uint8_t a, uint_fast8_t num_bits)
{
    return ((a << num_bits) | (a >> (8u - num_bits)));
}

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

uint8_t _aes_inv_for_test(uint8_t a)
{
    return aes_inv(a);
}

void _aes_sbox_apply_block_for_test(uint8_t p_block[AES_BLOCK_SIZE])
{
    aes_sbox_apply_block(p_block);
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

/* Multiply two numbers in Galois field GF(2^8) with reduction polynomial
 * 0x11B.
 * TODO: To prevent timing attacks, analyse the compiler-generated code
 * to see if it has constant execution time regardless of input values.
 */
static uint8_t aes_mul(uint8_t a, uint8_t b)
{
    uint8_t         result = 0;
    uint_fast8_t    i;
    for (i = 0; i < 8u; i++)
    {
#if 0
        /* This code variant is less likely to have constant execution time,
         * and thus more likely to be vulnerable to timing attacks. */
        if (b & 1)
        {
            result ^= a;
        }
#else
        result ^= (-(b & 1u)) & a;
#endif
        a = aes_mul2(a);
        b >>= 1;
    }
    return result;
}

/* Calculation of inverse in GF(2^8), by exponentiation to power 254.
 * Use minimal addition chain to raise to the power of 254, which requires
 * 11 multiplies.
 * There are many addition chains of length 11 for 254. This one was picked
 * because it has the most multiplies by the previous value, and least
 * references to earlier history, which in theory could minimise the size of
 * prev_values[]. However, in the end we do the simplest possible
 * implementation of the algorithm to minimise code size (because aes_inv() is
 * used to achieve smallest possible S-box implementation), so it doesn't
 * really matter which addition chain we pick.
 */
static uint8_t aes_inv(uint8_t a)
{
    static const uint8_t addition_chain_idx[AES_INV_CHAIN_LEN] = { 0, 1, 1, 3, 4, 3, 6, 7, 3, 9, 1 };
    uint_fast8_t    i;
    uint8_t         prev_values[AES_INV_CHAIN_LEN];

    for (i = 0; i < AES_INV_CHAIN_LEN; i++)
    {
        prev_values[i] = a;
        a = aes_mul(a, prev_values[addition_chain_idx[i]]);
    }
    return a;
}

#ifdef ENABLE_SBOX_SMALL

static uint8_t aes_sbox(uint8_t a)
{
    uint8_t x;

    a = aes_inv(a);

    x = aes_rotate_left_uint8(a, 1u);
    x ^= aes_rotate_left_uint8(x, 1u);
    x ^= aes_rotate_left_uint8(x, 2u);

    return a ^ x ^ 0x63u;
}

static uint8_t aes_sbox_inv(uint8_t a)
{
    uint8_t x;

    x = aes_rotate_left_uint8(a, 1u);
    a = aes_rotate_left_uint8(x, 2u);
    x ^= a;
    a = aes_rotate_left_uint8(a, 3u);

    return aes_inv(a ^ x ^ 0x05u);
}

#else /* ENABLE_SBOX_SMALL */

static uint8_t aes_sbox(uint8_t a)
{
    return aes_sbox_table[a];
}

static uint8_t aes_sbox_inv(uint8_t a)
{
    return aes_sbox_inv_table[a];
}

#endif /* ENABLE_SBOX_SMALL */

static void aes_sbox_apply_block(uint8_t p_block[AES_BLOCK_SIZE])
{
    uint_fast8_t    i;

    for (i = 0; i < AES_BLOCK_SIZE; ++i)
    {
        p_block[i] = aes_sbox(p_block[i]);
    }
}

static void aes_sbox_inv_apply_block(uint8_t p_block[AES_BLOCK_SIZE])
{
    uint_fast8_t    i;

    for (i = 0; i < AES_BLOCK_SIZE; ++i)
    {
        p_block[i] = aes_sbox_inv(p_block[i]);
    }
}

static void aes_shift_rows(uint8_t p_block[AES_BLOCK_SIZE])
{
    uint8_t temp_byte;

    /* First row doesn't shift */

    /* Shift the second row */
    temp_byte = p_block[0 * AES_COLUMN_SIZE + 1u];
    p_block[0  * AES_COLUMN_SIZE + 1u] = p_block[1u * AES_COLUMN_SIZE + 1u];
    p_block[1u * AES_COLUMN_SIZE + 1u] = p_block[2u * AES_COLUMN_SIZE + 1u];
    p_block[2u * AES_COLUMN_SIZE + 1u] = p_block[3u * AES_COLUMN_SIZE + 1u];
    p_block[3u * AES_COLUMN_SIZE + 1u] = temp_byte;

    /* Shift the third row */
    temp_byte = p_block[0 * AES_COLUMN_SIZE + 2u];
    p_block[0  * AES_COLUMN_SIZE + 2u] = p_block[2u * AES_COLUMN_SIZE + 2u];
    p_block[2u * AES_COLUMN_SIZE + 2u] = temp_byte;
    temp_byte = p_block[1u * AES_COLUMN_SIZE + 2u];
    p_block[1u * AES_COLUMN_SIZE + 2u] = p_block[3u * AES_COLUMN_SIZE + 2u];
    p_block[3u * AES_COLUMN_SIZE + 2u] = temp_byte;

    /* Shift the fourth row */
    temp_byte = p_block[3u * AES_COLUMN_SIZE + 3u];
    p_block[3u * AES_COLUMN_SIZE + 3u] = p_block[2u * AES_COLUMN_SIZE + 3u];
    p_block[2u * AES_COLUMN_SIZE + 3u] = p_block[1u * AES_COLUMN_SIZE + 3u];
    p_block[1u * AES_COLUMN_SIZE + 3u] = p_block[0  * AES_COLUMN_SIZE + 3u];
    p_block[0  * AES_COLUMN_SIZE + 3u] = temp_byte;
}

static void aes_shift_rows_inv(uint8_t p_block[AES_BLOCK_SIZE])
{
    uint8_t temp_byte;

    /* First row doesn't shift */

    /* Shift the second row */
    temp_byte = p_block[3u * AES_COLUMN_SIZE + 1u];
    p_block[3u * AES_COLUMN_SIZE + 1u] = p_block[2u * AES_COLUMN_SIZE + 1u];
    p_block[2u * AES_COLUMN_SIZE + 1u] = p_block[1u * AES_COLUMN_SIZE + 1u];
    p_block[1u * AES_COLUMN_SIZE + 1u] = p_block[0  * AES_COLUMN_SIZE + 1u];
    p_block[0  * AES_COLUMN_SIZE + 1u] = temp_byte;

    /* Shift the third row */
    temp_byte = p_block[0 * AES_COLUMN_SIZE + 2u];
    p_block[0  * AES_COLUMN_SIZE + 2u] = p_block[2u * AES_COLUMN_SIZE + 2u];
    p_block[2u * AES_COLUMN_SIZE + 2u] = temp_byte;
    temp_byte = p_block[1u * AES_COLUMN_SIZE + 2u];
    p_block[1u * AES_COLUMN_SIZE + 2u] = p_block[3u * AES_COLUMN_SIZE + 2u];
    p_block[3u * AES_COLUMN_SIZE + 2u] = temp_byte;

    /* Shift the fourth row */
    temp_byte = p_block[0 * AES_COLUMN_SIZE + 3u];
    p_block[0  * AES_COLUMN_SIZE + 3u] = p_block[1u * AES_COLUMN_SIZE + 3u];
    p_block[1u * AES_COLUMN_SIZE + 3u] = p_block[2u * AES_COLUMN_SIZE + 3u];
    p_block[2u * AES_COLUMN_SIZE + 3u] = p_block[3u * AES_COLUMN_SIZE + 3u];
    p_block[3u * AES_COLUMN_SIZE + 3u] = temp_byte;
}

static void aes_mix_columns(uint8_t p_block[AES_BLOCK_SIZE])
{
    uint8_t         temp_column[AES_COLUMN_SIZE];
    uint_fast8_t    i;
    uint_fast8_t    j;
    uint8_t         byte_value;
    uint8_t         byte_value_2;

    for (i = 0; i < AES_NUM_COLUMNS; i++)
    {
        memset(temp_column, 0, AES_COLUMN_SIZE);
        for (j = 0; j < AES_COLUMN_SIZE; j++)
        {
            byte_value = p_block[i * AES_COLUMN_SIZE + j];
            byte_value_2 = aes_mul2(byte_value);
            temp_column[(j + 0 ) % AES_COLUMN_SIZE] ^= byte_value_2;
            temp_column[(j + 1u) % AES_COLUMN_SIZE] ^= byte_value;
            temp_column[(j + 2u) % AES_COLUMN_SIZE] ^= byte_value;
            temp_column[(j + 3u) % AES_COLUMN_SIZE] ^= byte_value ^ byte_value_2;
        }
        memcpy(&p_block[i * AES_COLUMN_SIZE], temp_column, AES_COLUMN_SIZE);
    }
}

/* 14 = 1110b
 *  9 = 1001b
 * 13 = 1101b
 * 11 = 1011b
 */
static void aes_mix_columns_inv(uint8_t p_block[AES_BLOCK_SIZE])
{
    uint8_t         temp_column[AES_COLUMN_SIZE];
    uint_fast8_t    i;
    uint_fast8_t    j;
    uint8_t         byte_value;
    uint8_t         byte_value_2;
    uint8_t         byte_value_4;
    uint8_t         byte_value_8;

    for (i = 0; i < AES_NUM_COLUMNS; i++)
    {
        memset(temp_column, 0, AES_COLUMN_SIZE);
        for (j = 0; j < AES_COLUMN_SIZE; j++)
        {
            byte_value = p_block[i * AES_COLUMN_SIZE + j];
            byte_value_2 = aes_mul2(byte_value);
            byte_value_4 = aes_mul2(byte_value_2);
            byte_value_8 = aes_mul2(byte_value_4);
            temp_column[(j + 0 ) % AES_COLUMN_SIZE] ^= byte_value_8 ^ byte_value_4 ^ byte_value_2;  // 14 = 1110b
            temp_column[(j + 1u) % AES_COLUMN_SIZE] ^= byte_value_8 ^ byte_value;                   //  9 = 1001b
            temp_column[(j + 2u) % AES_COLUMN_SIZE] ^= byte_value_8 ^ byte_value_4 ^ byte_value;    // 13 = 1101b
            temp_column[(j + 3u) % AES_COLUMN_SIZE] ^= byte_value_8 ^ byte_value_2 ^ byte_value;    // 11 = 1011b
        }
        memcpy(&p_block[i * AES_COLUMN_SIZE], temp_column, AES_COLUMN_SIZE);
    }
}
