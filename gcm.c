/*****************************************************************************
 * gcm.c
 *
 * Functions to support GCM mode.
 ****************************************************************************/

/*****************************************************************************
 * Includes
 ****************************************************************************/

#include "gcm.h"

#include "aes-block-xor.h"

#include <string.h>

/*****************************************************************************
 * Defines
 ****************************************************************************/

#define UINT128_ELEMENT_SIZE		sizeof(uint128_element_t)

#define UINT128_ELEMENT_SIZE_BITS   (8u * UINT128_ELEMENT_SIZE)
#define UINT128_NUM_ELEMENTS        (AES_BLOCK_SIZE / UINT128_ELEMENT_SIZE)

/*****************************************************************************
 * Types
 ****************************************************************************/

/* Set an element type that is efficient on the target platform.
 * Ensure UINT128_ELEMENT_SIZE is suitably set to match.
 * unsigned int is a reasonable default, but it could be uint16_t, uint8_t.
 * If uint8_t is used, uint128_struct_from_bytes() etc could simply be
 * replaced by memcpy(). */
typedef unsigned int uint128_element_t;

/*
 * This struct is basically to enable big-integer calculations in the 128-bit
 * Galois field. The struct is fixed size for this purpose. The functions that
 * operate on it are specialised to do the bit-reversed operations needed
 * specifically for the Galois 128-bit multiply used in the GCM algorithm.
 */
typedef struct
{
    uint128_element_t   element[UINT128_NUM_ELEMENTS];
} uint128_struct_t;

/*****************************************************************************
 * Look-up tables
 ****************************************************************************/

/*
 * Fixed look-up table to efficiently implement block_mul256().
 * This data is independent of the GCM hash key, so it's a const table, and can
 * be located in Flash or other non-volatile memory on an embedded system.
 */
const uint16_t mul256_reduce_table[256] =
{
    0x0000u, 0x01C2u, 0x0384u, 0x0246u, 0x0708u, 0x06CAu, 0x048Cu, 0x054Eu, 0x0E10u, 0x0FD2u, 0x0D94u, 0x0C56u, 0x0918u, 0x08DAu, 0x0A9Cu, 0x0B5Eu,
    0x1C20u, 0x1DE2u, 0x1FA4u, 0x1E66u, 0x1B28u, 0x1AEAu, 0x18ACu, 0x196Eu, 0x1230u, 0x13F2u, 0x11B4u, 0x1076u, 0x1538u, 0x14FAu, 0x16BCu, 0x177Eu,
    0x3840u, 0x3982u, 0x3BC4u, 0x3A06u, 0x3F48u, 0x3E8Au, 0x3CCCu, 0x3D0Eu, 0x3650u, 0x3792u, 0x35D4u, 0x3416u, 0x3158u, 0x309Au, 0x32DCu, 0x331Eu,
    0x2460u, 0x25A2u, 0x27E4u, 0x2626u, 0x2368u, 0x22AAu, 0x20ECu, 0x212Eu, 0x2A70u, 0x2BB2u, 0x29F4u, 0x2836u, 0x2D78u, 0x2CBAu, 0x2EFCu, 0x2F3Eu,
    0x7080u, 0x7142u, 0x7304u, 0x72C6u, 0x7788u, 0x764Au, 0x740Cu, 0x75CEu, 0x7E90u, 0x7F52u, 0x7D14u, 0x7CD6u, 0x7998u, 0x785Au, 0x7A1Cu, 0x7BDEu,
    0x6CA0u, 0x6D62u, 0x6F24u, 0x6EE6u, 0x6BA8u, 0x6A6Au, 0x682Cu, 0x69EEu, 0x62B0u, 0x6372u, 0x6134u, 0x60F6u, 0x65B8u, 0x647Au, 0x663Cu, 0x67FEu,
    0x48C0u, 0x4902u, 0x4B44u, 0x4A86u, 0x4FC8u, 0x4E0Au, 0x4C4Cu, 0x4D8Eu, 0x46D0u, 0x4712u, 0x4554u, 0x4496u, 0x41D8u, 0x401Au, 0x425Cu, 0x439Eu,
    0x54E0u, 0x5522u, 0x5764u, 0x56A6u, 0x53E8u, 0x522Au, 0x506Cu, 0x51AEu, 0x5AF0u, 0x5B32u, 0x5974u, 0x58B6u, 0x5DF8u, 0x5C3Au, 0x5E7Cu, 0x5FBEu,
    0xE100u, 0xE0C2u, 0xE284u, 0xE346u, 0xE608u, 0xE7CAu, 0xE58Cu, 0xE44Eu, 0xEF10u, 0xEED2u, 0xEC94u, 0xED56u, 0xE818u, 0xE9DAu, 0xEB9Cu, 0xEA5Eu,
    0xFD20u, 0xFCE2u, 0xFEA4u, 0xFF66u, 0xFA28u, 0xFBEAu, 0xF9ACu, 0xF86Eu, 0xF330u, 0xF2F2u, 0xF0B4u, 0xF176u, 0xF438u, 0xF5FAu, 0xF7BCu, 0xF67Eu,
    0xD940u, 0xD882u, 0xDAC4u, 0xDB06u, 0xDE48u, 0xDF8Au, 0xDDCCu, 0xDC0Eu, 0xD750u, 0xD692u, 0xD4D4u, 0xD516u, 0xD058u, 0xD19Au, 0xD3DCu, 0xD21Eu,
    0xC560u, 0xC4A2u, 0xC6E4u, 0xC726u, 0xC268u, 0xC3AAu, 0xC1ECu, 0xC02Eu, 0xCB70u, 0xCAB2u, 0xC8F4u, 0xC936u, 0xCC78u, 0xCDBAu, 0xCFFCu, 0xCE3Eu,
    0x9180u, 0x9042u, 0x9204u, 0x93C6u, 0x9688u, 0x974Au, 0x950Cu, 0x94CEu, 0x9F90u, 0x9E52u, 0x9C14u, 0x9DD6u, 0x9898u, 0x995Au, 0x9B1Cu, 0x9ADEu,
    0x8DA0u, 0x8C62u, 0x8E24u, 0x8FE6u, 0x8AA8u, 0x8B6Au, 0x892Cu, 0x88EEu, 0x83B0u, 0x8272u, 0x8034u, 0x81F6u, 0x84B8u, 0x857Au, 0x873Cu, 0x86FEu,
    0xA9C0u, 0xA802u, 0xAA44u, 0xAB86u, 0xAEC8u, 0xAF0Au, 0xAD4Cu, 0xAC8Eu, 0xA7D0u, 0xA612u, 0xA454u, 0xA596u, 0xA0D8u, 0xA11Au, 0xA35Cu, 0xA29Eu,
    0xB5E0u, 0xB422u, 0xB664u, 0xB7A6u, 0xB2E8u, 0xB32Au, 0xB16Cu, 0xB0AEu, 0xBBF0u, 0xBA32u, 0xB874u, 0xB9B6u, 0xBCF8u, 0xBD3Au, 0xBF7Cu, 0xBEBEu,
};

/*****************************************************************************
 * Local function prototypes
 ****************************************************************************/

void uint128_struct_from_bytes(uint128_struct_t * p_dst, const uint8_t p_src[AES_BLOCK_SIZE]);
void uint128_struct_to_bytes(uint8_t p_dst[AES_BLOCK_SIZE], const uint128_struct_t * p_src);
void uint128_struct_xor(uint128_struct_t * p_dst, const uint128_struct_t * p_src);
void uint128_struct_mul2(uint128_struct_t * p);
void block_mul256(uint8_t p_block[AES_BLOCK_SIZE]);

/*****************************************************************************
 * Functions
 ****************************************************************************/

/*
 * Galois 128-bit multiply for GCM mode of encryption.
 *
 * This implementation uses a bit-by-bit calculation of the multiplication.
 * It is the slowest implementation, but requires minimal memory.
 */
void gcm_mul(uint8_t p_block[AES_BLOCK_SIZE], const uint8_t p_key[AES_BLOCK_SIZE])
{
    uint128_struct_t    a;
    uint128_struct_t    result = { 0 };
    uint_fast8_t        i = AES_BLOCK_SIZE - 1u;
    uint8_t             j_bit = 1u;

    uint128_struct_from_bytes(&a, p_key);

    /* Skip initial uint128_struct_mul2(&result) which is unnecessary when
     * result is initially zero. */
    goto start;

    for (;;)
    {
        for (j_bit = 1u; j_bit != 0; j_bit <<= 1u)
        {
            uint128_struct_mul2(&result);
start:
            if (p_block[i] & j_bit)
            {
                uint128_struct_xor(&result, &a);
            }
        }
        if (i == 0)
        {
            break;
        }
        i--;
    }

    uint128_struct_to_bytes(p_block, &result);
}

/*
 * Given a key, pre-calculate the large table that is needed for
 * gcm_mul_table(), the 8-bit table-driven implementation of GCM multiplication.
 */
void gcm_mul_prepare_table(gcm_mul_table_t * p_table, const uint8_t p_key[AES_BLOCK_SIZE])
{
    uint8_t             i_bit = 1u;
    uint_fast8_t        j;
    uint8_t             block[AES_BLOCK_SIZE];

    memset(p_table, 0, sizeof(*p_table));

    for (i_bit = 0x80u; i_bit != 0; i_bit >>= 1u)
    {
        memset(&block[1], 0u, sizeof(block) - 1u);
        block[0] = i_bit;
        gcm_mul(block, p_key);
        for (j = 255; j != 0; j--)
        {
            if (j & i_bit)
            {
                aes_block_xor(p_table->key_data[j - 1u], block);
            }
        }
    }
}

/*
 * Galois 128-bit multiply for GCM mode of encryption.
 *
 * This implementation uses an 8-bit table look-up.
 * It is the fastest implementation, but requires a large table pre-calculated
 * from the key.
 */
void gcm_mul_table(uint8_t p_block[AES_BLOCK_SIZE], const gcm_mul_table_t * p_table)
{
    uint128_struct_t    a;
    uint8_t             block_byte;
    uint8_t             result[AES_BLOCK_SIZE] = { 0 };
    uint_fast8_t        i = AES_BLOCK_SIZE - 1u;

    /* Skip initial block_mul256(result) which is unnecessary when
     * result is initially zero. */
    goto start;

    for (;;)
    {
        block_mul256(result);
start:
        block_byte = p_block[i];
        if (block_byte)
        {
            aes_block_xor(result, p_table->key_data[block_byte - 1u]);
        }
        if (i == 0)
        {
            break;
        }
        i--;
    }
    memcpy(p_block, result, AES_BLOCK_SIZE);
}

/*
 * Given a key, pre-calculate the medium-sized table that is needed for
 * gcm_mul_table4(), the 4-bit table-driven implementation of GCM multiplication.
 */
void gcm_mul_prepare_table4(gcm_mul_table4_t * p_table, const uint8_t p_key[AES_BLOCK_SIZE])
{
    uint8_t             i_bit = 1u;
    uint_fast8_t        j;
    uint8_t             block[AES_BLOCK_SIZE];

    memset(p_table, 0, sizeof(*p_table));

    for (i_bit = 0x80u; i_bit != 0; i_bit >>= 1u)
    {
        memset(&block[1], 0u, sizeof(block) - 1u);
        block[0] = i_bit;
        gcm_mul(block, p_key);
        if (i_bit >= 0x10u)
        {
            for (j = 15; j != 0; j--)
            {
                if ((j << 4u) & i_bit)
                {
                    aes_block_xor(p_table->key_data_hi[j - 1u], block);
                }
            }
        }
        else
        {
            for (j = 15; j != 0; j--)
            {
                if (j & i_bit)
                {
                    aes_block_xor(p_table->key_data_lo[j - 1u], block);
                }
            }
        }
    }
}

/*
 * Galois 128-bit multiply for GCM mode of encryption.
 *
 * This implementation uses an 4-bit table look-up.
 * This implementation is faster than the bit-by-bit implementation, but has
 * more modest memory requirements for the table pre-calculated from the key,
 * compared to the 8-bit table look-up of gcm_mul_table().
 */
void gcm_mul_table4(uint8_t p_block[AES_BLOCK_SIZE], const gcm_mul_table4_t * p_table)
{
    uint128_struct_t    a;
    uint8_t             block_byte;
    uint8_t             block_nibble;
    uint8_t             result[AES_BLOCK_SIZE] = { 0 };
    uint_fast8_t        i = AES_BLOCK_SIZE - 1u;

    /* Skip initial block_mul256(result) which is unnecessary when
     * result is initially zero. */
    goto start;

    for (;;)
    {
        block_mul256(result);
start:
        block_byte = p_block[i];
        /* High nibble */
        block_nibble = (block_byte >> 4u) & 0xFu;
        if (block_nibble)
        {
            aes_block_xor(result, p_table->key_data_hi[block_nibble - 1u]);
        }
        /* Low nibble */
        block_nibble = block_byte & 0xFu;
        if (block_nibble)
        {
            aes_block_xor(result, p_table->key_data_lo[block_nibble - 1u]);
        }
        if (i == 0)
        {
            break;
        }
        i--;
    }
    memcpy(p_block, result, AES_BLOCK_SIZE);
}

/*****************************************************************************
 * Local functions
 ****************************************************************************/

/*
 * Convert a multiplicand for GCM Galois 128-bit multiply into a form that can
 * be more efficiently manipulated for bit-by-bit calculation of the multiply.
 */
void uint128_struct_from_bytes(uint128_struct_t * p_dst, const uint8_t p_src[AES_BLOCK_SIZE])
{
    uint_fast8_t        i;
    uint_fast8_t        j;
    const uint8_t *     p_src_tmp;
    uint128_element_t   temp;

    p_src_tmp = p_src;
    for (i = 0; i < UINT128_NUM_ELEMENTS; i++)
    {
        temp = 0;
        for (j = 0; j < UINT128_ELEMENT_SIZE; j++)
        {
            temp = (temp << 8) | *p_src_tmp++;
        }
        p_dst->element[i] = temp;
    }
}

/*
 * Convert the GCM Galois 128-bit multiply special form back into an ordinary
 * string of bytes.
 */
void uint128_struct_to_bytes(uint8_t p_dst[AES_BLOCK_SIZE], const uint128_struct_t * p_src)
{
    uint_fast8_t        i;
    uint_fast8_t        j;
    uint8_t *           p_dst_tmp;
    uint128_element_t   temp;

    p_dst_tmp = p_dst;
    for (i = 0; i < UINT128_NUM_ELEMENTS; i++)
    {
        temp = p_src->element[i];
        for (j = 0; j < UINT128_ELEMENT_SIZE; j++)
        {
            *p_dst_tmp++ = (temp >> (UINT128_ELEMENT_SIZE_BITS - 8u));
            temp <<= 8;
        }
    }
}

/*
 * XOR for uint128_struct_t.
 *
 * In-place XOR all the bits of p_src into p_dst.
 */
void uint128_struct_xor(uint128_struct_t * p_dst, const uint128_struct_t * p_src)
{
    uint_fast8_t        i;

    for (i = 0; i < UINT128_NUM_ELEMENTS; i++)
    {
        p_dst->element[i] ^= p_src->element[i];
    }
}

/*
 * Galois 128-bit multiply by 2.
 *
 * Multiply is done in-place on the uint128_struct_t operand.
 */
void uint128_struct_mul2(uint128_struct_t * p)
{
    uint_fast8_t        i;
    uint128_element_t   temp;
    uint128_element_t   carry;
    uint128_element_t   next_carry;

    if (p->element[UINT128_NUM_ELEMENTS - 1u] & 1u)
    {
        carry = (0xE1u << (UINT128_ELEMENT_SIZE_BITS - 8u));
    }
    else
    {
        carry = 0u;
    }

    for (i = 0; i < UINT128_NUM_ELEMENTS; i++)
    {
        next_carry = ((p->element[i] & 1u) << (UINT128_ELEMENT_SIZE_BITS - 1u));
        p->element[i] = (p->element[i] >> 1u) ^ carry;
        carry = next_carry;
    }
}

/*
 * Galois 128-bit multiply by 2^8.
 *
 * Multiply is done in-place on the byte array of standard AES block size.
 */
void block_mul256(uint8_t p_block[AES_BLOCK_SIZE])
{
    uint_fast8_t        i;
    uint16_t            reduce;

    reduce = mul256_reduce_table[p_block[AES_BLOCK_SIZE - 1u]];
    for (i = AES_BLOCK_SIZE - 1u; i != 0; i--)
    {
        p_block[i] = p_block[i - 1u];
    }
    p_block[0] = reduce >> 8u;
    p_block[1] ^= reduce;
}
