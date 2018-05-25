/*****************************************************************************
 * gcm.c
 *
 * Functions to support GCM mode.
 ****************************************************************************/

/*****************************************************************************
 * Includes
 ****************************************************************************/

#include "gcm.h"

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

typedef struct
{
    uint128_element_t   element[UINT128_NUM_ELEMENTS];
} uint128_struct_t;

/*****************************************************************************
 * Local function prototypes
 ****************************************************************************/

void uint128_struct_from_bytes(uint128_struct_t * p_dst, const uint8_t p_src[AES_BLOCK_SIZE]);
void uint128_struct_to_bytes(uint8_t p_dst[AES_BLOCK_SIZE], const uint128_struct_t * p_src);
void uint128_struct_xor(uint128_struct_t * p_dst, const uint128_struct_t * p_src);
void uint128_struct_mul2(uint128_struct_t * p);

/*****************************************************************************
 * Functions
 ****************************************************************************/

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

/*****************************************************************************
 * Local functions
 ****************************************************************************/

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

void uint128_struct_xor(uint128_struct_t * p_dst, const uint128_struct_t * p_src)
{
    uint_fast8_t        i;

    for (i = 0; i < UINT128_NUM_ELEMENTS; i++)
    {
        p_dst->element[i] ^= p_src->element[i];
    }
}

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