/*****************************************************************************
 * gcm-mul.c
 *
 * Functions to support GCM mode.
 ****************************************************************************/

/*****************************************************************************
 * Includes
 ****************************************************************************/

#include "gcm-mul.h"

#include <string.h>

/*****************************************************************************
 * Defines
 ****************************************************************************/

#define GCM_U128_ELEMENT_SIZE_BITS  (8u * GCM_U128_ELEMENT_SIZE)

#define GCM_U128_STRUCT_INIT_0      { { 0 } }

/*****************************************************************************
 * Local function prototypes
 ****************************************************************************/

static void gcm_u128_struct_from_bytes(gcm_u128_struct_t * restrict p_dst, const uint8_t p_src[AES_BLOCK_SIZE]);
static void gcm_u128_struct_to_bytes(uint8_t p_dst[AES_BLOCK_SIZE], const gcm_u128_struct_t * p_src);
static void uint128_struct_mul2(gcm_u128_struct_t * restrict p);
static void block_mul256(gcm_u128_struct_t * restrict p);

/*****************************************************************************
 * Local inline functions
 ****************************************************************************/

/*
 * XOR for gcm_u128_struct_t.
 *
 * In-place XOR all the bits of p_src into p_dst.
 */
static inline void uint128_struct_xor(gcm_u128_struct_t * p_dst, const gcm_u128_struct_t * p_src)
{
    uint_fast8_t        i;

    for (i = 0; i < GCM_U128_NUM_ELEMENTS; i++)
    {
        p_dst->element[i] ^= p_src->element[i];
    }
}

/*****************************************************************************
 * Functions
 ****************************************************************************/

#ifdef GCM_MUL_BIT_BY_BIT

/*
 * Galois 128-bit multiply for GCM mode of encryption.
 *
 * This implementation uses a bit-by-bit calculation of the multiplication.
 * It is the slowest implementation, but requires minimal memory.
 */
void gcm_mul(uint8_t p_block[AES_BLOCK_SIZE], const uint8_t p_key[AES_BLOCK_SIZE])
{
    gcm_u128_struct_t   a;
    gcm_u128_struct_t   result = GCM_U128_STRUCT_INIT_0;
    uint_fast8_t        i = AES_BLOCK_SIZE - 1u;
    uint8_t             j_bit = 1u;

    gcm_u128_struct_from_bytes(&a, p_key);

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

    gcm_u128_struct_to_bytes(p_block, &result);
}

#endif // defined(GCM_MUL_BIT_BY_BIT)


#ifdef GCM_MUL_TABLE_8

/*
 * Given a key, pre-calculate the large table that is needed for
 * gcm_mul_table(), the 8-bit table-driven implementation of GCM multiplication.
 */
void gcm_mul_prepare_table8(gcm_mul_table8_t * restrict p_table, const uint8_t p_key[AES_BLOCK_SIZE])
{
    gcm_u128_struct_t   a;
    gcm_u128_struct_t   block;
    uint_fast8_t        i_bit = 0x80u;
    uint_fast8_t        j;

    memset(p_table, 0u, sizeof(*p_table));
    gcm_u128_struct_from_bytes(&a, p_key);
    memcpy(block.bytes, p_key, AES_BLOCK_SIZE);

    for (;;)
    {
        for (j = 255u; j != 0u; j--)
        {
            if (j & i_bit)
            {
                uint128_struct_xor(&p_table->key_data[j - 1u], &block);
            }
        }
        i_bit >>= 1u;
        if (i_bit == 0u)
            break;
        uint128_struct_mul2(&a);
        gcm_u128_struct_to_bytes(block.bytes, &a);
    }
}

/*
 * Galois 128-bit multiply for GCM mode of encryption.
 *
 * This implementation uses an 8-bit table look-up.
 * It is the fastest implementation, but requires a large table pre-calculated
 * from the key.
 */
void gcm_mul_table8(uint8_t p_block[AES_BLOCK_SIZE], const gcm_mul_table8_t * p_table)
{
    uint8_t             block_byte;
    gcm_u128_struct_t   result = GCM_U128_STRUCT_INIT_0;
    uint_fast8_t        i = AES_BLOCK_SIZE - 1u;

    /* Skip initial block_mul256(&result) which is unnecessary when
     * result is initially zero. */
    goto start;

    for (;;)
    {
        block_mul256(&result);
start:
        block_byte = p_block[i];
        if (block_byte)
        {
            uint128_struct_xor(&result, &p_table->key_data[block_byte - 1u]);
        }
        if (i == 0u)
        {
            break;
        }
        i--;
    }
    memcpy(p_block, result.bytes, AES_BLOCK_SIZE);
}

#endif // defined(GCM_MUL_TABLE_8)


#ifdef GCM_MUL_TABLE_4

/*
 * Given a key, pre-calculate the medium-sized table that is needed for
 * gcm_mul_table4(), the 4-bit table-driven implementation of GCM multiplication.
 */
void gcm_mul_prepare_table4(gcm_mul_table4_t * restrict p_table, const uint8_t p_key[AES_BLOCK_SIZE])
{
    gcm_u128_struct_t   a;
    gcm_u128_struct_t   block;
    uint_fast8_t        i_bit = 0x80u;
    uint_fast8_t        j;

    memset(p_table, 0u, sizeof(*p_table));
    gcm_u128_struct_from_bytes(&a, p_key);
    memcpy(block.bytes, p_key, AES_BLOCK_SIZE);

    for (;;)
    {
        if (i_bit >= 0x10u)
        {
            for (j = 15u; j != 0u; j--)
            {
                if (j & (i_bit >> 4u))
                {
                    uint128_struct_xor(&p_table->key_data_hi[j - 1u], &block);
                }
            }
        }
        else
        {
            for (j = 15u; j != 0u; j--)
            {
                if (j & i_bit)
                {
                    uint128_struct_xor(&p_table->key_data_lo[j - 1u], &block);
                }
            }
        }

        i_bit >>= 1u;
        if (i_bit == 0u)
            break;
        uint128_struct_mul2(&a);
        gcm_u128_struct_to_bytes(block.bytes, &a);
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
    uint8_t             block_byte;
    uint8_t             block_nibble;
    gcm_u128_struct_t   result = GCM_U128_STRUCT_INIT_0;
    uint_fast8_t        i = AES_BLOCK_SIZE - 1u;

    /* Skip initial block_mul256(&result) which is unnecessary when
     * result is initially zero. */
    goto start;

    for (;;)
    {
        block_mul256(&result);
start:
        block_byte = p_block[i];
        /* High nibble */
        block_nibble = (block_byte >> 4u) & 0xFu;
        if (block_nibble)
        {
            uint128_struct_xor(&result, &p_table->key_data_hi[block_nibble - 1u]);
        }
        /* Low nibble */
        block_nibble = block_byte & 0xFu;
        if (block_nibble)
        {
            uint128_struct_xor(&result, &p_table->key_data_lo[block_nibble - 1u]);
        }
        if (i == 0u)
        {
            break;
        }
        i--;
    }
    memcpy(p_block, result.bytes, AES_BLOCK_SIZE);
}

#endif // defined(GCM_MUL_TABLE_4)


/*****************************************************************************
 * Local functions
 ****************************************************************************/

/*
 * Convert a multiplicand for GCM Galois 128-bit multiply into a form that can
 * be more efficiently manipulated for bit-by-bit calculation of the multiply.
 */
static void gcm_u128_struct_from_bytes(gcm_u128_struct_t * restrict p_dst, const uint8_t p_src[AES_BLOCK_SIZE])
{
    uint_fast8_t        i;
    uint_fast8_t        j;
    const uint8_t *     p_src_tmp;
    gcm_u128_element_t  temp;

    p_src_tmp = p_src;
    for (i = 0; i < GCM_U128_NUM_ELEMENTS; i++)
    {
        temp = 0;
        for (j = 0; j < GCM_U128_ELEMENT_SIZE; j++)
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
static void gcm_u128_struct_to_bytes(uint8_t p_dst[AES_BLOCK_SIZE], const gcm_u128_struct_t * p_src)
{
    uint_fast8_t        i;
    uint_fast8_t        j;
    uint8_t *           p_dst_tmp;
    gcm_u128_element_t  temp;

    p_dst_tmp = p_dst;
    for (i = 0; i < GCM_U128_NUM_ELEMENTS; i++)
    {
        temp = p_src->element[i];
        for (j = 0; j < GCM_U128_ELEMENT_SIZE; j++)
        {
            *p_dst_tmp++ = (temp >> (GCM_U128_ELEMENT_SIZE_BITS - 8u));
            temp <<= 8;
        }
    }
}

/*
 * Galois 128-bit multiply by 2.
 *
 * Multiply is done in-place on the gcm_u128_struct_t operand.
 */
static void uint128_struct_mul2(gcm_u128_struct_t * restrict p)
{
    uint_fast8_t        i = 0;
    gcm_u128_element_t  carry;
    gcm_u128_element_t  next_carry;

    /*
     * This expression is intended to be timing invariant to prevent a timing
     * attack due to execution timing dependent on the bits of the GHASH key.
     * Check generated assembler from the compiler to confirm it.
     * This could be expressed as an 'if' statement, but then it's less likely
     * to be timing invariant.
     *
     * (0xE1u << (GCM_U128_ELEMENT_SIZE_BITS - 8u)) is the reduction poly bits.
     * (p->element[GCM_U128_NUM_ELEMENTS - 1u] & 1u) is the check of the MSbit
     * to determine if it's necessary to XOR the reduction poly.
     * (-(p->element[GCM_U128_NUM_ELEMENTS - 1u] & 1u)) turns it into a mask for
     * the bitwise AND.
     */
    carry = ((gcm_u128_element_t)0xE1u << (GCM_U128_ELEMENT_SIZE_BITS - 8u)) & (-(p->element[GCM_U128_NUM_ELEMENTS - 1u] & 1u));

    goto start;
    for (i = 0; i < GCM_U128_NUM_ELEMENTS - 1u; i++)
    {
        carry = next_carry;
start:
        next_carry = ((p->element[i] & 1u) << (GCM_U128_ELEMENT_SIZE_BITS - 1u));
        p->element[i] = (p->element[i] >> 1u) ^ carry;
    }
    p->element[i] = (p->element[i] >> 1u) ^ next_carry;
}

#if defined(GCM_MUL_LITTLE_ENDIAN) && GCM_U128_ELEMENT_SIZE != 1

/*
 * Galois 128-bit multiply by 2^8.
 *
 * Multiply is done in-place on the byte array of standard AES block size.
 *
 * Little-endian specific implementation.
 * This implementation requires gcm_u128_element_t to be at least a 16-bit
 * integer. I.e. it doesn't work with uint8_t.
 */
static void block_mul256(gcm_u128_struct_t * restrict p)
{
    static const uint16_t reduce_table[] =
    {
        0x0000u, 0xC201u, 0x8403u, 0x4602u, 0x0807u, 0xCA06u, 0x8C04u, 0x4E05u, 0x100Eu, 0xD20Fu, 0x940Du, 0x560Cu, 0x1809u, 0xDA08u, 0x9C0Au, 0x5E0Bu,
        0x201Cu, 0xE21Du, 0xA41Fu, 0x661Eu, 0x281Bu, 0xEA1Au, 0xAC18u, 0x6E19u, 0x3012u, 0xF213u, 0xB411u, 0x7610u, 0x3815u, 0xFA14u, 0xBC16u, 0x7E17u,
        0x4038u, 0x8239u, 0xC43Bu, 0x063Au, 0x483Fu, 0x8A3Eu, 0xCC3Cu, 0x0E3Du, 0x5036u, 0x9237u, 0xD435u, 0x1634u, 0x5831u, 0x9A30u, 0xDC32u, 0x1E33u,
        0x6024u, 0xA225u, 0xE427u, 0x2626u, 0x6823u, 0xAA22u, 0xEC20u, 0x2E21u, 0x702Au, 0xB22Bu, 0xF429u, 0x3628u, 0x782Du, 0xBA2Cu, 0xFC2Eu, 0x3E2Fu,
        0x8070u, 0x4271u, 0x0473u, 0xC672u, 0x8877u, 0x4A76u, 0x0C74u, 0xCE75u, 0x907Eu, 0x527Fu, 0x147Du, 0xD67Cu, 0x9879u, 0x5A78u, 0x1C7Au, 0xDE7Bu,
        0xA06Cu, 0x626Du, 0x246Fu, 0xE66Eu, 0xA86Bu, 0x6A6Au, 0x2C68u, 0xEE69u, 0xB062u, 0x7263u, 0x3461u, 0xF660u, 0xB865u, 0x7A64u, 0x3C66u, 0xFE67u,
        0xC048u, 0x0249u, 0x444Bu, 0x864Au, 0xC84Fu, 0x0A4Eu, 0x4C4Cu, 0x8E4Du, 0xD046u, 0x1247u, 0x5445u, 0x9644u, 0xD841u, 0x1A40u, 0x5C42u, 0x9E43u,
        0xE054u, 0x2255u, 0x6457u, 0xA656u, 0xE853u, 0x2A52u, 0x6C50u, 0xAE51u, 0xF05Au, 0x325Bu, 0x7459u, 0xB658u, 0xF85Du, 0x3A5Cu, 0x7C5Eu, 0xBE5Fu,
        0x00E1u, 0xC2E0u, 0x84E2u, 0x46E3u, 0x08E6u, 0xCAE7u, 0x8CE5u, 0x4EE4u, 0x10EFu, 0xD2EEu, 0x94ECu, 0x56EDu, 0x18E8u, 0xDAE9u, 0x9CEBu, 0x5EEAu,
        0x20FDu, 0xE2FCu, 0xA4FEu, 0x66FFu, 0x28FAu, 0xEAFBu, 0xACF9u, 0x6EF8u, 0x30F3u, 0xF2F2u, 0xB4F0u, 0x76F1u, 0x38F4u, 0xFAF5u, 0xBCF7u, 0x7EF6u,
        0x40D9u, 0x82D8u, 0xC4DAu, 0x06DBu, 0x48DEu, 0x8ADFu, 0xCCDDu, 0x0EDCu, 0x50D7u, 0x92D6u, 0xD4D4u, 0x16D5u, 0x58D0u, 0x9AD1u, 0xDCD3u, 0x1ED2u,
        0x60C5u, 0xA2C4u, 0xE4C6u, 0x26C7u, 0x68C2u, 0xAAC3u, 0xECC1u, 0x2EC0u, 0x70CBu, 0xB2CAu, 0xF4C8u, 0x36C9u, 0x78CCu, 0xBACDu, 0xFCCFu, 0x3ECEu,
        0x8091u, 0x4290u, 0x0492u, 0xC693u, 0x8896u, 0x4A97u, 0x0C95u, 0xCE94u, 0x909Fu, 0x529Eu, 0x149Cu, 0xD69Du, 0x9898u, 0x5A99u, 0x1C9Bu, 0xDE9Au,
        0xA08Du, 0x628Cu, 0x248Eu, 0xE68Fu, 0xA88Au, 0x6A8Bu, 0x2C89u, 0xEE88u, 0xB083u, 0x7282u, 0x3480u, 0xF681u, 0xB884u, 0x7A85u, 0x3C87u, 0xFE86u,
        0xC0A9u, 0x02A8u, 0x44AAu, 0x86ABu, 0xC8AEu, 0x0AAFu, 0x4CADu, 0x8EACu, 0xD0A7u, 0x12A6u, 0x54A4u, 0x96A5u, 0xD8A0u, 0x1AA1u, 0x5CA3u, 0x9EA2u,
        0xE0B5u, 0x22B4u, 0x64B6u, 0xA6B7u, 0xE8B2u, 0x2AB3u, 0x6CB1u, 0xAEB0u, 0xF0BBu, 0x32BAu, 0x74B8u, 0xB6B9u, 0xF8BCu, 0x3ABDu, 0x7CBFu, 0xBEBEu,
    };
    uint_fast8_t        i = 0;
    gcm_u128_element_t  carry;
    gcm_u128_element_t  next_carry;

    carry = reduce_table[p->bytes[AES_BLOCK_SIZE - 1u]];

    goto start;
    for (; i < GCM_U128_NUM_ELEMENTS - 1u; i++)
    {
        carry = next_carry;
start:
        next_carry = p->element[i] >> (GCM_U128_ELEMENT_SIZE_BITS - 8u);
        p->element[i] = (p->element[i] << 8u) ^ carry;
    }
    p->element[i] = (p->element[i] << 8u) ^ next_carry;
}

#else // !defined(GCM_MUL_LITTLE_ENDIAN)

/*
 * Galois 128-bit multiply by 2^8.
 *
 * Multiply is done in-place on the byte array of standard AES block size.
 *
 * Generic implementation that should work for either big- or little-endian,
 * albeit not necessarily as fast.
 */
static void block_mul256(gcm_u128_struct_t * restrict p)
{
    static const uint16_t reduce_table[] =
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
#if 0
    uint_fast8_t        i;
#endif
    uint_fast16_t       reduce;

    reduce = reduce_table[p->bytes[AES_BLOCK_SIZE - 1u]];
#if 0
    for (i = AES_BLOCK_SIZE - 1u; i != 0; i--)
    {
        p->bytes[i] = p->bytes[i - 1u];
    }
#else
    memmove(p->bytes + 1, p->bytes, AES_BLOCK_SIZE - 1u);
#endif
    p->bytes[0] = reduce >> 8;
    p->bytes[1] ^= reduce;
}

#endif // !defined(GCM_MUL_LITTLE_ENDIAN)
