/*****************************************************************************
 * gcm-mul.h
 *
 * Functions to support GCM mode.
 ****************************************************************************/

#ifndef GCM_MUL_H
#define GCM_MUL_H

/*****************************************************************************
 * Includes
 ****************************************************************************/

#include "aes-min.h"

#include "gcm-mul-cfg.h"


/*****************************************************************************
 * Defines
 ****************************************************************************/

#ifndef GCM_U128_ELEMENT_SIZE
#define GCM_U128_ELEMENT_SIZE               4
#endif

#define GCM_U128_NUM_ELEMENTS               (AES_BLOCK_SIZE / GCM_U128_ELEMENT_SIZE)

/*****************************************************************************
 * Types
 ****************************************************************************/

#if GCM_U128_ELEMENT_SIZE == 1
typedef uint8_t gcm_u128_element_t;
#elif GCM_U128_ELEMENT_SIZE == 2
typedef uint16_t gcm_u128_element_t;
#elif GCM_U128_ELEMENT_SIZE == 4
typedef uint32_t gcm_u128_element_t;
#elif GCM_U128_ELEMENT_SIZE == 8
typedef uint64_t gcm_u128_element_t;
#else
#error Invalid GCM_U128_ELEMENT_SIZE
#endif

/*
 * This struct is basically to enable big-integer calculations in the 128-bit
 * Galois field. The struct is fixed size for this purpose. The functions that
 * operate on it are specialised to do the bit-reversed operations needed
 * specifically for the Galois 128-bit multiply used in the GCM algorithm.
 */
typedef union
{
    gcm_u128_element_t  element[GCM_U128_NUM_ELEMENTS];
    uint16_t            reduce_bytes;
    uint8_t             bytes[AES_BLOCK_SIZE];
} gcm_u128_struct_t;

typedef struct
{
    gcm_u128_struct_t   key_data[255];
} gcm_mul_table8_t;

typedef struct
{
    gcm_u128_struct_t   key_data_hi[15];
    gcm_u128_struct_t   key_data_lo[15];
} gcm_mul_table4_t;

/*****************************************************************************
 * Functions
 ****************************************************************************/

#ifdef GCM_MUL_BIT_BY_BIT

void gcm_mul(uint8_t p_block[AES_BLOCK_SIZE], const uint8_t p_key[AES_BLOCK_SIZE]);

#endif


#ifdef GCM_MUL_TABLE_8

void gcm_mul_prepare_table8(gcm_mul_table8_t * restrict p_table, const uint8_t p_key[AES_BLOCK_SIZE]);
void gcm_mul_table8(uint8_t p_block[AES_BLOCK_SIZE], const gcm_mul_table8_t * p_table);

#endif


#ifdef GCM_MUL_TABLE_4

void gcm_mul_prepare_table4(gcm_mul_table4_t * restrict p_table, const uint8_t p_key[AES_BLOCK_SIZE]);
void gcm_mul_table4(uint8_t p_block[AES_BLOCK_SIZE], const gcm_mul_table4_t * p_table);

#endif


#endif /* !defined(GCM_MUL_H) */
