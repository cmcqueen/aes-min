/*****************************************************************************
 * gcm.h
 *
 * Functions to support GCM mode.
 ****************************************************************************/

#ifndef GCM_H
#define GCM_H

/*****************************************************************************
 * Includes
 ****************************************************************************/

#include "aes.h"

/*****************************************************************************
 * Types
 ****************************************************************************/

typedef struct
{
    uint8_t             key_data[255][AES_BLOCK_SIZE];
} gcm_mul_table_t;

typedef struct
{
    uint8_t             key_data_hi[15][AES_BLOCK_SIZE];
    uint8_t             key_data_lo[15][AES_BLOCK_SIZE];
} gcm_mul_table4_t;

/*****************************************************************************
 * Functions
 ****************************************************************************/

void gcm_mul(uint8_t p_block[AES_BLOCK_SIZE], const uint8_t p_key[AES_BLOCK_SIZE]);

void gcm_mul_prepare_table(gcm_mul_table_t * p_table, const uint8_t p_key[AES_BLOCK_SIZE]);
void gcm_mul_table(uint8_t p_block[AES_BLOCK_SIZE], const gcm_mul_table_t * p_table);

void gcm_mul_prepare_table4(gcm_mul_table4_t * p_table, const uint8_t p_key[AES_BLOCK_SIZE]);
void gcm_mul_table4(uint8_t p_block[AES_BLOCK_SIZE], const gcm_mul_table4_t * p_table);

#endif /* !defined(GCM_H) */
