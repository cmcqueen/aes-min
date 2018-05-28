/*****************************************************************************
 * aes-block-xor.h
 ****************************************************************************/

#ifndef AES_BLOCK_XOR_H
#define AES_BLOCK_XOR_H

/*****************************************************************************
 * Includes
 ****************************************************************************/

#include "aes.h"

/*****************************************************************************
 * Inline functions
 ****************************************************************************/

/* XOR the specified round key into the AES block.
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

#endif /* !defined(AES_BLOCK_XOR_H) */
