
#ifndef AES_MIX_COLUMNS_H
#define AES_MIX_COLUMNS_H

#include <stdint.h>

void aes_mix_columns(uint8_t p_block[AES_BLOCK_SIZE]);
void aes_mix_columns_inv(uint8_t p_block[AES_BLOCK_SIZE]);

#endif /* !defined(AES_MIX_COLUMNS_H) */

