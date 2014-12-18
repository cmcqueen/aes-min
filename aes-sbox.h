
#ifndef AES_SBOX_H
#define AES_SBOX_H

#include "aes.h"

#include <stdint.h>

uint8_t aes_sbox(uint8_t a);
void aes_sbox_apply_block(uint8_t p_block[AES_BLOCK_SIZE]);


#endif /* !defined(AES_SBOX_H) */

