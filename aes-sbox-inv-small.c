
#include "aes-sbox.h"
#include "aes-rotate.h"
#include "aes-inv.h"


uint8_t aes_sbox_inv(uint8_t a)
{
    uint8_t x;

    x = aes_rotate_left_uint8(a, 1u);
    a = aes_rotate_left_uint8(x, 2u);
    x ^= a;
    a = aes_rotate_left_uint8(a, 3u);
    
    return aes_inv(a ^ x ^ 0x05u);
}


void aes_sbox_inv_apply_block(uint8_t p_block[AES_BLOCK_SIZE])
{
    uint_fast8_t    i;

    for (i = 0; i < AES_BLOCK_SIZE; ++i)
    {
        p_block[i] = aes_sbox_inv(p_block[i]);
    }
}

