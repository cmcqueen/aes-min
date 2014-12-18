/* aes-rotate.h
 */
#ifndef AES_ROTATE_H
#define AES_ROTATE_H

#include <stdint.h>

static inline uint8_t aes_rotate_left_uint8(uint8_t a, uint_fast8_t num_bits)
{
    return (a << num_bits) | (a >> (8u - num_bits));
}

#endif /* !defined(AES_MUL2_H) */

