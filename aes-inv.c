/* aes-inv.c
 *
 * aes_inv() calculates multiplicative inverse in Galois field GF(2^8) with
 * reduction polynomial 0x11B.
 */

#include "aes-inv.h"
#include "aes-mul.h"

#ifndef dimof
#define dimof(array)    (sizeof(array) / sizeof(array[0]))
#endif

#define PREV_VALUE_I_MIN    1u
#define PREV_VALUE_I_MAX    3u

uint8_t aes_inv(uint8_t a)
{
    static const uint8_t addition_chain_idx[] = { 0, 1, 1, 3, 4, 3, 6, 7, 3, 9, 1 };
    uint_fast8_t i;
    uint_fast8_t prev_value_i;
    uint8_t prev_values[PREV_VALUE_I_MAX - PREV_VALUE_I_MIN + 1u];
    uint8_t result = 0;
    
    for (i = 0; i < dimof(addition_chain_idx); i++)
    {
        prev_value_i = addition_chain_idx[i];
        a = aes_mul(a, (i == prev_value_i) ? a : prev_values[prev_value_i - PREV_VALUE_I_MIN]);
        if (PREV_VALUE_I_MIN - 1u <= i && i <= PREV_VALUE_I_MAX - 1u)
            prev_values[i + 1u - PREV_VALUE_I_MIN] = a;
    }
    return a;
}

