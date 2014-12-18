/* aes-mul.c
 *
 * aes_mul() multiplies two numbers in Galois field GF(2^8) with reduction
 * polynomial 0x11B.
 */

#include "aes-mul.h"
#include "aes-mul2.h"

uint8_t aes_mul(uint8_t a, uint8_t b)
{
    uint8_t result = 0;
    uint8_t i;
    for (i = 0; i < 8; i++)
    {
#if 0
        if (b & 1)
        {
            result ^= a;
        }
#else
        result ^= (-((b & 1) != 0)) & a;
#endif
        a = aes_mul2(a);
        b >>= 1;
    }
    return result;
}

