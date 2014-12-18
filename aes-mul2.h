/* aes-mul2.h
 *
 * aes_mul() multiplies by 2 in Galois field GF(2^8) with reduction
 * polynomial 0x11B.
 *
 * Several implementations are available. Depending on the architecture, one
 * might be preferable in terms of
 *     - Speed.
 *     - Lack of timing variability. That is, to prevent timing attacks, the
 *       execution speed ideally should be the same regardless of whether the
 *       most-significant bit is set or clear (which determines whether the
 *       reduction polynomial is XORed into the result). It is necessary to
 *       inspect the compiled code on the target platform to determine this.
 */
#ifndef AES_MUL2_H
#define AES_MUL2_H

#include <stdint.h>

#if 0

/* This is probably the most straight-forward expression of the algorithm.
 * This seems more likely to have variable timing, although inspection
 * of compiled code would be needed to confirm it.
 * It is more likely to have variable timing when no optimisations are
 * enabled. */
static inline uint8_t aes_mul2(uint8_t a)
{
    uint8_t result;

    result = a << 1u;
    if (a & 0x80)
        result ^= 0x1B;
    return result;
}

#elif 0

/* This hopefully has fixed timing, although inspection
 * of compiled code would be needed to confirm it. */
static inline uint8_t aes_mul2(uint8_t a)
{
    static const uint8_t reduce[2] = { 0, 0x1B };

    return (a << 1u) ^ reduce[a >= 0x80];
}

#else

/* This hopefully has fixed timing, although inspection
 * of compiled code would be needed to confirm it. */
static inline uint8_t aes_mul2(uint8_t a)
{
    return (a << 1u) ^ ((-(a >= 0x80)) & 0x1B);
}

#endif

#endif /* !defined(AES_MUL2_H) */

