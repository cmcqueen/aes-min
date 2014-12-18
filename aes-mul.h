/* aes-mul.h
 *
 * aes_mul() multiplies two numbers in Galois field GF(2^8) with reduction
 * polynomial 0x11B.
 */
#ifndef AES_MUL_H
#define AES_MUL_H

#include <stdint.h>

uint8_t aes_mul(uint8_t a, uint8_t b);

#endif /* !defined(AES_MUL_H) */
