
#ifndef AES_H
#define AES_H


#include <stdint.h>


#define AES_BLOCK_SIZE              16u
#define AES_COLUMN_SIZE             4u
#define AES_NUM_COLUMNS             4u

#define AES128_NUM_ROUNDS           99u // TODO: set this correctly
#define AES128_KEY_SIZE             16u
#define AES128_KEY_SCHEDULE_SIZE    (AES_BLOCK_SIZE * (AES128_NUM_ROUNDS + 1u))  // TODO: set this correctly


void aes128_encrypt(uint8_t p_block[AES_BLOCK_SIZE], const uint8_t p_key_schedule[AES128_KEY_SCHEDULE_SIZE]);
void aes128_decrypt(uint8_t p_block[AES_BLOCK_SIZE], const uint8_t p_key_schedule[AES128_KEY_SCHEDULE_SIZE]);

void aes128_key_schedule(uint8_t p_key_schedule[AES128_KEY_SCHEDULE_SIZE], const uint8_t p_key[AES128_KEY_SIZE]);


#endif /* !defined(AES_H) */

