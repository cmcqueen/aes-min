
#ifndef AES_KEY_SCHEDULE_ROUND_H
#define AES_KEY_SCHEDULE_ROUND_H

#include "aes.h"

void aes128_key_schedule_round(uint8_t p_key[AES128_KEY_SIZE], uint8_t rcon);

#endif /* !defined(AES_KEY_SCHEDULE_ROUND_H) */
