
#include "gcm.h"
#include "aes-print-block.h"

#include <string.h>


static const uint8_t gcm_a[AES_BLOCK_SIZE] =
{
    0x95u, 0x2Bu, 0x2Au, 0x56u, 0xA5u, 0x60u, 0x4Au, 0xC0u, 0xB3u, 0x2Bu, 0x66u, 0x56u, 0xA0u, 0x5Bu, 0x40u, 0xB6u,
};

static const uint8_t gcm_b[AES_BLOCK_SIZE] =
{
    0xDFu, 0xA6u, 0xBFu, 0x4Du, 0xEDu, 0x81u, 0xDBu, 0x03u, 0xFFu, 0xCAu, 0xFFu, 0x95u, 0xF8u, 0x30u, 0xF0u, 0x61u,
};

static const uint8_t gcm_result[AES_BLOCK_SIZE] =
{
    0xDAu, 0x53u, 0xEBu, 0x0Au, 0xD2u, 0xC5u, 0x5Bu, 0xB6u, 0x4Fu, 0xC4u, 0x80u, 0x2Cu, 0xC3u, 0xFEu, 0xDAu, 0x60u,
};


int main(int argc, char **argv)
{
    size_t  i;
    uint8_t gmul_out[AES_BLOCK_SIZE];

    (void)argc;
    (void)argv;

    memcpy(gmul_out, gcm_a, AES_BLOCK_SIZE);
    gcm_mul(gmul_out, gcm_b);

    printf("gcm_mul() result:\n");
    print_block_hex(gmul_out, 16u);

    return memcmp(gmul_out, gcm_result, AES_BLOCK_SIZE) ? 1 : 0;
}

