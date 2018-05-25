
#include "gcm.h"
#include "aes-print-block.h"

#include <string.h>

/*****************************************************************************
 * Types
 ****************************************************************************/

typedef struct
{
    uint8_t a[AES_BLOCK_SIZE];
    uint8_t b[AES_BLOCK_SIZE];
    uint8_t result[AES_BLOCK_SIZE];
} test_vector_t;

/*****************************************************************************
 * Look-up tables
 ****************************************************************************/

static const test_vector_t test_vectors[] =
{
    {
        { 0x95u, 0x2Bu, 0x2Au, 0x56u, 0xA5u, 0x60u, 0x4Au, 0xC0u, 0xB3u, 0x2Bu, 0x66u, 0x56u, 0xA0u, 0x5Bu, 0x40u, 0xB6u, },
        { 0xDFu, 0xA6u, 0xBFu, 0x4Du, 0xEDu, 0x81u, 0xDBu, 0x03u, 0xFFu, 0xCAu, 0xFFu, 0x95u, 0xF8u, 0x30u, 0xF0u, 0x61u, },
        { 0xDAu, 0x53u, 0xEBu, 0x0Au, 0xD2u, 0xC5u, 0x5Bu, 0xB6u, 0x4Fu, 0xC4u, 0x80u, 0x2Cu, 0xC3u, 0xFEu, 0xDAu, 0x60u, },
    },
    {
        { 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, },
        { 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, },
        { 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, },
    },
    {
        { 0x80u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, },
        { 0x80u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, },
        { 0x80u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, },
    },
    {
        { 0x80u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, },
        { 0x40u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, },
        { 0x40u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, },
    },
    {
        { 0x80u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, },
        { 0x00u, 0x80u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, },
        { 0x00u, 0x80u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, },
    },
};

/*****************************************************************************
 * Local functions
 ****************************************************************************/

static int gcm_mul_test_one(const uint8_t a[AES_BLOCK_SIZE], const uint8_t b[AES_BLOCK_SIZE], const uint8_t correct_result[AES_BLOCK_SIZE])
{
    size_t  i;
    int     result;
    uint8_t gmul_out[AES_BLOCK_SIZE];

    memcpy(gmul_out, a, AES_BLOCK_SIZE);
    gcm_mul(gmul_out, b);

    result = memcmp(gmul_out, correct_result, AES_BLOCK_SIZE) ? 1 : 0;
    if (result)
    {
        printf("gcm_mul() a:\n");
        print_block_hex(a, 16u);

        printf("gcm_mul() b:\n");
        print_block_hex(b, 16u);

        printf("gcm_mul() expected:\n");
        print_block_hex(correct_result, 16u);

        printf("gcm_mul() result:\n");
        print_block_hex(gmul_out, 16u);
        return result;
    }
    return 0;
}

static int gcm_mul_test(void)
{
    size_t  i;
    int     result;
    uint8_t gmul_out[AES_BLOCK_SIZE];

    for (i = 0; i < (sizeof(test_vectors)/sizeof(test_vectors[0])); i++)
    {
        result = gcm_mul_test_one(test_vectors[i].a, test_vectors[i].b, test_vectors[i].result);
        if (result)
            return result;

        /* Swapped. */
        result = gcm_mul_test_one(test_vectors[i].b, test_vectors[i].a, test_vectors[i].result);
        if (result)
            return result;
    }
    return 0;
}

static int gcm_mul_table_test_one(const uint8_t a[AES_BLOCK_SIZE], const uint8_t b[AES_BLOCK_SIZE], const uint8_t correct_result[AES_BLOCK_SIZE])
{
    gcm_mul_table_t mul_table;
    size_t  j;
    int     result;
    uint8_t gmul_out[AES_BLOCK_SIZE];

    /* Prepare the table. */
    //printf("gcm_mul_prepare_table()\n");
    gcm_mul_prepare_table(&mul_table, b);

    /* Do the multiply. */
    memcpy(gmul_out, a, AES_BLOCK_SIZE);
    //printf("gcm_mul_table()\n");
    gcm_mul_table(gmul_out, &mul_table);

    result = memcmp(gmul_out, correct_result, AES_BLOCK_SIZE) ? 1 : 0;
    if (result)
    {
        printf("gcm_mul_prepare_table() result:\n");
        for (j = 0; j < 255; j++)
        {
            printf("%02zX: ", j + 1);
            print_block_hex(mul_table.key_data[j], 16u);
        }

        printf("gcm_mul_table() a:\n");
        print_block_hex(a, 16u);

        printf("gcm_mul_table() b:\n");
        print_block_hex(b, 16u);

        printf("gcm_mul_table() expected:\n");
        print_block_hex(correct_result, 16u);

        printf("gcm_mul_table() result:\n");
        print_block_hex(gmul_out, 16u);

        return result;
    }
    return 0;
}

static int gcm_mul_table_test(void)
{
    size_t  i;
    int     result;

    for (i = 0; i < (sizeof(test_vectors)/sizeof(test_vectors[0])); i++)
    {
        result = gcm_mul_table_test_one(test_vectors[i].a, test_vectors[i].b, test_vectors[i].result);
        if (result)
            return result;

        /* Swapped. */
        result = gcm_mul_table_test_one(test_vectors[i].b, test_vectors[i].a, test_vectors[i].result);
        if (result)
            return result;
    }
    return 0;
}

/*****************************************************************************
 * Functions
 ****************************************************************************/

int main(int argc, char **argv)
{
    int         result;

    (void)argc;
    (void)argv;

    result = gcm_mul_test();
    if (result)
        return result;

    result = gcm_mul_table_test();
    if (result)
        return result;

    return 0;
}

