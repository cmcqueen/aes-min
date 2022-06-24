
#include "gcm-mul.h"
#include "aes-min.h"
#include "aes-print-block.h"

#include "gcm-test-vectors.h"

#include <string.h>

#include <endian.h>

/*****************************************************************************
 * Defines
 ****************************************************************************/

#define SIMPLE_IV_SIZE          12u

#define MAX(A, B)               ((A) >= (B) ? (A) : (B))
#define MIN(A, B)               ((A) <= (B) ? (A) : (B))

/*****************************************************************************
 * Types
 ****************************************************************************/

typedef enum
{
    TEST_GCM_MUL_BIT_BY_BIT,
    TEST_GCM_MUL_TABLE4,
    TEST_GCM_MUL_TABLE8,
} gcm_mul_implementation_t;

typedef struct
{
    uint8_t a[AES_BLOCK_SIZE];
    uint8_t b[AES_BLOCK_SIZE];
    uint8_t result[AES_BLOCK_SIZE];
} mul_test_vector_t;

typedef union
{
    uint8_t bytes[AES_BLOCK_SIZE];
    struct
    {
        uint8_t iv[SIMPLE_IV_SIZE];
        union
        {
            uint8_t ctr_bytes[4];
            uint32_t ctr;
        };
    };
} gcm_iv_t;

typedef union
{
    uint8_t bytes[AES_BLOCK_SIZE];
    struct
    {
        uint32_t padding1;
        uint32_t aad_len;
        uint32_t padding2;
        uint32_t pt_len;
    };
} ghash_lengths_t;

/*****************************************************************************
 * Look-up tables
 ****************************************************************************/

static const mul_test_vector_t mul_test_vectors[] =
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
    int     result;
    uint8_t gmul_out[AES_BLOCK_SIZE];

    memcpy(gmul_out, a, AES_BLOCK_SIZE);
    gcm_mul(gmul_out, b);

    result = memcmp(gmul_out, correct_result, AES_BLOCK_SIZE) ? 1 : 0;
    if (result)
    {
        printf("gcm_mul() a:\n");
        print_block_hex(a, AES_BLOCK_SIZE);

        printf("gcm_mul() b:\n");
        print_block_hex(b, AES_BLOCK_SIZE);

        printf("gcm_mul() expected:\n");
        print_block_hex(correct_result, AES_BLOCK_SIZE);

        printf("gcm_mul() result:\n");
        print_block_hex(gmul_out, AES_BLOCK_SIZE);
        return result;
    }
    return 0;
}

static int gcm_mul_test(void)
{
    size_t  i;
    int     result;

    for (i = 0; i < (sizeof(mul_test_vectors)/sizeof(mul_test_vectors[0])); i++)
    {
        result = gcm_mul_test_one(mul_test_vectors[i].a, mul_test_vectors[i].b, mul_test_vectors[i].result);
        if (result)
            return result;

        /* Swapped. */
        result = gcm_mul_test_one(mul_test_vectors[i].b, mul_test_vectors[i].a, mul_test_vectors[i].result);
        if (result)
            return result;
    }
    return 0;
}

static int gcm_mul_table8_test_one(const uint8_t a[AES_BLOCK_SIZE], const uint8_t b[AES_BLOCK_SIZE], const uint8_t correct_result[AES_BLOCK_SIZE])
{
    gcm_mul_table8_t mul_table;
    size_t  j;
    int     result;
    uint8_t gmul_out[AES_BLOCK_SIZE];

    /* Prepare the table. */
    //printf("gcm_mul_prepare_table8()\n");
    gcm_mul_prepare_table8(&mul_table, b);

    /* Do the multiply. */
    memcpy(gmul_out, a, AES_BLOCK_SIZE);
    //printf("gcm_mul_table8()\n");
    gcm_mul_table8(gmul_out, &mul_table);

    result = memcmp(gmul_out, correct_result, AES_BLOCK_SIZE) ? 1 : 0;
    if (result)
    {
        printf("gcm_mul_prepare_table8() result:\n");
        for (j = 0; j < 255; j++)
        {
            printf("%02zX: ", j + 1);
            print_block_hex(mul_table.key_data[j].bytes, AES_BLOCK_SIZE);
        }

        printf("gcm_mul_table8() a:\n");
        print_block_hex(a, AES_BLOCK_SIZE);

        printf("gcm_mul_table8() b:\n");
        print_block_hex(b, AES_BLOCK_SIZE);

        printf("gcm_mul_table8() expected:\n");
        print_block_hex(correct_result, AES_BLOCK_SIZE);

        printf("gcm_mul_table8() result:\n");
        print_block_hex(gmul_out, AES_BLOCK_SIZE);

        return result;
    }
    return 0;
}

static int gcm_mul_table8_test(void)
{
    size_t  i;
    int     result;

    for (i = 0; i < (sizeof(mul_test_vectors)/sizeof(mul_test_vectors[0])); i++)
    {
        result = gcm_mul_table8_test_one(mul_test_vectors[i].a, mul_test_vectors[i].b, mul_test_vectors[i].result);
        if (result)
            return result;

        /* Swapped. */
        result = gcm_mul_table8_test_one(mul_test_vectors[i].b, mul_test_vectors[i].a, mul_test_vectors[i].result);
        if (result)
            return result;
    }
    return 0;
}

static int gcm_mul_table4_test_one(const uint8_t a[AES_BLOCK_SIZE], const uint8_t b[AES_BLOCK_SIZE], const uint8_t correct_result[AES_BLOCK_SIZE])
{
    gcm_mul_table4_t mul_table;
    size_t  j;
    int     result;
    uint8_t gmul_out[AES_BLOCK_SIZE];

    /* Prepare the table. */
    //printf("gcm_mul_prepare_table4()\n");
    gcm_mul_prepare_table4(&mul_table, b);

    /* Do the multiply. */
    memcpy(gmul_out, a, AES_BLOCK_SIZE);
    //printf("gcm_mul_table4()\n");
    gcm_mul_table4(gmul_out, &mul_table);

    result = memcmp(gmul_out, correct_result, AES_BLOCK_SIZE) ? 1 : 0;
    if (result)
    {
        printf("gcm_mul_prepare_table4() result:\n");
        for (j = 0; j < 15; j++)
        {
            printf("Hi %02zX: ", j + 1);
            print_block_hex(mul_table.key_data_hi[j].bytes, AES_BLOCK_SIZE);
        }
        for (j = 0; j < 15; j++)
        {
            printf("Lo %02zX: ", j + 1);
            print_block_hex(mul_table.key_data_lo[j].bytes, AES_BLOCK_SIZE);
        }

        printf("gcm_mul_table4() a:\n");
        print_block_hex(a, AES_BLOCK_SIZE);

        printf("gcm_mul_table4() b:\n");
        print_block_hex(b, AES_BLOCK_SIZE);

        printf("gcm_mul_table4() expected:\n");
        print_block_hex(correct_result, AES_BLOCK_SIZE);

        printf("gcm_mul_table4() result:\n");
        print_block_hex(gmul_out, AES_BLOCK_SIZE);

        return result;
    }
    return 0;
}

static int gcm_mul_table4_test(void)
{
    size_t  i;
    int     result;

    for (i = 0; i < (sizeof(mul_test_vectors)/sizeof(mul_test_vectors[0])); i++)
    {
        result = gcm_mul_table4_test_one(mul_test_vectors[i].a, mul_test_vectors[i].b, mul_test_vectors[i].result);
        if (result)
            return result;

        /* Swapped. */
        result = gcm_mul_table4_test_one(mul_test_vectors[i].b, mul_test_vectors[i].a, mul_test_vectors[i].result);
        if (result)
            return result;
    }
    return 0;
}

static int gcm_test(gcm_mul_implementation_t mul_impl)
{
    size_t              i;
    size_t              data_len;
    int                 result;
    gcm_iv_t            iv_block;
    ghash_lengths_t     ghash_lengths;
    const uint8_t *     p_data;
    uint8_t             data_block[AES_BLOCK_SIZE];
    uint8_t             aes_key[AES_BLOCK_SIZE];
    uint8_t             aes_work[AES_BLOCK_SIZE];
    uint8_t             ghash_key[AES_BLOCK_SIZE];
    uint8_t             ghash_work[AES_BLOCK_SIZE];
    gcm_mul_table8_t    mul_table8;
    gcm_mul_table4_t    mul_table4;

    for (i = 0; i < GCM_NUM_VECTORS; i++)
    {
        /* Prepare working IV. */
        memcpy(iv_block.iv, gcm_test_vectors[i].p_iv, sizeof(iv_block.iv));
        iv_block.ctr = htobe32(1);

        /* Prepare GHASH calculation. */
        memset(ghash_work, 0, sizeof(ghash_work));
        memset(ghash_key, 0, sizeof(ghash_key));
        memcpy(aes_key, gcm_test_vectors[i].p_key, sizeof(aes_key));
        aes128_otfks_encrypt(ghash_key, aes_key);
        switch (mul_impl)
        {
            case TEST_GCM_MUL_BIT_BY_BIT:
                break;
            case TEST_GCM_MUL_TABLE4:
                gcm_mul_prepare_table4(&mul_table4, ghash_key);
                break;
            case TEST_GCM_MUL_TABLE8:
                gcm_mul_prepare_table8(&mul_table8, ghash_key);
                break;
        }

        /* Compute GHASH for any AAD (additional authenticated data). */
        if (gcm_test_vectors[i].p_aad)
        {
            p_data = gcm_test_vectors[i].p_aad;
            data_len = gcm_test_vectors[i].aad_len;
            while (data_len)
            {
                memcpy(data_block, p_data, MIN(data_len, sizeof(data_block)));
                if (data_len < sizeof(data_block))
                    memset(data_block + data_len, 0, sizeof(data_block) - data_len);

                aes_block_xor(ghash_work, data_block);
                switch (mul_impl)
                {
                    case TEST_GCM_MUL_BIT_BY_BIT:
                        gcm_mul(ghash_work, ghash_key);
                        break;
                    case TEST_GCM_MUL_TABLE4:
                        gcm_mul_table4(ghash_work, &mul_table4);
                        break;
                    case TEST_GCM_MUL_TABLE8:
                        gcm_mul_table8(ghash_work, &mul_table8);
                        break;
                }

                p_data   += MIN(data_len, sizeof(data_block));
                data_len -= MIN(data_len, sizeof(data_block));
            }
        }

        /* Compute GHASH for any plaintext. */
        if (gcm_test_vectors[i].p_pt)
        {
            p_data = gcm_test_vectors[i].p_pt;
            data_len = gcm_test_vectors[i].pt_len;
            while (data_len)
            {
                iv_block.ctr = htobe32(be32toh(iv_block.ctr) + 1);
                memcpy(aes_work, iv_block.bytes, sizeof(aes_work));
                memcpy(aes_key, gcm_test_vectors[i].p_key, sizeof(aes_key));
                aes128_otfks_encrypt(aes_work, aes_key);

                memcpy(data_block, p_data, MIN(data_len, sizeof(data_block)));
                aes_block_xor(data_block, aes_work);
                if (data_len < sizeof(data_block))
                    memset(data_block + data_len, 0, sizeof(data_block) - data_len);
                /* TODO: Verify ciphertext against that in the test vector. */

                aes_block_xor(ghash_work, data_block);
                switch (mul_impl)
                {
                    case TEST_GCM_MUL_BIT_BY_BIT:
                        gcm_mul(ghash_work, ghash_key);
                        break;
                    case TEST_GCM_MUL_TABLE4:
                        gcm_mul_table4(ghash_work, &mul_table4);
                        break;
                    case TEST_GCM_MUL_TABLE8:
                        gcm_mul_table8(ghash_work, &mul_table8);
                        break;
                }

                p_data   += MIN(data_len, sizeof(data_block));
                data_len -= MIN(data_len, sizeof(data_block));
            }
        }

        /* Final GHASH calculation.
         * Add block that indicates lengths of AAD and plaintext. */
        ghash_lengths.padding1 = 0;
        ghash_lengths.aad_len = htobe32(gcm_test_vectors[i].aad_len * 8u);
        ghash_lengths.padding2 = 0;
        ghash_lengths.pt_len = htobe32(gcm_test_vectors[i].pt_len * 8u);
        aes_block_xor(ghash_work, ghash_lengths.bytes);
        switch (mul_impl)
        {
            case TEST_GCM_MUL_BIT_BY_BIT:
                gcm_mul(ghash_work, ghash_key);
                break;
            case TEST_GCM_MUL_TABLE4:
                gcm_mul_table4(ghash_work, &mul_table4);
                break;
            case TEST_GCM_MUL_TABLE8:
                gcm_mul_table8(ghash_work, &mul_table8);
                break;
        }

        /* Final AES operation that is XORed with final GHASH value. */
        iv_block.ctr = htobe32(1);
        memcpy(aes_work, iv_block.bytes, sizeof(aes_work));
        memcpy(aes_key, gcm_test_vectors[i].p_key, sizeof(aes_key));
        aes128_otfks_encrypt(aes_work, aes_key);
        aes_block_xor(ghash_work, aes_work);
        /* ghash_work now contains calculated tag. */

        /* Verify tag. */
        result = memcmp(ghash_work, gcm_test_vectors[i].p_tag, gcm_test_vectors[i].tag_len) ? 1 : 0;
        if (result)
        {
            printf("Test vector %zu failed\n", i);

            printf("Tag result:\n");
            print_block_hex(ghash_work, gcm_test_vectors[i].tag_len);

            printf("Tag expected:\n");
            print_block_hex(gcm_test_vectors[i].p_tag, gcm_test_vectors[i].tag_len);
            return result;
        }
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

    result = gcm_mul_table8_test();
    if (result)
        return result;

    result = gcm_mul_table4_test();
    if (result)
        return result;

    result = gcm_test(TEST_GCM_MUL_BIT_BY_BIT);
    if (result)
        return result;
    result = gcm_test(TEST_GCM_MUL_TABLE4);
    if (result)
        return result;
    result = gcm_test(TEST_GCM_MUL_TABLE8);
    if (result)
        return result;

    return 0;
}

