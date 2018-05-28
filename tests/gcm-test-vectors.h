#ifndef GCM_TEST_VECTORS_H
#define GCM_TEST_VECTORS_H

/*****************************************************************************
 * Includes
 ****************************************************************************/

#include <stdint.h>
#include <stddef.h>

/*****************************************************************************
 * Defines
 ****************************************************************************/

#define GCM_NUM_VECTORS     2625u

/*****************************************************************************
 * Types
 ****************************************************************************/

typedef struct
{
    const uint8_t * p_key;

    /* Assume IV is always 96 bits. */
    const uint8_t * p_iv;

    size_t  aad_len;
    const uint8_t * p_aad;

    size_t  pt_len;
    const uint8_t * p_pt;

    size_t  ct_len;
    const uint8_t * p_ct;

    size_t  tag_len;
    const uint8_t * p_tag;
} gcm_test_vector_t;

/*****************************************************************************
 * Look-up tables
 ****************************************************************************/

extern const gcm_test_vector_t gcm_test_vectors[];


#endif /* !defined(GCM_TEST_VECTORS_H) */
