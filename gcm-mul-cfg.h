/**
 * gcm_mul_cfg.h
 *
 * Select which GCM Galois multiplication implementation to use.
 */

#ifndef GCM_MUL_CFG_H
#define GCM_MUL_CFG_H


///////////////////////////////////////////////////////////////////////////////////////////////////
// Defines
///////////////////////////////////////////////////////////////////////////////////////////////////

/* Set an element type that is efficient on the target platform. 1, 2, 4 or 8.
 * Same size as platform's unsigned int is probably a good value.
 * But for 8-bit platforms, 1 may be better. For 64-bit platforms, 8 is probably good.
 * If 1 is used, gcm_u128_struct_from_bytes() etc could simply be
 * replaced by memcpy(). */
#define GCM_U128_ELEMENT_SIZE               4

// Select little-endian optimisation
#undef GCM_MUL_LITTLE_ENDIAN

// Control which GCM Galois multiplication implementations are compiled in gcm_mul.c.

#define GCM_MUL_BIT_BY_BIT
#define GCM_MUL_TABLE_4
#define GCM_MUL_TABLE_8


#endif /* !defined( GCM_MUL_CFG_H ) */
