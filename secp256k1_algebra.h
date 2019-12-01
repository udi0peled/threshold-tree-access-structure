#ifndef __SECP256K1_ALGEBRA_H__
#define __SECP256K1_ALGEBRA_H__

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif //__cplusplus

#define SECP256K1_FIELD_SIZE 32
#define SECP256K1_COMPRESSED_POINT_LEN 33

extern const uint8_t SECP256K1_FIELD[];

typedef struct secp256k1_algebra_ctx secp256k1_algebra_ctx_t;
typedef uint8_t secp256k1_point_t[SECP256K1_COMPRESSED_POINT_LEN];
typedef uint8_t secp256k1_scalar_t[SECP256K1_FIELD_SIZE];

typedef enum
{
    SECP256K1_ALGEBRA_SUCCESS               =  0,
    SECP256K1_ALGEBRA_UNKNOWN_ERROR         = -1,
    SECP256K1_ALGEBRA_INVALID_PARAMETER     = -2,
    SECP256K1_ALGEBRA_INSUFFICIENT_BUFFER   = -3,
    SECP256K1_ALGEBRA_OUT_OF_MEMORY         = -4,
} secp256k1_algebra_status;


secp256k1_algebra_ctx_t *secp256k1_algebra_ctx_new();
void secp256k1_algebra_ctx_free(secp256k1_algebra_ctx_t *ctx);

/* Generates proof g^data over the secp256k1 curve, so data must be SECP256K1_FIELD_SIZE (or less) */
secp256k1_algebra_status secp256k1_algebra_generate_proof_for_data(const secp256k1_algebra_ctx_t *ctx, const uint8_t *data, uint32_t data_len, secp256k1_point_t *proof);
/* Verifies that proof == g^data over the secp256k1 curve */
secp256k1_algebra_status secp256k1_algebra_verify(const secp256k1_algebra_ctx_t *ctx, const uint8_t *data, uint32_t data_len, const secp256k1_point_t *proof, uint8_t *result);
/* Verifies that proof == sum(proof_points) over the secp256k1 curve */
secp256k1_algebra_status secp256k1_algebra_verify_sum(const secp256k1_algebra_ctx_t *ctx, const secp256k1_point_t *proof, const secp256k1_point_t *proof_points, uint32_t points_count, uint8_t *result);
/* Verifies that proof == sum(proof_point[i]*coef[i]) over the secp256k1 curve */
secp256k1_algebra_status secp256k1_algebra_verify_linear_combination(const secp256k1_algebra_ctx_t *ctx, const secp256k1_point_t *proof, const secp256k1_point_t *proof_points, const secp256k1_scalar_t *coefficients, 
    uint32_t points_count, uint8_t *result);
/* Returns g^exp over the secp256k1 curve */
secp256k1_algebra_status secp256k1_algebra_generator_mul(const secp256k1_algebra_ctx_t *ctx, secp256k1_point_t *res, const secp256k1_scalar_t *exp);
/* Adds p1 and p2 points over the secp256k1 curve */
secp256k1_algebra_status secp256k1_algebra_add_points(const secp256k1_algebra_ctx_t *ctx, secp256k1_point_t *res, const secp256k1_point_t *p1, const secp256k1_point_t *p2);
/* Computes p^exp over the secp256k1 curve */
secp256k1_algebra_status secp256k1_algebra_point_mul(const secp256k1_algebra_ctx_t *ctx, secp256k1_point_t *res, const secp256k1_point_t *p, const secp256k1_scalar_t *exp);
/* Returns the normalized projection of p over the X axis, the optional parameter overflow returns whether x coordinate exceeds the order */
secp256k1_algebra_status secp256k1_algebra_get_point_projection(const secp256k1_algebra_ctx_t *ctx, secp256k1_scalar_t *res, const secp256k1_point_t *p, uint8_t* overflow);
/* Adds a and b over the secp256k1 order */
secp256k1_algebra_status secp256k1_algebra_add_scalars(secp256k1_algebra_ctx_t *ctx, secp256k1_scalar_t *res, const uint8_t *a, uint32_t a_len, const uint8_t *b, uint32_t b_len);
/* Subs b from a over the secp256k1 order */
secp256k1_algebra_status secp256k1_algebra_sub_scalars(secp256k1_algebra_ctx_t *ctx, secp256k1_scalar_t *res, const uint8_t *a, uint32_t a_len, const uint8_t *b, uint32_t b_len);
/* Multiplies a and b over the secp256k1 order */
secp256k1_algebra_status secp256k1_algebra_mul_scalars(secp256k1_algebra_ctx_t *ctx, secp256k1_scalar_t *res, const uint8_t *a, uint32_t a_len, const uint8_t *b, uint32_t b_len);
/* Calculates val ^ -1 over the secp256k1 order */
secp256k1_algebra_status secp256k1_algebra_inverse(secp256k1_algebra_ctx_t *ctx, secp256k1_scalar_t *res, const secp256k1_scalar_t *val);
/* Returns the absalute value of val over the secp256k1 order, e.g. if val > field/2 return -val */
secp256k1_algebra_status secp256k1_algebra_abs(secp256k1_algebra_ctx_t *ctx, secp256k1_scalar_t *res, const secp256k1_scalar_t *val);
/* Returns a random number over the secp256k1 order */
secp256k1_algebra_status secp256k1_algebra_rand(secp256k1_algebra_ctx_t *ctx, secp256k1_scalar_t *res);

#ifdef __cplusplus
}
#endif //__cplusplus

#endif //#ifndef __SECP256K1_ALGEBRA_H__