#include "secp256k1_algebra.h"

#include <string.h>
#include <assert.h>

#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/sha.h>
#include <openssl/ec.h>
#include <openssl/objects.h>

const uint8_t SECP256K1_FIELD[] = {
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe, 
    0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x41};

struct secp256k1_algebra_ctx 
{
    EC_GROUP *secp256k1;
};

secp256k1_algebra_ctx_t *secp256k1_algebra_ctx_new()
{
    secp256k1_algebra_ctx_t *ctx = malloc(sizeof(secp256k1_algebra_ctx_t));

    if (ctx)
    {
        ctx->secp256k1 = EC_GROUP_new_by_curve_name(NID_secp256k1);
        if (!ctx->secp256k1)
        {
            free(ctx);
            return NULL;
        }
    }
    return ctx;
}

void secp256k1_algebra_ctx_free(secp256k1_algebra_ctx_t *ctx)
{
    if (ctx)
    {
        EC_GROUP_free(ctx->secp256k1);
        free(ctx);
    }
}

#define SIZEOF_POINT(p) (*(p) ? sizeof(secp256k1_point_t) : 1)

static secp256k1_algebra_status from_openssl_error(long err)
{
    if (ERR_GET_LIB(err) == ERR_LIB_EC && (ERR_GET_REASON(err) == EC_R_INVALID_ENCODING || ERR_GET_REASON(err) == EC_R_INVALID_COMPRESSED_POINT))
        return SECP256K1_ALGEBRA_INVALID_PARAMETER;
    if (ERR_GET_REASON(err) == ERR_R_MALLOC_FAILURE)
        return SECP256K1_ALGEBRA_OUT_OF_MEMORY;
    return SECP256K1_ALGEBRA_UNKNOWN_ERROR;
}

secp256k1_algebra_status secp256k1_algebra_generate_proof_for_data(const secp256k1_algebra_ctx_t *ctx, const uint8_t *data, uint32_t data_len, secp256k1_point_t *proof)
{
    BN_CTX *bn_ctx = NULL;
    EC_POINT *point = NULL;
    BIGNUM *exp = NULL;
    secp256k1_algebra_status ret = SECP256K1_ALGEBRA_UNKNOWN_ERROR;

    if (!ctx || !data || !proof || !data_len)
        return SECP256K1_ALGEBRA_INVALID_PARAMETER;
    
    memset(*proof, 0, sizeof(secp256k1_point_t));
    point = EC_POINT_new(ctx->secp256k1);
    if (!point)
        return SECP256K1_ALGEBRA_OUT_OF_MEMORY;
    bn_ctx = BN_CTX_new();
    if (!bn_ctx)
    {
        EC_POINT_free(point);
        return SECP256K1_ALGEBRA_OUT_OF_MEMORY;
    }
    BN_CTX_start(bn_ctx);
    exp = BN_CTX_get(bn_ctx);
    if (!exp || !BN_bin2bn(data, data_len, exp))
    {
        ret = SECP256K1_ALGEBRA_OUT_OF_MEMORY;
        goto cleanup;
    }
    if (EC_POINT_mul(ctx->secp256k1, point, exp, NULL, NULL, bn_ctx))
    {
        if (EC_POINT_point2oct(ctx->secp256k1, point, POINT_CONVERSION_COMPRESSED, *proof, sizeof(secp256k1_point_t), bn_ctx) > 0)
            ret = SECP256K1_ALGEBRA_SUCCESS;            
    }

cleanup:
    BN_clear(exp);
    BN_CTX_end(bn_ctx);
    BN_CTX_free(bn_ctx);
    EC_POINT_free(point);
    return ret;
}

secp256k1_algebra_status secp256k1_algebra_verify(const secp256k1_algebra_ctx_t *ctx, const uint8_t *data, uint32_t data_len, const secp256k1_point_t *proof, uint8_t *result)
{
    secp256k1_point_t local_proof;
    secp256k1_algebra_status ret;

    if (!result || !proof)
        return SECP256K1_ALGEBRA_INVALID_PARAMETER;
    
    *result = 0;
    
    ret = secp256k1_algebra_generate_proof_for_data(ctx, data, data_len, &local_proof);
    if (ret == SECP256K1_ALGEBRA_SUCCESS)
        *result = CRYPTO_memcmp(local_proof, proof, sizeof(secp256k1_point_t)) ? 0 : 1;
    return ret;
}

secp256k1_algebra_status secp256k1_algebra_verify_sum(const secp256k1_algebra_ctx_t *ctx, const secp256k1_point_t *proof, const secp256k1_point_t *proof_points, uint32_t points_count, uint8_t *result)
{
    BN_CTX *bn_ctx = NULL;
    EC_POINT *p_proof = NULL;
    EC_POINT *point = NULL;
    EC_POINT *tmp = NULL;
    int ret;
    secp256k1_algebra_status status = SECP256K1_ALGEBRA_UNKNOWN_ERROR;

    if (!ctx || !proof || !proof_points || !points_count || !result)
        return SECP256K1_ALGEBRA_INVALID_PARAMETER;
    
    *result = 0;

    p_proof = EC_POINT_new(ctx->secp256k1);
    if (!p_proof)
        return SECP256K1_ALGEBRA_OUT_OF_MEMORY;

    point = EC_POINT_new(ctx->secp256k1);
    if (!point)
    {
        status = SECP256K1_ALGEBRA_OUT_OF_MEMORY;
        goto cleanup;
    }

    tmp = EC_POINT_new(ctx->secp256k1);
    if (!tmp)
    {
        status = SECP256K1_ALGEBRA_OUT_OF_MEMORY;
        goto cleanup;
    }

    bn_ctx = BN_CTX_new();
    if (!bn_ctx)
    {
        status = SECP256K1_ALGEBRA_OUT_OF_MEMORY;
        goto cleanup;
    }
    BN_CTX_start(bn_ctx);
    
    if (!EC_POINT_oct2point(ctx->secp256k1, p_proof, *proof, SIZEOF_POINT(*proof), bn_ctx))
    {
        status = from_openssl_error(ERR_get_error());
        goto cleanup;
    }

    for (uint32_t i = 0; i < points_count; ++i)
    {
        if (!EC_POINT_oct2point(ctx->secp256k1, tmp, proof_points[i], SIZEOF_POINT(proof_points[i]), bn_ctx))
        {
            status = from_openssl_error(ERR_get_error());
            goto cleanup;
        }
        if (!EC_POINT_add(ctx->secp256k1, point, point, tmp, bn_ctx))
            goto cleanup;
    }
    
    ret = EC_POINT_cmp(ctx->secp256k1, point, p_proof, bn_ctx);
    if (ret >= 0)
    {
        *result = (ret == 0);
        status = SECP256K1_ALGEBRA_SUCCESS;
    }
    
cleanup:
    BN_CTX_end(bn_ctx);
    BN_CTX_free(bn_ctx);
    EC_POINT_free(p_proof);
    EC_POINT_free(point);
    EC_POINT_free(tmp);
    return status;
}

secp256k1_algebra_status secp256k1_algebra_verify_linear_combination(const secp256k1_algebra_ctx_t *ctx, const secp256k1_point_t *proof, const secp256k1_point_t *proof_points, const secp256k1_scalar_t *coefficients, 
    uint32_t points_count, uint8_t *result)
{
    BN_CTX *bn_ctx = NULL;
    EC_POINT *p_proof = NULL;
    EC_POINT **points = NULL;
    BIGNUM **coeff = NULL;
    EC_POINT *tmp = NULL;
    BIGNUM *zero = NULL;
    int ret;
    secp256k1_algebra_status status = SECP256K1_ALGEBRA_OUT_OF_MEMORY;

    if (!ctx || !proof || !proof_points || !coefficients || !points_count || !result)
        return SECP256K1_ALGEBRA_INVALID_PARAMETER;
    
    *result = 0;

    bn_ctx = BN_CTX_new();
    if (!bn_ctx)
        return SECP256K1_ALGEBRA_OUT_OF_MEMORY;
    BN_CTX_start(bn_ctx);
    
    p_proof = EC_POINT_new(ctx->secp256k1);
    if (!p_proof)
        goto cleanup;
    if (!EC_POINT_oct2point(ctx->secp256k1, p_proof, *proof, SIZEOF_POINT(*proof), bn_ctx))
    {
        status = from_openssl_error(ERR_get_error());
        goto cleanup;
    }

    points = (EC_POINT**)calloc(points_count, sizeof(EC_POINT*));
    if (!points)
        goto cleanup;
    
    for (size_t i = 0; i < points_count; ++i)
    {
        points[i] = EC_POINT_new(ctx->secp256k1);
        if (!points[i])
            goto cleanup;
        if (!EC_POINT_oct2point(ctx->secp256k1, points[i], proof_points[i], SIZEOF_POINT(proof_points[i]), bn_ctx))
        {
            status = from_openssl_error(ERR_get_error());
            goto cleanup;
        }
    }

    coeff = (BIGNUM**)calloc(points_count, sizeof(BIGNUM*));
    if (!coeff)
        goto cleanup;
    
    for (size_t i = 0; i < points_count; ++i)
    {
        coeff[i] = BN_CTX_get(bn_ctx);
        if (!coeff[i] || !BN_bin2bn(coefficients[i], sizeof(secp256k1_scalar_t), coeff[i]))
            goto cleanup;
    }

    zero = BN_CTX_get(bn_ctx);
    BN_zero(zero);
    tmp = EC_POINT_new(ctx->secp256k1);
    if (!zero || !tmp)
        goto cleanup;
    if (!EC_POINTs_mul(ctx->secp256k1, tmp, zero, points_count, (const EC_POINT**)points, (const BIGNUM**)coeff, bn_ctx))
    {
        status = SECP256K1_ALGEBRA_UNKNOWN_ERROR;
        goto cleanup;
    }
    
    ret = EC_POINT_cmp(ctx->secp256k1, tmp, p_proof, bn_ctx);
    if (ret >= 0)
    {
        *result = (ret == 0);
        status = SECP256K1_ALGEBRA_SUCCESS;
    }
    
cleanup:
    for (size_t i = 0; i < points_count; ++i)
    {
        if (coeff[i])
            BN_clear(coeff[i]);
    }

    BN_CTX_end(bn_ctx);
    BN_CTX_free(bn_ctx);

    if (points)
    {
        for (size_t i = 0; i < points_count; ++i)
            EC_POINT_free(points[i]);
        free(points);
    }
    free(coeff);
    EC_POINT_free(p_proof);
    EC_POINT_free(tmp);
    return status;
}

secp256k1_algebra_status secp256k1_algebra_generator_mul(const secp256k1_algebra_ctx_t *ctx, secp256k1_point_t *res, const secp256k1_scalar_t *exp)
{
    if (!exp)
        return SECP256K1_ALGEBRA_INVALID_PARAMETER;
    return secp256k1_algebra_generate_proof_for_data(ctx, *exp, sizeof(secp256k1_scalar_t), res);
}

secp256k1_algebra_status secp256k1_algebra_add_points(const secp256k1_algebra_ctx_t *ctx, secp256k1_point_t *res, const secp256k1_point_t *p1, const secp256k1_point_t *p2)
{
    BN_CTX *bn_ctx = NULL;
    EC_POINT *p_p1 = NULL;
    EC_POINT *p_p2 = NULL;
    secp256k1_algebra_status status = SECP256K1_ALGEBRA_UNKNOWN_ERROR;

    if (!ctx || !res || !p1 || !p2)
        return SECP256K1_ALGEBRA_INVALID_PARAMETER;
    
    p_p1 = EC_POINT_new(ctx->secp256k1);
    if (!p_p1)
        return SECP256K1_ALGEBRA_OUT_OF_MEMORY;

    p_p2 = EC_POINT_new(ctx->secp256k1);
    if (!p_p2)
    {
        status = SECP256K1_ALGEBRA_OUT_OF_MEMORY;
        goto cleanup;
    }

    bn_ctx = BN_CTX_new();
    if (!bn_ctx)
    {
        status = SECP256K1_ALGEBRA_OUT_OF_MEMORY;
        goto cleanup;
    }
    BN_CTX_start(bn_ctx);
    
    if (!EC_POINT_oct2point(ctx->secp256k1, p_p1, *p1, SIZEOF_POINT(*p1), bn_ctx))
    {
        status = from_openssl_error(ERR_get_error());
        goto cleanup;
    }
    if (!EC_POINT_oct2point(ctx->secp256k1, p_p2, *p2, SIZEOF_POINT(*p2), bn_ctx))
    {
        status = from_openssl_error(ERR_get_error());
        goto cleanup;
    }

    if (!EC_POINT_add(ctx->secp256k1, p_p1, p_p1, p_p2, bn_ctx))
        goto cleanup;
    
    memset(*res, 0, sizeof(secp256k1_point_t));
    if (EC_POINT_point2oct(ctx->secp256k1, p_p1, POINT_CONVERSION_COMPRESSED, *res, sizeof(secp256k1_point_t), bn_ctx) > 0)
        status = SECP256K1_ALGEBRA_SUCCESS;
    
cleanup:
    BN_CTX_end(bn_ctx);
    BN_CTX_free(bn_ctx);
    EC_POINT_free(p_p1);
    EC_POINT_free(p_p2);
    return status;
}

secp256k1_algebra_status secp256k1_algebra_point_mul(const secp256k1_algebra_ctx_t *ctx, secp256k1_point_t *res, const secp256k1_point_t *p, const secp256k1_scalar_t *exp)
{
    BN_CTX *bn_ctx = NULL;
    EC_POINT *p_p = NULL;
    BIGNUM *bn_exp = NULL;
    secp256k1_algebra_status status = SECP256K1_ALGEBRA_UNKNOWN_ERROR;

    if (!ctx || !res || !p || !exp)
        return SECP256K1_ALGEBRA_INVALID_PARAMETER;
    
    p_p = EC_POINT_new(ctx->secp256k1);
    if (!p_p)
        return SECP256K1_ALGEBRA_OUT_OF_MEMORY;

    bn_ctx = BN_CTX_new();
    if (!bn_ctx)
    {
        status = SECP256K1_ALGEBRA_OUT_OF_MEMORY;
        goto cleanup;
    }
    BN_CTX_start(bn_ctx);
    
    bn_exp = BN_CTX_get(bn_ctx);
    if (!bn_exp || !BN_bin2bn(*exp, sizeof(secp256k1_scalar_t), bn_exp))
    {
        status = SECP256K1_ALGEBRA_OUT_OF_MEMORY;
        goto cleanup;
    }

    if (!EC_POINT_oct2point(ctx->secp256k1, p_p, *p, SIZEOF_POINT(*p), bn_ctx))
    {
        status = from_openssl_error(ERR_get_error());
        goto cleanup;
    }

    if (!EC_POINT_mul(ctx->secp256k1, p_p, NULL, p_p, bn_exp, bn_ctx))
        goto cleanup;
    
    memset(*res, 0, sizeof(secp256k1_point_t));
    if (EC_POINT_point2oct(ctx->secp256k1, p_p, POINT_CONVERSION_COMPRESSED, *res, sizeof(secp256k1_point_t), bn_ctx) > 0)
        status = SECP256K1_ALGEBRA_SUCCESS;
    
cleanup:
    if (bn_exp)
        BN_clear(bn_exp);
    BN_CTX_end(bn_ctx);
    BN_CTX_free(bn_ctx);
    EC_POINT_free(p_p);
    return status;
}

secp256k1_algebra_status secp256k1_algebra_get_point_projection(const secp256k1_algebra_ctx_t *ctx, secp256k1_scalar_t *res, const secp256k1_point_t *p, uint8_t* overflow)
{
    BN_CTX *bn_ctx = NULL;
    EC_POINT *p_p = NULL;
    BIGNUM *X = NULL;
    secp256k1_algebra_status status = SECP256K1_ALGEBRA_UNKNOWN_ERROR;

    if (!ctx || !res || !p)
        return SECP256K1_ALGEBRA_INVALID_PARAMETER;
    
    memset(*res, 0, sizeof(secp256k1_scalar_t));
    p_p = EC_POINT_new(ctx->secp256k1);
    if (!p_p)
        return SECP256K1_ALGEBRA_OUT_OF_MEMORY;

    bn_ctx = BN_CTX_new();
    if (!bn_ctx)
    {
        status = SECP256K1_ALGEBRA_OUT_OF_MEMORY;
        goto cleanup;
    }

    BN_CTX_start(bn_ctx);
    
    X = BN_CTX_get(bn_ctx);
    if (!X)
    {
        status = SECP256K1_ALGEBRA_OUT_OF_MEMORY;
        goto cleanup;
    }

    if (!EC_POINT_oct2point(ctx->secp256k1, p_p, *p, SIZEOF_POINT(*p), bn_ctx))
    {
        status = from_openssl_error(ERR_get_error());
        goto cleanup;
    }

    if (!EC_POINT_get_affine_coordinates_GFp(ctx->secp256k1, p_p, X, NULL, bn_ctx))
        goto cleanup;
    
    if (overflow)
        *overflow = BN_cmp(X, EC_GROUP_get0_order(ctx->secp256k1)) < 0 ? 0 : 1;

    if (!BN_nnmod(X, X, EC_GROUP_get0_order(ctx->secp256k1), bn_ctx))
        goto cleanup;
    
    status = BN_bn2binpad(X, *res, sizeof(secp256k1_scalar_t)) > 0 ? SECP256K1_ALGEBRA_SUCCESS : SECP256K1_ALGEBRA_UNKNOWN_ERROR;
    
cleanup:
    BN_CTX_end(bn_ctx);
    BN_CTX_free(bn_ctx);
    EC_POINT_free(p_p);
    return status;
}

secp256k1_algebra_status secp256k1_algebra_add_scalars(secp256k1_algebra_ctx_t *ctx, secp256k1_scalar_t *res, const uint8_t *a, uint32_t a_len, const uint8_t *b, uint32_t b_len)
{
    BN_CTX *bn_ctx = NULL;
    BIGNUM *bn_a = NULL;
    BIGNUM *bn_b = NULL;
    secp256k1_algebra_status ret = SECP256K1_ALGEBRA_OUT_OF_MEMORY;

    if (!ctx || !res || !a || !a_len || !b || !b_len)
        return SECP256K1_ALGEBRA_INVALID_PARAMETER;
    
    bn_ctx = BN_CTX_new();
    if (!bn_ctx)
        return SECP256K1_ALGEBRA_OUT_OF_MEMORY;

    BN_CTX_start(bn_ctx);

    bn_a = BN_CTX_get(bn_ctx);
    if (!bn_a || !BN_bin2bn(a, a_len, bn_a))
        goto cleanup;
    bn_b = BN_CTX_get(bn_ctx);
    if (!bn_b || !BN_bin2bn(b, b_len, bn_b))
        goto cleanup;
    
    BN_set_flags(bn_a, BN_FLG_CONSTTIME);
    BN_set_flags(bn_b, BN_FLG_CONSTTIME);
    
    if (BN_mod_add(bn_a, bn_a, bn_b, EC_GROUP_get0_order(ctx->secp256k1), bn_ctx))
    {
        ret = BN_bn2binpad(bn_a, *res, sizeof(secp256k1_scalar_t)) > 0 ? SECP256K1_ALGEBRA_SUCCESS : SECP256K1_ALGEBRA_UNKNOWN_ERROR;
    }
    else
        ret = SECP256K1_ALGEBRA_UNKNOWN_ERROR;
    
cleanup:
    if (bn_a)
        BN_clear(bn_a);
    if (bn_b)
        BN_clear(bn_b);
    BN_CTX_end(bn_ctx);
    BN_CTX_free(bn_ctx);
    return ret;
}

secp256k1_algebra_status secp256k1_algebra_sub_scalars(secp256k1_algebra_ctx_t *ctx, secp256k1_scalar_t *res, const uint8_t *a, uint32_t a_len, const uint8_t *b, uint32_t b_len)
{
    BN_CTX *bn_ctx = NULL;
    BIGNUM *bn_a = NULL;
    BIGNUM *bn_b = NULL;
    secp256k1_algebra_status ret = SECP256K1_ALGEBRA_OUT_OF_MEMORY;

    if (!ctx || !res || !a || !a_len || !b || !b_len)
        return SECP256K1_ALGEBRA_INVALID_PARAMETER;

    bn_ctx = BN_CTX_new();
    if (!bn_ctx)
        return SECP256K1_ALGEBRA_OUT_OF_MEMORY;
    
    BN_CTX_start(bn_ctx);

    bn_a = BN_CTX_get(bn_ctx);
    if (!bn_a || !BN_bin2bn(a, a_len, bn_a))
        goto cleanup;
    bn_b = BN_CTX_get(bn_ctx);
    if (!bn_b || !BN_bin2bn(b, b_len, bn_b))
        goto cleanup;
    
    BN_set_flags(bn_a, BN_FLG_CONSTTIME);
    BN_set_flags(bn_b, BN_FLG_CONSTTIME);

    if (BN_mod_sub(bn_a, bn_a, bn_b, EC_GROUP_get0_order(ctx->secp256k1), bn_ctx))
    {
        ret = BN_bn2binpad(bn_a, *res, sizeof(secp256k1_scalar_t)) > 0 ? SECP256K1_ALGEBRA_SUCCESS : SECP256K1_ALGEBRA_UNKNOWN_ERROR;
    }
    else
        ret = SECP256K1_ALGEBRA_UNKNOWN_ERROR;
    
cleanup:
    if (bn_a)
        BN_clear(bn_a);
    if (bn_b)
        BN_clear(bn_b);
    BN_CTX_end(bn_ctx);
    BN_CTX_free(bn_ctx);
    return ret;
}

secp256k1_algebra_status secp256k1_algebra_mul_scalars(secp256k1_algebra_ctx_t *ctx, secp256k1_scalar_t *res, const uint8_t *a, uint32_t a_len, const uint8_t *b, uint32_t b_len)
{
    BN_CTX *bn_ctx = NULL;
    BIGNUM *bn_a = NULL;
    BIGNUM *bn_b = NULL;
    secp256k1_algebra_status ret = SECP256K1_ALGEBRA_OUT_OF_MEMORY;

    if (!ctx || !res || !a || !a_len || !b || !b_len)
        return SECP256K1_ALGEBRA_INVALID_PARAMETER;

    bn_ctx = BN_CTX_new();
    if (!bn_ctx)
        return SECP256K1_ALGEBRA_OUT_OF_MEMORY;
    
    BN_CTX_start(bn_ctx);

    bn_a = BN_CTX_get(bn_ctx);
    if (!bn_a || !BN_bin2bn(a, a_len, bn_a))
        goto cleanup;
    bn_b = BN_CTX_get(bn_ctx);
    if (!bn_b || !BN_bin2bn(b, b_len, bn_b))
        goto cleanup;
    
    BN_set_flags(bn_a, BN_FLG_CONSTTIME);
    BN_set_flags(bn_b, BN_FLG_CONSTTIME);

    if (BN_mod_mul(bn_a, bn_a, bn_b, EC_GROUP_get0_order(ctx->secp256k1), bn_ctx))
    {
        ret = BN_bn2binpad(bn_a, *res, sizeof(secp256k1_scalar_t)) > 0 ? SECP256K1_ALGEBRA_SUCCESS : SECP256K1_ALGEBRA_UNKNOWN_ERROR;
    }
    else
        ret = SECP256K1_ALGEBRA_UNKNOWN_ERROR;

cleanup:
    if (bn_a)
        BN_clear(bn_a);
    if (bn_b)
        BN_clear(bn_b);
    BN_CTX_end(bn_ctx);
    BN_CTX_free(bn_ctx);
    return ret;
}

secp256k1_algebra_status secp256k1_algebra_inverse(secp256k1_algebra_ctx_t *ctx, secp256k1_scalar_t *res, const secp256k1_scalar_t *val)
{
    BN_CTX *bn_ctx = NULL;
    BIGNUM *bn_val = NULL;
    secp256k1_algebra_status ret = SECP256K1_ALGEBRA_OUT_OF_MEMORY;

    if (!ctx || !res || !val)
        return SECP256K1_ALGEBRA_INVALID_PARAMETER;

    bn_ctx = BN_CTX_new();
    if (!bn_ctx)
        return SECP256K1_ALGEBRA_OUT_OF_MEMORY;

    BN_CTX_start(bn_ctx);

    bn_val = BN_CTX_get(bn_ctx);
    if (!bn_val || !BN_bin2bn(*val, sizeof(secp256k1_scalar_t), bn_val))
        goto cleanup;
    
    BN_set_flags(bn_val, BN_FLG_CONSTTIME);
    
    if (BN_mod_inverse(bn_val, bn_val, EC_GROUP_get0_order(ctx->secp256k1), bn_ctx))
    {
        ret = BN_bn2binpad(bn_val, *res, sizeof(secp256k1_scalar_t)) > 0 ? SECP256K1_ALGEBRA_SUCCESS : SECP256K1_ALGEBRA_UNKNOWN_ERROR;
    }
    else
        ret = SECP256K1_ALGEBRA_UNKNOWN_ERROR;

cleanup:
    if (bn_val)
        BN_clear(bn_val);
    BN_CTX_end(bn_ctx);
    BN_CTX_free(bn_ctx);
    return ret;
}

secp256k1_algebra_status secp256k1_algebra_abs(secp256k1_algebra_ctx_t *ctx, secp256k1_scalar_t *res, const secp256k1_scalar_t *val)
{
    BIGNUM *bn_val = NULL;
    BIGNUM *bn_neg_val = NULL;
    BIGNUM *tmp = NULL;
    const BIGNUM *field = NULL;
    secp256k1_algebra_status ret = SECP256K1_ALGEBRA_OUT_OF_MEMORY;

    if (!ctx || !res || !val)
        return SECP256K1_ALGEBRA_INVALID_PARAMETER;
    
    field = EC_GROUP_get0_order(ctx->secp256k1);

    bn_val = BN_new();
    if (!bn_val || !BN_bin2bn(*val, sizeof(secp256k1_scalar_t), bn_val))
        goto cleanup;
    tmp = BN_new();
    if (!tmp || !BN_rshift1(tmp, field))
        goto cleanup;
    bn_neg_val = BN_new();
    if (!bn_neg_val)
        goto cleanup;

    // The sub operation is always done, so that the function will run in constant time
    if (!BN_sub(bn_neg_val, field, bn_val))
    {
        ret = SECP256K1_ALGEBRA_UNKNOWN_ERROR;
        goto cleanup;
    }

    if (BN_cmp(bn_val, tmp) > 0 && !BN_is_negative(bn_neg_val))
        ret = BN_bn2binpad(bn_neg_val, *res, sizeof(secp256k1_scalar_t)) > 0 ? SECP256K1_ALGEBRA_SUCCESS : SECP256K1_ALGEBRA_UNKNOWN_ERROR;
    else
        ret = BN_bn2binpad(bn_val, *res, sizeof(secp256k1_scalar_t)) > 0 ? SECP256K1_ALGEBRA_SUCCESS : SECP256K1_ALGEBRA_UNKNOWN_ERROR;

cleanup:
    if (bn_val)
        BN_clear_free(bn_val);
    if (bn_neg_val)
        BN_clear_free(bn_neg_val);
    if (tmp)
        BN_free(tmp);
    return ret;
}

secp256k1_algebra_status secp256k1_algebra_rand(secp256k1_algebra_ctx_t *ctx, secp256k1_scalar_t *res)
{
    BIGNUM *tmp = NULL;
    secp256k1_algebra_status ret = SECP256K1_ALGEBRA_OUT_OF_MEMORY;

    if (!ctx || !res)
        return SECP256K1_ALGEBRA_INVALID_PARAMETER;
    
    tmp = BN_new();
    if (!tmp)
        goto cleanup;
    if (!BN_rand_range(tmp, EC_GROUP_get0_order(ctx->secp256k1)))
    {
        ret = SECP256K1_ALGEBRA_UNKNOWN_ERROR;
        goto cleanup;
    }

    ret = BN_bn2binpad(tmp, *res, sizeof(secp256k1_scalar_t)) > 0 ? SECP256K1_ALGEBRA_SUCCESS : SECP256K1_ALGEBRA_UNKNOWN_ERROR;

cleanup:
    BN_clear_free(tmp);
    return ret;
}

// UDI: added function used in threshold tree
secp256k1_algebra_status secp256k1_algebra_scalar_from_ul(secp256k1_algebra_ctx_t *ctx, unsigned long value, secp256k1_scalar_t *res)
{
    if (!ctx || !res) return SECP256K1_ALGEBRA_INVALID_PARAMETER;

    secp256k1_algebra_status ret_status = SECP256K1_ALGEBRA_UNKNOWN_ERROR;

    BN_CTX *bn_ctx = NULL;

    bn_ctx = BN_CTX_new();
    if (!bn_ctx) return SECP256K1_ALGEBRA_OUT_OF_MEMORY;
    
    BN_CTX_start(bn_ctx);

    BIGNUM *bn_value = BN_CTX_get(bn_ctx);
    if (!BN_set_word(bn_value, value)) 
    {
        ret_status = from_openssl_error(ERR_get_error());
        goto cleanup;
    }
    if (!BN_mod(bn_value, bn_value, EC_GROUP_get0_order(ctx->secp256k1), bn_ctx))
    {
        ret_status = from_openssl_error(ERR_get_error());
        goto cleanup;
    }

    ret_status = BN_bn2binpad(bn_value, *res, sizeof(secp256k1_scalar_t)) > 0 ? SECP256K1_ALGEBRA_SUCCESS : SECP256K1_ALGEBRA_UNKNOWN_ERROR;

cleanup:
    if (bn_value) BN_clear(bn_value);
    BN_CTX_end(bn_ctx);
    BN_CTX_free(bn_ctx);

    return ret_status;
}