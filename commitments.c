#include "commitments.h"

#include <openssl/sha.h>
#include <openssl/rand.h>
#include <openssl/crypto.h>


commitments_status commitments_create_commitment_for_data(const uint8_t *data, uint32_t data_len, commitments_commitment_t *commitment)
{
    SHA256_CTX ctx;
    if (!data || !data_len || !commitment)
        return COMMITMENTS_INVALID_PARAMETER;
    if (!RAND_bytes(commitment->salt, sizeof(commitments_sha256_t)))
        return COMMITMENTS_INTERNAL_ERROR;
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, commitment->salt, sizeof(commitments_sha256_t));
    SHA256_Update(&ctx, data, data_len);
    SHA256_Final(commitment->commitment, &ctx);
    return COMMITMENTS_SUCCESS;
}

commitments_status commitments_verify_commitment(const uint8_t *data, uint32_t data_len, const commitments_commitment_t *commitment)
{
    commitments_sha256_t hash;
    SHA256_CTX ctx;
    if (!data || !data_len || !commitment)
        return COMMITMENTS_INVALID_PARAMETER;
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, commitment->salt, sizeof(commitments_sha256_t));
    SHA256_Update(&ctx, data, data_len);
    SHA256_Final(hash, &ctx);
    return CRYPTO_memcmp(hash, commitment->commitment, sizeof(commitments_sha256_t)) ? COMMITMENTS_INVALID_COMMITMENT : COMMITMENTS_SUCCESS;
}
