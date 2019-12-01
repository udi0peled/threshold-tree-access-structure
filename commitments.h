#ifndef __COMMITMENTS_H__
#define __COMMITMENTS_H__

#ifdef __cplusplus
extern "C" {
#endif //__cplusplus

#include <stdint.h>

typedef uint8_t commitments_sha256_t[32];

typedef struct commitments_commitment
{
    commitments_sha256_t salt;
    commitments_sha256_t commitment;
} commitments_commitment_t;

typedef enum
{
    COMMITMENTS_SUCCESS               =  0,
    COMMITMENTS_INTERNAL_ERROR        = -1,
    COMMITMENTS_INVALID_PARAMETER     = -2,
    COMMITMENTS_INVALID_COMMITMENT    = -3,
} commitments_status;

/* Creates commitment (SHA256) the data */
commitments_status commitments_create_commitment_for_data(const uint8_t *data, uint32_t data_len, commitments_commitment_t *commitment);
/* Verfies the data commitment (SHA256) */
commitments_status commitments_verify_commitment(const uint8_t *data, uint32_t data_len, const commitments_commitment_t *commitment);

#ifdef __cplusplus
}
#endif //__cplusplus

#endif // __COMMITMENTS_H__