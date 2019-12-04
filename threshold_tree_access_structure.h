#ifndef __THRESHOLD_TREE_ACCESS_STRUCTURE_H__
#define __THRESHOLD_TREE_ACCESS_STRUCTURE_H__

#include <stdint.h>

#include "secp256k1_algebra.h"

#ifdef __cplusplus
extern "C" {
#endif //__cplusplus

typedef struct threshold_tree_ctx threshold_tree_ctx_t;

typedef enum
{
    THRESHOLD_TREE_SUCCESS                  =  0,
    THRESHOLD_TREE_UNKNOWN_ERROR            = -1,
    THRESHOLD_TREE_INVALID_PATH             = -2,
    THRESHOLD_TREE_INVALID_THRESHOLD        = -3,
    THRESHOLD_TREE_INSUFFICIENT_BUFFER      = -4,
    THRESHOLD_TREE_OUT_OF_MEMORY            = -5,
    THRESHOLD_TREE_MISSING_ID               = -6,
    THRESHOLD_TREE_INVALID_ID               = -7,
    THRESHOLD_TREE_INVALID_CTX              = -8,
    THRESHOLD_TREE_NULL_POINTER             = -9,
    THRESHOLD_TREE_INCOMPLETE_STRUCTURE     = -10,
    THRESHOLD_TREE_INVALID_PARAMETER        = -11,
    THRESHOLD_TREE_SHARING_INVALID_INDEX    = -12,
    THRESHOLD_TREE_SHARING_INVALID_SECRET   = -13,
    THRESHOLD_TREE_SHARING_INVALID_SHARE    = -14,
} threshold_tree_status;

threshold_tree_ctx_t *threshold_tree_ctx_new();
void threshold_tree_ctx_free(threshold_tree_ctx_t *tree_ctx);

#ifdef __cplusplus
}
#endif //__cplusplus

#endif //#ifndef __THRESHOLD_TREE_ACCESS_STRUCTURE_H__