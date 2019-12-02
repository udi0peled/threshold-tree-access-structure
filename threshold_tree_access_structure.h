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
    THRESHOLD_TREE_SUCCESS               =  0,
    THRESHOLD_TREE_UNKNOWN_ERROR         = -1,
    THRESHOLD_TREE_INVALID_PARAMETER     = -2,
    THRESHOLD_TREE_INSUFFICIENT_BUFFER   = -3,
    THRESHOLD_TREE_OUT_OF_MEMORY         = -4,
} threshold_tree_status;

typedef struct threshold_tree_node_path threshold_tree_node_path_t;

typedef struct threshold_tree_node_path
{
    uint8_t *path;
    uint8_t length;
};

threshold_tree_ctx_t *threshold_tree_ctx_new(uint8_t num_shares, uint8_t threshold, uint64_t *ids);
void threshold_tree_ctx_free(threshold_tree_ctx_t *tree_ctx);

#ifdef __cplusplus
}
#endif //__cplusplus

#endif //#ifndef __THRESHOLD_TREE_ACCESS_STRUCTURE_H__