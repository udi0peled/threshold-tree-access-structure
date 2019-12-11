#ifndef __THRESHOLD_TREE_ACCESS_STRUCTURE_H__
#define __THRESHOLD_TREE_ACCESS_STRUCTURE_H__

#include <stdint.h>

#include "secp256k1_algebra.h"

#ifdef __cplusplus
extern "C" {
#endif //__cplusplus

typedef struct threshold_tree_ctx threshold_tree_ctx_t;
typedef struct threshold_tree_node* threshold_tree_party_t;
typedef secp256k1_scalar_t threshold_tree_scalar_t;
typedef secp256k1_point_t threshold_tree_group_point_t;

typedef enum
{
    THRESHOLD_TREE_SUCCESS                  =  0,
    THRESHOLD_TREE_UNKNOWN_ERROR            = -1,
    THRESHOLD_TREE_INVALID_PARAMETER        = -2,
    THRESHOLD_TREE_INVALID_TREE_STRUCTURE   = -3,
    THRESHOLD_TREE_INSUFFICIENT_BUFFER      = -4,
    THRESHOLD_TREE_OUT_OF_MEMORY            = -5,
    THRESHOLD_TREE_MISSING_ID               = -6,
    THRESHOLD_TREE_INVALID_ID               = -7,
    THRESHOLD_TREE_NULL_POINTER             = -8,
    THRESHOLD_TREE_INVALID_PARTY            = -9,
    THRESHOLD_TREE_INVALID_SHARE            = -10,
    THRESHOLD_TREE_INVALID_INDEX            = -11,
    THRESHOLD_TREE_INVALID_SECRET           = -12,
    THRESHOLD_TREE_UNAUTHORIZED_TREE        = -13,
} threshold_tree_status;

threshold_tree_ctx_t *threshold_tree_ctx_new();
void threshold_tree_ctx_free(threshold_tree_ctx_t *tree_ctx);

/* Returns (and counts) players with given ids in tree. Ids can repeat. Players and count_found can be null, in which case they are not populated. If any of the ids missing, returns MISSING_ID */
threshold_tree_status threshold_tree_get_parties_by_ids(const threshold_tree_ctx_t *tree_ctx, const uint64_t *ids, uint64_t num_ids, threshold_tree_party_t *parties, uint64_t *count_found);

/* Like threshold_tree_get_players_by_ids, just for a single player. Found or not is from the returned status */
threshold_tree_status threshold_tree_get_single_party_by_id(const threshold_tree_ctx_t *tree_ctx, uint64_t id, threshold_tree_party_t *player);

#ifdef __cplusplus
}
#endif //__cplusplus

#endif //#ifndef __THRESHOLD_TREE_ACCESS_STRUCTURE_H__