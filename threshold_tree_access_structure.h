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

// ---------- Tree Structure ------------------------------------------------------------------------------------------------------------------------

threshold_tree_ctx_t *threshold_tree_ctx_new();
void threshold_tree_ctx_free(threshold_tree_ctx_t *tree_ctx);

/*
    Sets a child data (id, num children/shares, threshold) at given index parent's children.
    Null parent means setting tree root.
    Valid index should be unpopulated.
    Child's threshold can only be 0 iff num shares is 0 (child is leaf).
    Child's id should be non-zero and unique in the tree.
*/
threshold_tree_status threshold_tree_set_new_child(threshold_tree_ctx_t *tree_ctx, threshold_tree_party_t parent, uint8_t child_index, uint64_t child_id, uint8_t child_num_shares, uint8_t child_threshold, threshold_tree_party_t *new_child);

/*
    Validates threshold tree structures is completely built (no nodes/leaves left to be set).
    Doesn't say anything about tree's secret/group values.
*/
threshold_tree_status threshold_tree_is_complete_structure(threshold_tree_ctx_t *tree_ctx);

/*
    Generates a new tree from subtree rooted at pary, duplicating the subtree structure (not secret values).
*/
threshold_tree_status threshold_tree_duplicate_tree_structure(threshold_tree_party_t root_party, threshold_tree_ctx_t **new_tree_ctx);

// ---------- Getters and Serializers ------------------------------------------------------------------------------------------------------------------------

/*  
    Finds and counts parties with given ids in tree.
    Given ids can repeat, but *assumes tree ids are unique*.
    Non-null count_found is set to the count found parties.
    Non-null parties populated with found parties in order of ids.
    If at least one of the given ids wasn't found return MISSING_ID status.
*/
threshold_tree_status threshold_tree_get_parties_by_ids(const threshold_tree_ctx_t *tree_ctx, const uint64_t *ids, uint64_t num_ids, threshold_tree_party_t *parties, uint64_t *count_found);

/*
    Same as threshold_tree_get_parties_by_ids, without count_found, return SUCCESS or MISSING_ID
*/
threshold_tree_status threshold_tree_get_single_party_by_id(const threshold_tree_ctx_t *tree_ctx, uint64_t id, threshold_tree_party_t *party);

threshold_tree_status threshold_tree_get_party_secret(const threshold_tree_ctx_t *tree_ctx, const  threshold_tree_party_t party, threshold_tree_scalar_t secret);
threshold_tree_status threshold_tree_get_party_id(const threshold_tree_ctx_t *tree_ctx, const  threshold_tree_party_t party, uint64_t *id);
threshold_tree_status threshold_tree_get_party_num_shares(const threshold_tree_ctx_t *tree_ctx, const  threshold_tree_party_t party, uint8_t *num_shares);
threshold_tree_status threshold_tree_get_party_threshold(const threshold_tree_ctx_t *tree_ctx, const  threshold_tree_party_t party, uint8_t *threshold);
threshold_tree_status threshold_tree_get_party_lagrange_coeff(const threshold_tree_ctx_t *tree_ctx, const  threshold_tree_party_t party, threshold_tree_scalar_t lagrange_coeff);
threshold_tree_status threshold_tree_get_party_group_secret(const threshold_tree_ctx_t *tree_ctx, const  threshold_tree_party_t party, threshold_tree_group_point_t group_secret);

/*
    Populates buffer of group values (shares and polynomial coefficients) in a specific order.
    Null points or too small num of points, sets the needed num_points and doesn't populate.
*/
threshold_tree_status threshold_tree_serialize_group_points(threshold_tree_ctx_t *tree_ctx, threshold_tree_group_point_t *points, uint64_t *num_points);

/*
    Sets group values (shares and polynomial coefficients) on an already built tree in a specific order (correlated with serialize).
    Checks given num of points is not what's required by the tree structure.
*/
threshold_tree_status threshold_tree_deserialize_group_points(threshold_tree_ctx_t *tree_ctx, threshold_tree_group_point_t *points, uint64_t num_points);

// ---------- Verifiable Secret Sharing ------------------------------------------------------------------------------------------------------------------------

/*
    Sets a secret value at the root of the tree, and splits all the way down to the leaves.
*/
threshold_tree_status threshold_tree_share_secret(threshold_tree_ctx_t *tree_ctx, const threshold_tree_scalar_t secret);

/*
    Feldman verification that each node generated valid shares for children.
*/
threshold_tree_status threshold_tree_verify_group_sharing(threshold_tree_ctx_t *tree_ctx);

// ---------- Authorized Subtree ------------------------------------------------------------------------------------------------------------------------

/*
    Starting from given authorized parties, goes upwards in the tree and marks all authorized nodes (which have threshold authrozized children).
*/
threshold_tree_status threshold_tree_set_authorized_subtree_by_parties(threshold_tree_ctx_t *tree_ctx, threshold_tree_party_t *parties, uint64_t num_parties);

/*
    Checks if last call of threshold_tree_set_authorized_subtree_by_parties resulted in an authorized tree root.
    If so, root's secret can be reconstructed from authrized parties shares (using lagrange coeffs).
    If not, no information about the root's secret can be deduced from authorized parties.
*/
threshold_tree_status threshold_tree_is_tree_authorized(threshold_tree_ctx_t *tree_ctx);

/*
    Computes lagrage coeffs of all nodes in the tree, non-authorized nodes' coefficient is 0.
    Computing make sense only after setting authorized parties in the tree (using threshold_tree_set_authorized_subtree_by_parties).
    Also, lagrange coeffs are defined ony if root is authorized.
    If so, linear combination of authorized parties' secrets with lagrange coeffs equals the secret.
*/
threshold_tree_status threshold_tree_compute_lagrange_coeffs_at_authorized_subtree(threshold_tree_ctx_t *tree_ctx);


#ifdef __cplusplus
}
#endif //__cplusplus

#endif //#ifndef __THRESHOLD_TREE_ACCESS_STRUCTURE_H__