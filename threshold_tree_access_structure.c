#include "threshold_tree_access_structure.h"
#include "verifiable_secret_sharing.h"
#include "secp256k1_algebra.h"

#include <stdlib.h>
#include <string.h>
#include <assert.h>

typedef struct threshold_tree_node threshold_tree_node_t;

struct threshold_tree_node 
{
    uint64_t id;
    uint8_t num_shares;
    uint8_t threshold;
    
    shamir_secret_sharing_scalar_t secret_share;
    secp256k1_point_t group_share;
    secp256k1_point_t *group_polynom_coeffs;

    secp256k1_scalar_t lagrange_coeff;
    uint8_t is_authorized_node;
    uint8_t num_authorized_children;

    threshold_tree_node_t **children;
    threshold_tree_node_t *parent;
};

struct threshold_tree_ctx
{
    threshold_tree_node_t *root;
};

// ---------------------------------------- Error Conversion ----------------------------------------

static threshold_tree_status from_verifiable_secret_sharing_status(verifiable_secret_sharing_status status)
{
    switch (status)
    {
        case VERIFIABLE_SECRET_SHARING_SUCCESS              : return THRESHOLD_TREE_SUCCESS;
        case VERIFIABLE_SECRET_SHARING_UNKNOWN_ERROR        : return THRESHOLD_TREE_UNKNOWN_ERROR;
        case VERIFIABLE_SECRET_SHARING_INVALID_PARAMETER    : return THRESHOLD_TREE_INVALID_PARAMETER;
        case VERIFIABLE_SECRET_SHARING_INVALID_INDEX        : return THRESHOLD_TREE_INVALID_INDEX;
        case VERIFIABLE_SECRET_SHARING_INVALID_SECRET       : return THRESHOLD_TREE_INVALID_SECRET;
        case VERIFIABLE_SECRET_SHARING_INVALID_SHARE        : return THRESHOLD_TREE_INVALID_SHARE;
        case VERIFIABLE_SECRET_SHARING_INVALID_SHARE_ID     : return THRESHOLD_TREE_INVALID_ID;
        case VERIFIABLE_SECRET_SHARING_INSUFFICIENT_BUFFER  : return THRESHOLD_TREE_INSUFFICIENT_BUFFER;
        case VERIFIABLE_SECRET_SHARING_OUT_OF_MEMORY        : return THRESHOLD_TREE_OUT_OF_MEMORY;
        default                                             : return THRESHOLD_TREE_UNKNOWN_ERROR;
    }
}

static threshold_tree_status from_secp256k1_algebra_status(secp256k1_algebra_status status)
{
    switch (status)
    {
        case SECP256K1_ALGEBRA_SUCCESS               : return THRESHOLD_TREE_SUCCESS;
        case SECP256K1_ALGEBRA_UNKNOWN_ERROR         : return THRESHOLD_TREE_UNKNOWN_ERROR;
        case SECP256K1_ALGEBRA_INVALID_PARAMETER     : return THRESHOLD_TREE_INVALID_PARAMETER;
        case SECP256K1_ALGEBRA_INSUFFICIENT_BUFFER   : return THRESHOLD_TREE_INSUFFICIENT_BUFFER;
        case SECP256K1_ALGEBRA_OUT_OF_MEMORY         : return THRESHOLD_TREE_OUT_OF_MEMORY;
        default                                      : return THRESHOLD_TREE_UNKNOWN_ERROR;
    }
}

// ---------------------------------------- Tree Structure ----------------------------------------

#pragma region

threshold_tree_ctx_t *threshold_tree_ctx_new()
{
    threshold_tree_ctx_t *tree_ctx = (threshold_tree_ctx_t *) malloc(sizeof(threshold_tree_ctx_t));

    if (!tree_ctx) return NULL;

    tree_ctx->root = NULL;

    return tree_ctx;
}

static void threshold_tree_free_subtree_impl(threshold_tree_node_t *subtree_root) 
{
    if (subtree_root)
    {
        for (uint8_t i = 0; i < subtree_root->num_shares; ++i)
        {
            threshold_tree_free_subtree_impl(subtree_root->children[i]);
        }
        free(subtree_root->children);

        memset(subtree_root->group_polynom_coeffs, 0, subtree_root->threshold * sizeof(secp256k1_point_t));
        free(subtree_root->group_polynom_coeffs);

        memset(subtree_root->secret_share, 0, sizeof(shamir_secret_sharing_scalar_t));
        memset(subtree_root->group_share, 0, sizeof(secp256k1_point_t));

        memset(subtree_root->lagrange_coeff, 0, sizeof(secp256k1_scalar_t));
        subtree_root->is_authorized_node = 0;
        subtree_root->num_authorized_children = 0;

        subtree_root->id = 0;
        subtree_root->num_shares = 0;
        subtree_root->threshold = 0;

        free(subtree_root);
    }
}

void threshold_tree_ctx_free(threshold_tree_ctx_t *tree_ctx)
{
    if (!tree_ctx) return ;
    threshold_tree_free_subtree_impl(tree_ctx->root);
    free(tree_ctx);
}

static threshold_tree_status threshold_tree_check_complete_subtree_structure_impl(threshold_tree_node_t *subtree)
{
    if (!subtree) return THRESHOLD_TREE_INCOMPLETE_STRUCTURE;

    for (uint8_t i = 0; i < subtree->num_shares; ++i)
    {   
        threshold_tree_node_t *child = subtree->children[i];
        // if (child) if (child->parent != subtree) return THRESHOLD_TREE_UNKNOWN_ERROR;

        if (threshold_tree_check_complete_subtree_structure_impl(child) != THRESHOLD_TREE_SUCCESS) return THRESHOLD_TREE_INCOMPLETE_STRUCTURE;
    }

    return THRESHOLD_TREE_SUCCESS;
}

static threshold_tree_status threshold_tree_check_complete_structure(threshold_tree_ctx_t *tree_ctx)
{
    if (!tree_ctx) return THRESHOLD_TREE_INVALID_PARAMETER;
    return threshold_tree_check_complete_subtree_structure_impl(tree_ctx->root);
}

/* Find nodes with given ids in tree. Assumes tree ids are unique. Given ids can repeat. If found_nodes is null, just counts  */
static uint64_t threshold_tree_get_nodes_by_ids_impl(const threshold_tree_node_t *subtree, const uint64_t *ids, uint64_t num_ids, threshold_tree_node_t **found_nodes)
{
    if (!subtree) return 0;

    uint64_t count_found = 0;

    for (uint64_t i = 0; i < num_ids; ++i)
    {
        if (subtree->id == ids[i])
        {
            if (found_nodes) found_nodes[i] = (threshold_tree_node_t *) subtree;
            ++count_found;
        }
    }

    for (uint8_t i = 0; i < subtree->num_shares; ++i)
    {
        count_found += threshold_tree_get_nodes_by_ids_impl(subtree->children[i], ids, num_ids, found_nodes);
    }

    return count_found;
}

threshold_tree_status threshold_tree_get_parties_by_ids(const threshold_tree_ctx_t *tree_ctx, const uint64_t *ids, uint64_t num_ids, threshold_tree_party_t *parties, uint64_t *count_found)
{
    if (!tree_ctx || !ids) return THRESHOLD_TREE_INVALID_PARAMETER;
    
    if (parties) for (uint64_t i = 0; i < num_ids; ++i) parties[i] = NULL;
        
    uint64_t temp_num_found = threshold_tree_get_nodes_by_ids_impl(tree_ctx->root, ids, num_ids, parties);

    if (count_found) *count_found = temp_num_found;

    if (temp_num_found == num_ids)
        return THRESHOLD_TREE_SUCCESS;
    else
        return THRESHOLD_TREE_MISSING_ID;
}

threshold_tree_status threshold_tree_get_single_party_by_id(const threshold_tree_ctx_t *tree_ctx, uint64_t id, threshold_tree_party_t *player)
{
    uint64_t id_arr[1] = {id};
    return threshold_tree_get_parties_by_ids(tree_ctx, id_arr, 1, player, NULL);
}

threshold_tree_status threshold_tree_add_new_child(threshold_tree_ctx_t *tree_ctx, threshold_tree_party_t parent, uint8_t child_index, uint64_t child_id, uint8_t child_num_shares, uint8_t child_threshold, threshold_tree_party_t *new_child)
{
    threshold_tree_status ret_status = THRESHOLD_TREE_OUT_OF_MEMORY;

    if (!tree_ctx
        || ((child_threshold == 0) && (child_num_shares > 0) ) 
        || (child_threshold > child_num_shares)
        || (!parent && tree_ctx->root))
        return THRESHOLD_TREE_INVALID_PARAMETER;

    if (child_id == 0 || (threshold_tree_get_single_party_by_id(tree_ctx, child_id, NULL) == THRESHOLD_TREE_SUCCESS)) return THRESHOLD_TREE_INVALID_ID;

    threshold_tree_node_t *new_node = (threshold_tree_node_t *) calloc(1, sizeof(threshold_tree_node_t));
    if (!new_node) goto cleanup;

    if (parent) // non-null, so add non-root node
    { 
        if ((child_index >= parent->num_shares) || (parent->children[child_index]))
        {
            ret_status = THRESHOLD_TREE_INVALID_INDEX;
            goto cleanup;
        }

        parent->children[child_index] = new_node;
    }
    else // parent is null, so add root (check before that root didn't exist)
    {   
        tree_ctx->root = new_node;
    }

    new_node->children = (threshold_tree_node_t **) calloc(child_num_shares, sizeof(threshold_tree_node_t *));
    if (!new_node->children) goto cleanup_node_data;
    
    new_node->group_polynom_coeffs = (secp256k1_point_t *) calloc(child_threshold, sizeof(secp256k1_point_t));
    if (!new_node->group_polynom_coeffs) goto cleanup_node_data;

    new_node->id = child_id;
    new_node->num_shares = child_num_shares;
    new_node->threshold = child_threshold;
    new_node->parent = parent;
    new_node->is_authorized_node = 0;
    new_node->num_authorized_children = 0;

    memset(new_node->secret_share, 0, sizeof(shamir_secret_sharing_scalar_t));
    memset(new_node->group_share, 0, sizeof(secp256k1_point_t));
    memset(new_node->lagrange_coeff, 0, sizeof(secp256k1_scalar_t));

    for (uint8_t i = 0; i < new_node->num_shares; ++i)
    {
        new_node->children[i] = NULL;
    }

    if (new_child) *new_child = new_node;

    return THRESHOLD_TREE_SUCCESS;

cleanup_node_data:
    free(new_node->children);
    free(new_node->group_polynom_coeffs);
cleanup:
    free(new_node);
    return ret_status;
}

#pragma endregion

// ---------------------------------------- Tree Maintenance ----------------------------------------

static void threshold_tree_clear_values_subtree_impl(threshold_tree_node_t *subtree, uint8_t clear_secret, uint8_t clear_authorized_nodes)
{
    if (!subtree) return ;
    
    if (clear_authorized_nodes) 
    {
        subtree->is_authorized_node = 0;
        subtree->num_authorized_children = 0;
    }
    
    if (clear_secret) memset(subtree->secret_share, 0, sizeof(shamir_secret_sharing_scalar_t));    

    for (uint8_t i = 0; i < subtree->num_shares; ++i)
    {
        threshold_tree_clear_values_subtree_impl(subtree->children[i], clear_secret, clear_authorized_nodes);
    }
}

// ---------------------------------------- Secret Sharing ----------------------------------------

#pragma region

static threshold_tree_status threshold_tree_share_secret_subtree_impl(threshold_tree_node_t *subtree)
{
    if (!subtree->num_shares) return THRESHOLD_TREE_SUCCESS;

    threshold_tree_status ret_status = THRESHOLD_TREE_SUCCESS;
    
    verifiable_secret_sharing_t *shares;

    uint64_t *ids = (uint64_t *) calloc(subtree->num_shares, sizeof(uint64_t));
    
    if (!ids) goto cleanup;
    
    for (uint8_t i = 0; i < subtree->num_shares; ++i) {
        memcpy(&ids[i], &subtree->children[i]->id, sizeof(uint64_t));
    }

    ret_status = from_verifiable_secret_sharing_status(
        verifiable_secret_sharing_split_with_custom_ids(subtree->secret_share, sizeof(shamir_secret_sharing_scalar_t), subtree->threshold, subtree->num_shares, ids, &shares));

    free(ids);

    if (ret_status != THRESHOLD_TREE_SUCCESS) goto cleanup;

    ret_status = from_verifiable_secret_sharing_status(
        verifiable_secret_sharing_get_polynom_proofs(shares, subtree->group_polynom_coeffs, subtree->threshold));

    if (ret_status != THRESHOLD_TREE_SUCCESS) goto cleanup;

    shamir_secret_share_t temp_share;

    for (uint8_t i = 0; i < subtree->num_shares; ++i)
    {
        ret_status = from_verifiable_secret_sharing_status(
            verifiable_secret_sharing_get_share_and_proof(shares, i, &temp_share, &subtree->children[i]->group_share));

        if (ret_status != THRESHOLD_TREE_SUCCESS) goto cleanup;

        memcpy(subtree->children[i]->secret_share, temp_share.data, sizeof(shamir_secret_sharing_scalar_t));
    }

    verifiable_secret_sharing_free_shares(shares);
    shares = NULL;

    for (uint8_t i = 0; i < subtree->num_shares; ++i)
    {
        ret_status = threshold_tree_share_secret_subtree_impl(subtree->children[i]);

        if (ret_status != THRESHOLD_TREE_SUCCESS) goto cleanup;
    }

    return THRESHOLD_TREE_SUCCESS;

cleanup:
    free(ids);
    verifiable_secret_sharing_free_shares(shares);
    memset(temp_share.data, 0, sizeof(shamir_secret_sharing_scalar_t));

    return ret_status;
}

threshold_tree_status threshold_tree_share_secret(threshold_tree_ctx_t *tree_ctx, const shamir_secret_sharing_scalar_t secret)
{
    threshold_tree_status ret_status = threshold_tree_check_complete_structure(tree_ctx);

    if (ret_status != THRESHOLD_TREE_SUCCESS) return ret_status;

    memcpy(tree_ctx->root->secret_share, secret, sizeof(shamir_secret_sharing_scalar_t));

    ret_status = threshold_tree_share_secret_subtree_impl(tree_ctx->root);
    
    if (ret_status != THRESHOLD_TREE_SUCCESS) threshold_tree_clear_values_subtree_impl(tree_ctx->root, 1, 0);

    return ret_status;
}

threshold_tree_status threshold_tree_get_parties_secrets(const threshold_tree_ctx_t *tree_ctx, const  threshold_tree_party_t *parties, uint64_t num_parties, shamir_secret_sharing_scalar_t *secrets)
{
    if (!parties || !secrets) return THRESHOLD_TREE_INVALID_PARAMETER;

    for (uint8_t i = 0; i < num_parties; ++i) 
    {
        if (!parties[i]) goto cleanup;

        memcpy(&secrets[i], parties[i]->secret_share, sizeof(shamir_secret_sharing_scalar_t));
    }

    return THRESHOLD_TREE_SUCCESS;
    
cleanup:
    memset(secrets, 0, num_parties * sizeof(shamir_secret_sharing_scalar_t));
    return THRESHOLD_TREE_NULL_POINTER;
}

static threshold_tree_status threshold_tree_verify_subtree_group_shares_impl(threshold_tree_node_t *subtree)
{
    return THRESHOLD_TREE_SUCCESS;
}

threshold_tree_status threshold_tree_verify_group_shares(threshold_tree_ctx_t *tree_ctx)
{
    return THRESHOLD_TREE_SUCCESS;
}

#pragma endregion

// ---------------------------------------- Authorized Subtree ----------------------------------------

static threshold_tree_status threshold_tree_authorize_parents_from_marked_node_impl(threshold_tree_node_t *curr_node)
{
    if (!curr_node) return THRESHOLD_TREE_NULL_POINTER;
    
    if (curr_node->is_authorized_node) return THRESHOLD_TREE_SUCCESS;

    curr_node->is_authorized_node = 1;

    if (!curr_node->parent) return THRESHOLD_TREE_SUCCESS;

    curr_node->parent->num_authorized_children++;

    if (curr_node->parent->num_authorized_children >= curr_node->parent->threshold)
        threshold_tree_authorize_parents_from_marked_node_impl(curr_node->parent);

    return THRESHOLD_TREE_SUCCESS;
}

static threshold_tree_status threshold_tree_mark_authorized_subtree_by_nodes_impl(threshold_tree_ctx_t *tree_ctx, threshold_tree_node_t **nodes, uint64_t num_nodes)
{
    if (!tree_ctx || !nodes) return THRESHOLD_TREE_INVALID_PARAMETER;

    threshold_tree_status ret_status = THRESHOLD_TREE_UNKNOWN_ERROR;

    threshold_tree_clear_values_subtree_impl(tree_ctx->root, 0, 1);

    for (uint64_t i = 0; i < num_nodes; ++i)
    {
        ret_status = threshold_tree_authorize_parents_from_marked_node_impl(nodes[i]);
        if (ret_status != THRESHOLD_TREE_SUCCESS) goto cleanup;
    }

    return THRESHOLD_TREE_SUCCESS;
    
cleanup:
    threshold_tree_clear_values_subtree_impl(tree_ctx->root, 0, 1);
    return ret_status;
}

static threshold_tree_status threshold_tree_compute_children_lagrange_coeffs_impl(threshold_tree_node_t *subtree, secp256k1_algebra_ctx_t *algebra_ctx)
{
    if (!subtree) return THRESHOLD_TREE_UNKNOWN_ERROR;
    
    threshold_tree_status ret_status = THRESHOLD_TREE_OUT_OF_MEMORY;

    uint8_t temp_auth_index = 0;
    uint64_t *authorized_ids = (uint64_t *) calloc(subtree->num_authorized_children, sizeof(uint64_t));
    if (!authorized_ids) goto cleanup;
    
    for (uint8_t i = 0; i < subtree->num_shares; ++i)
    {
        if (subtree->children[i]->is_authorized_node)
        {
            memcpy(&authorized_ids[temp_auth_index++], &subtree->children[i]->id, sizeof(uint64_t));
        }
    }

    temp_auth_index = 0;
    for (uint8_t i = 0; i < subtree->num_shares; ++i)
    {
        if (subtree->children[i]->is_authorized_node)
        {
            ret_status = from_secp256k1_algebra_status(
                secp256k1_algebra_lagrange_interpolate_ids_at_value(algebra_ctx, authorized_ids, subtree->num_authorized_children, temp_auth_index++, 0, subtree->lagrange_coeff, subtree->children[i]->lagrange_coeff));
        }
        else
        {
            ret_status = from_secp256k1_algebra_status(
                secp256k1_algebra_scalar_from_ul(algebra_ctx, 0, subtree->children[i]->lagrange_coeff));        
        }

        if (ret_status != THRESHOLD_TREE_SUCCESS) goto cleanup;
        
        ret_status = threshold_tree_compute_children_lagrange_coeffs_impl(subtree->children[i], algebra_ctx);
        if (ret_status != THRESHOLD_TREE_SUCCESS) goto cleanup;
    }

    ret_status = THRESHOLD_TREE_SUCCESS;

cleanup:
    free(authorized_ids);
    return ret_status;
}

static threshold_tree_status threshold_tree_compute_lagrange_coeffs_at_authorized_subtree_impl(threshold_tree_ctx_t *tree_ctx)
{
    if (!tree_ctx) return THRESHOLD_TREE_INVALID_PARAMETER;

    threshold_tree_status ret_status = THRESHOLD_TREE_UNKNOWN_ERROR;

    secp256k1_algebra_ctx_t *algebra_ctx = secp256k1_algebra_ctx_new();
    if (!algebra_ctx) return THRESHOLD_TREE_OUT_OF_MEMORY;

    unsigned long root_coeff = 0;
    if (tree_ctx->root->is_authorized_node) root_coeff = 1;

    ret_status = from_secp256k1_algebra_status(
        secp256k1_algebra_scalar_from_ul(algebra_ctx, root_coeff, tree_ctx->root->lagrange_coeff));
    if (ret_status != THRESHOLD_TREE_SUCCESS) goto cleanup;

    ret_status = threshold_tree_compute_children_lagrange_coeffs_impl(tree_ctx->root, algebra_ctx);
    if (ret_status != THRESHOLD_TREE_SUCCESS) goto cleanup;

    ret_status = THRESHOLD_TREE_SUCCESS;

cleanup:
    secp256k1_algebra_ctx_free(algebra_ctx);
    return ret_status;
}

threshold_tree_status threshold_tree_set_authorized_parties(threshold_tree_ctx_t *tree_ctx, threshold_tree_party_t *auth_parties, uint64_t num_parties)
{
    threshold_tree_status ret_status;
    
    ret_status = threshold_tree_check_complete_structure(tree_ctx);
    if (ret_status != THRESHOLD_TREE_SUCCESS) goto cleanup;

    ret_status = threshold_tree_mark_authorized_subtree_by_nodes_impl(tree_ctx, auth_parties, num_parties);
    if (ret_status != THRESHOLD_TREE_SUCCESS) goto cleanup;

    ret_status = threshold_tree_compute_lagrange_coeffs_at_authorized_subtree_impl(tree_ctx);
    if (ret_status != THRESHOLD_TREE_SUCCESS) goto cleanup;

cleanup:
    return ret_status;
}