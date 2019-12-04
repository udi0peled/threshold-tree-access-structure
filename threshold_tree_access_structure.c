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
    uint8_t is_authorized_subtree;

    threshold_tree_node_t **children;
    threshold_tree_node_t *parent;
};

struct threshold_tree_ctx
{
    threshold_tree_node_t *root;
};

static threshold_tree_status from_verifiable_secret_sharing_status(verifiable_secret_sharing_status status)
{
    switch (status)
    {
        case VERIFIABLE_SECRET_SHARING_SUCCESS:              return THRESHOLD_TREE_SUCCESS;
        case VERIFIABLE_SECRET_SHARING_UNKNOWN_ERROR:        return THRESHOLD_TREE_UNKNOWN_ERROR;
        case VERIFIABLE_SECRET_SHARING_INVALID_PARAMETER:    return THRESHOLD_TREE_INVALID_PARAMETER;
        case VERIFIABLE_SECRET_SHARING_INVALID_INDEX:        return THRESHOLD_TREE_SHARING_INVALID_INDEX;
        case VERIFIABLE_SECRET_SHARING_INVALID_SECRET:       return THRESHOLD_TREE_SHARING_INVALID_SECRET;
        case VERIFIABLE_SECRET_SHARING_INVALID_SHARE:        return THRESHOLD_TREE_SHARING_INVALID_SHARE;
        case VERIFIABLE_SECRET_SHARING_INVALID_SHARE_ID:     return THRESHOLD_TREE_INVALID_ID;
        case VERIFIABLE_SECRET_SHARING_INSUFFICIENT_BUFFER:  return THRESHOLD_TREE_INSUFFICIENT_BUFFER;
        case VERIFIABLE_SECRET_SHARING_OUT_OF_MEMORY:        return THRESHOLD_TREE_OUT_OF_MEMORY;
        default:                                             return THRESHOLD_TREE_UNKNOWN_ERROR;
    }
}

// -------------------------------------------------- Tree Structure --------------------------------------------------

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
        subtree_root->is_authorized_subtree = 0;

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
        // if (child)
        // {
        //     if (child->parent != subtree) return THRESHOLD_TREE_UNKNOWN_ERROR;
        // }

        if (threshold_tree_check_complete_subtree_structure_impl(child) != THRESHOLD_TREE_SUCCESS) return THRESHOLD_TREE_INCOMPLETE_STRUCTURE;
    }

    return THRESHOLD_TREE_SUCCESS;
}

threshold_tree_status threshold_tree_check_complete_structure(threshold_tree_ctx_t *tree_ctx)
{
    if (!tree_ctx) return THRESHOLD_TREE_INVALID_CTX;
    return threshold_tree_check_complete_subtree_structure_impl(tree_ctx->root);
}

static threshold_tree_status threshold_tree_get_node_by_path_impl(const threshold_tree_node_t *current_node, const uint8_t *node_path, uint8_t node_path_length, threshold_tree_node_t **found_node)
{
    while (node_path_length > 0)
    {
        if (!current_node) return THRESHOLD_TREE_INVALID_PATH;

        if (*node_path >= current_node->num_shares) return THRESHOLD_TREE_INVALID_PATH;

        current_node = current_node->children[*node_path];
        ++node_path;
        --node_path_length;
    }

    if (!current_node) return THRESHOLD_TREE_INVALID_PATH;

    *found_node = (threshold_tree_node_t *) current_node;

    return THRESHOLD_TREE_SUCCESS;
}

threshold_tree_status threshold_tree_get_node_by_path(const threshold_tree_ctx_t *tree_ctx, const uint8_t *node_path, uint8_t node_path_length, threshold_tree_node_t **found_node)
{
    if (!tree_ctx) return THRESHOLD_TREE_INVALID_CTX;

    threshold_tree_node_t *temp_found_node = NULL;

    threshold_tree_status ret_status = threshold_tree_get_node_by_path_impl(tree_ctx->root, node_path, node_path_length, &temp_found_node);

    if (found_node) *found_node = temp_found_node;

    return ret_status;
}

static threshold_tree_status threshold_tree_get_node_by_id_impl(threshold_tree_node_t *current_node, uint64_t id, threshold_tree_node_t **found_node)
{
    if (!current_node) return THRESHOLD_TREE_MISSING_ID;

    if (current_node->id == id) 
    {
        *found_node = current_node;
        return THRESHOLD_TREE_SUCCESS;
    }

    for (uint8_t i = 0; i < current_node->num_shares; ++i)
    {
        if (threshold_tree_get_node_by_id_impl(current_node->children[i], id, found_node) == THRESHOLD_TREE_SUCCESS) return THRESHOLD_TREE_SUCCESS;
    }

    return THRESHOLD_TREE_MISSING_ID;
}

threshold_tree_status threshold_tree_get_node_by_id(const threshold_tree_ctx_t *tree_ctx, uint64_t id, threshold_tree_node_t **found_node)
{
    if (!tree_ctx) return THRESHOLD_TREE_INVALID_CTX;
    
    threshold_tree_node_t *temp_found_node = NULL;
    
    threshold_tree_status ret_status = threshold_tree_get_node_by_id_impl(tree_ctx->root, id, &temp_found_node);
    
    if (found_node) *found_node = temp_found_node;
    
    return ret_status;
}

threshold_tree_status threshold_tree_add_node(threshold_tree_ctx_t *tree_ctx, const uint8_t *node_path, uint8_t node_path_length, uint64_t id, uint8_t num_shares, uint8_t threshold)
{
    if (!tree_ctx) return THRESHOLD_TREE_INVALID_CTX;
    if (( (threshold == 0) && (num_shares > 0) ) || (threshold > num_shares)) return THRESHOLD_TREE_INVALID_THRESHOLD;
    if (threshold_tree_get_node_by_id(tree_ctx, id, NULL) == THRESHOLD_TREE_SUCCESS) return THRESHOLD_TREE_INVALID_ID;

    threshold_tree_node_t *parent_node;
    threshold_tree_node_t *new_node = (threshold_tree_node_t *) calloc(1, sizeof(threshold_tree_node_t));

    if (!new_node) return THRESHOLD_TREE_OUT_OF_MEMORY;

    if (node_path_length == 0)
    {
        if (tree_ctx->root) goto cleanup_invalid_path;

        tree_ctx->root = new_node;
        parent_node = NULL;
    }
    else
    {        
        if (threshold_tree_get_node_by_path(tree_ctx, node_path, node_path_length - 1, &parent_node) != THRESHOLD_TREE_SUCCESS) goto cleanup_invalid_path;
        if (node_path[node_path_length - 1] >= parent_node->num_shares) goto cleanup_invalid_path;
        if (parent_node->children[node_path[node_path_length -1]]) goto cleanup_invalid_path;
        
        parent_node->children[node_path[node_path_length - 1]] = new_node;
    }

    new_node->children = (threshold_tree_node_t **) calloc(num_shares, sizeof(threshold_tree_node_t *));
    if (!new_node->children) goto cleanup_new_children;
    
    new_node->group_polynom_coeffs = (secp256k1_point_t *) calloc(threshold, sizeof(secp256k1_point_t));
    if (!new_node->group_polynom_coeffs) goto cleanup_new_coeffs;

    new_node->id = id;
    new_node->num_shares = num_shares;
    new_node->threshold = threshold;
    new_node->parent = parent_node;
    new_node->is_authorized_subtree = 0;

    memset(new_node->secret_share, 0, sizeof(shamir_secret_sharing_scalar_t));
    memset(new_node->group_share, 0, sizeof(secp256k1_point_t));
    memset(new_node->lagrange_coeff, 0, sizeof(secp256k1_scalar_t));

    for (uint8_t i = 0; i < new_node->num_shares; ++i)
    {
        new_node->children[i] = NULL;
    }

    return THRESHOLD_TREE_SUCCESS;

cleanup_new_coeffs:
    free(new_node->children);
cleanup_new_children:
    free(new_node);
    return THRESHOLD_TREE_OUT_OF_MEMORY;

cleanup_invalid_path:
    free(new_node);
    return THRESHOLD_TREE_INVALID_PATH;
}

#pragma endregion

// -------------------------------------------------- Secret Sharing --------------------------------------------------

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
    verifiable_secret_sharing_free_shares(shares);
    free(ids);

    memset(subtree->group_polynom_coeffs, 0, sizeof(secp256k1_point_t) * subtree->threshold);
    memset(temp_share.data, 0, sizeof(shamir_secret_sharing_scalar_t));

    for (uint8_t i = 0; i < subtree->num_shares; ++i)
    {
        memset(subtree->children[i]->secret_share, 0, sizeof(shamir_secret_sharing_scalar_t));
    }

    return ret_status;
}

threshold_tree_status threshold_tree_share_secret(threshold_tree_ctx_t *tree_ctx, const shamir_secret_sharing_scalar_t secret)
{
    threshold_tree_status ret_status = THRESHOLD_TREE_SUCCESS;

    if (!tree_ctx) return THRESHOLD_TREE_INVALID_CTX;

    ret_status = threshold_tree_check_complete_structure(tree_ctx);
    if (ret_status != THRESHOLD_TREE_SUCCESS) return ret_status;
    
    // Check all to-be-allocated data, is null now

    memcpy(tree_ctx->root->secret_share, secret, sizeof(shamir_secret_sharing_scalar_t));

    return threshold_tree_share_secret_subtree_impl(tree_ctx->root);
}

// Use "verifiable_secret_sharing_reconstruct" to check sharing at each node
// Write ecret clearing
// Write veryfication of empty values (group_coeff, group_share, secret_share), to be used before sharing a new secret