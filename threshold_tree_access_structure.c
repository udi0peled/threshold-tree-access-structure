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

static size_t threshold_tree_get_nodes_by_ids_impl(const threshold_tree_node_t *subtree, uint64_t *ids, size_t num_ids, threshold_tree_node_t **found_nodes)
{
    if (!subtree) return 0;

    size_t count_found = 0;

    for (size_t i = 0; i < num_ids; ++i)
    {
        if (subtree->id == ids[i])
        {
            if (found_nodes) found_nodes[i] = subtree;
            ++count_found;
        }
    }

    for (uint8_t i = 0; i < subtree->num_shares; ++i)
    {
        count_found += threshold_tree_get_nodes_by_ids_impl(subtree->children[i], ids, num_ids, found_nodes);
    }

    return count_found;
}

threshold_tree_status threshold_tree_get_nodes_by_ids(const threshold_tree_ctx_t *tree_ctx, uint64_t *ids, size_t num_ids, threshold_tree_node_t **found_nodes, size_t *num_found)
{
    if (!tree_ctx) return THRESHOLD_TREE_INVALID_CTX;
    if (!ids) return THRESHOLD_TREE_INVALID_PARAMETER;

    if (found_nodes) for (size_t i = 0; i < num_ids; ++i) found_nodes[i] = NULL;
    
    size_t temp_num_found = threshold_tree_get_nodes_by_ids_impl(tree_ctx->root, ids, num_ids, found_nodes);

    if (num_found) *num_found = temp_num_found;

    if (temp_num_found == num_ids)
        return THRESHOLD_TREE_SUCCESS;
    else
        return THRESHOLD_TREE_MISSING_ID;
}

threshold_tree_status threshold_tree_get_single_node_by_id(const threshold_tree_ctx_t *tree_ctx, uint64_t id, threshold_tree_node_t **found_node)
{
    size_t num_found;
    uint64_t id_arr[1] = {id};
    return threshold_tree_get_nodes_by_ids(tree_ctx, id_arr, 1, found_node, &num_found);
}

threshold_tree_status threshold_tree_add_node(threshold_tree_ctx_t *tree_ctx, const uint8_t *node_path, uint8_t node_path_length, uint64_t id, uint8_t num_shares, uint8_t threshold)
{
    if (!tree_ctx) return THRESHOLD_TREE_INVALID_CTX;
    if (( (threshold == 0) && (num_shares > 0) ) || (threshold > num_shares)) return THRESHOLD_TREE_INVALID_THRESHOLD;
    if (threshold_tree_get_single_node_by_id(tree_ctx, id, NULL) == THRESHOLD_TREE_SUCCESS) return THRESHOLD_TREE_INVALID_ID;

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
    new_node->is_authorized_node = 0;
    new_node->num_authorized_children = 0;

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
    free(ids);
    verifiable_secret_sharing_free_shares(shares);
    memset(temp_share.data, 0, sizeof(shamir_secret_sharing_scalar_t));
    // TODO: Add zeroing all secrets in the tree

    return ret_status;
}

threshold_tree_status threshold_tree_share_secret(threshold_tree_ctx_t *tree_ctx, const shamir_secret_sharing_scalar_t secret)
{
    threshold_tree_status ret_status = threshold_tree_check_complete_structure(tree_ctx);

    if (ret_status != THRESHOLD_TREE_SUCCESS) return ret_status;
    
    // TODO: Check all to-be-allocated data, is null now

    memcpy(tree_ctx->root->secret_share, secret, sizeof(shamir_secret_sharing_scalar_t));

    return threshold_tree_share_secret_subtree_impl(tree_ctx->root);
}

// Write secret clearing
// Write veryfication of empty values (group_coeff, group_share, secret_share), to be used before sharing a new secret

static threshold_tree_status threshold_tree_authorize_parents_from_marked_node_impl(threshold_tree_node_t *curr_node)
{
    if (!curr_node) return THRESHOLD_TREE_UNKNOWN_ERROR;
    
    if (curr_node->is_authorized_node) return THRESHOLD_TREE_SUCCESS;

    curr_node->is_authorized_node = 1;

    if (!curr_node->parent) return THRESHOLD_TREE_SUCCESS;

    curr_node->is_authorized_node = 1;
    curr_node->parent->num_authorized_children++;

    if (curr_node->parent->num_authorized_children >= curr_node->parent->threshold)
        threshold_tree_authorize_parents_from_marked_node_impl(curr_node->parent);

    return THRESHOLD_TREE_SUCCESS;
}

threshold_tree_status threshold_tree_mark_authorized_subtree_by_ids(threshold_tree_ctx_t *tree_ctx, uint64_t *ids, size_t num_ids)
{
    threshold_tree_status ret_status = THRESHOLD_TREE_UNKNOWN_ERROR;

    threshold_tree_node_t **ids_nodes = malloc(num_ids * sizeof(threshold_tree_node_t *));
    if (!ids_nodes) return THRESHOLD_TREE_OUT_OF_MEMORY;

    size_t num_found_nodes = 0; 

    threshold_tree_get_nodes_by_ids(tree_ctx, ids, num_ids, ids_nodes, &num_found_nodes);

    if (num_found_nodes != num_ids) goto cleanup_missing_id;
    for (size_t i = 0; i < num_ids; ++i) if (!ids_nodes[i]) goto cleanup_missing_id;

    // TODO clear marking here 

    for (size_t i = 0; i < num_ids; ++i)
    {
        ret_status = threshold_tree_authorize_parents_from_marked_node_impl(ids_nodes[i]);
        if (ret_status != THRESHOLD_TREE_SUCCESS) goto cleanup;
    }

    free(ids_nodes);
    return ret_status;

cleanup_missing_id:
    ret_status = THRESHOLD_TREE_MISSING_ID;
cleanup:
    free(ids_nodes);
    // TODO clear marking here 
    return ret_status;
}

// -------------------------------------------------- Testing Auxiliary Functions --------------------------------------------------

// all_combinations must point to a null pointer (which we be allocated with the num_created combinations)
int generate_all_combinations_impl(uint8_t input_data[], uint8_t data_index, uint8_t data_size, uint8_t combination_size, uint8_t current_combination[], uint8_t current_index, uint8_t **all_combinations, size_t *num_created) 
{ 
    int ret_status = 1;

    // Current cobination is ready, save it 
    if (current_index >= combination_size)
    { 
        size_t combination_byte_size = sizeof(uint8_t) * combination_size;

        uint8_t *temp_alloc = realloc(*all_combinations, (*num_created + 1) * combination_byte_size);
        if (!temp_alloc) goto cleanup;
        *all_combinations = temp_alloc;

        memcpy((*all_combinations) + combination_byte_size * (*num_created) , current_combination, combination_byte_size); 

        *num_created += 1;

        return 0;
    } 

    if (data_index >= data_size) return 0; 

    // Include current input value
    current_combination[current_index] = input_data[data_index]; 

    ret_status = generate_all_combinations_impl(input_data, data_index+1, data_size, combination_size, current_combination, current_index + 1, all_combinations, num_created);
    if (ret_status) goto cleanup;

    // Exclude current input value
    ret_status = generate_all_combinations_impl(input_data, data_index+1, data_size, combination_size, current_combination, current_index, all_combinations, num_created);
    if (ret_status) goto cleanup;

    return 0;

cleanup:
    free(*all_combinations);
    *all_combinations = NULL;
    return ret_status;
}


int get_all_combinations(uint8_t data_size, uint8_t combination_size, uint8_t **all_combinations, size_t *num_combinations) 
{ 
    int ret_status = 1; // default error

    if (!all_combinations) return ret_status;
    if (*all_combinations) return ret_status;

    uint8_t *arr = malloc(data_size * sizeof(uint8_t));
    if (!arr) goto cleanup;

    for (uint8_t i = 0; i < data_size; ++i) arr[i] = i;

    uint8_t *current_combination = malloc(combination_size * sizeof(uint8_t));
    if (!current_combination) goto cleanup;

    *num_combinations = 0;
    
    if (generate_all_combinations_impl(arr, 0, data_size, combination_size, current_combination, 0, all_combinations, num_combinations)) goto cleanup;

    ret_status = 0;

cleanup:
    free(arr);
    free(current_combination);
    
    return ret_status;;
} 
  
static threshold_tree_status test_threshold_tree_verify_all_shares_impl(threshold_tree_node_t *subtree)
{
    if (!subtree) return THRESHOLD_TREE_SUCCESS;
    if (!subtree->num_shares) return THRESHOLD_TREE_SUCCESS;

    threshold_tree_status ret_status = THRESHOLD_TREE_UNKNOWN_ERROR;

    uint8_t reconstructed_secret[sizeof(shamir_secret_sharing_scalar_t)];

    uint8_t *all_indices_combinations = NULL;

    shamir_secret_share_t *current_child_shares = malloc(subtree->num_shares * sizeof(shamir_secret_share_t));
    if (!current_child_shares)
    {
        ret_status = THRESHOLD_TREE_OUT_OF_MEMORY;
        goto cleanup;
    }

    for (uint8_t thr = 1; thr <= subtree->num_shares; ++thr)
    {
        size_t num_of_comb;

        if (get_all_combinations(subtree->num_shares, thr, &all_indices_combinations, &num_of_comb))
        {
            ret_status = THRESHOLD_TREE_OUT_OF_MEMORY;
            goto cleanup;
        }

        for (size_t comb = 0; comb < num_of_comb; ++comb)
        {
            uint8_t *current_indices = all_indices_combinations + (comb * thr * sizeof(uint8_t));

            printf("Checking Reconstruction of ");
            for (uint8_t i = 0; i < thr; ++i) 
            {
                current_child_shares[i].id = subtree->children[current_indices[i]]->id;
                memcpy(current_child_shares[i].data, subtree->children[current_indices[i]]->secret_share, sizeof(shamir_secret_sharing_scalar_t));
                printf("%ld ", current_child_shares[i].id);
            }
            printf("\n");

            ret_status = from_verifiable_secret_sharing_status(
                verifiable_secret_sharing_reconstruct(current_child_shares, thr, reconstructed_secret, sizeof(shamir_secret_sharing_scalar_t), NULL));
            if (ret_status != THRESHOLD_TREE_SUCCESS) goto cleanup;

            if (memcmp(reconstructed_secret, subtree->secret_share, sizeof(shamir_secret_sharing_scalar_t)))
            {
                if (thr < subtree->threshold)
                {
                    printf("Couldn't - GOOD\n");
                }
                else 
                {
                    ret_status = THRESHOLD_TREE_SHARING_INVALID_SHARE;
                    printf("Reconstruction failed!\n");
                    goto cleanup;
                }
            }
            else    // same string
            {
                if (thr < subtree->threshold)
                {
                    ret_status = THRESHOLD_TREE_UNKNOWN_ERROR;
                    printf("Reconstruction success with less than threshold number of shares- VERY WEIRD!\n");
                    goto cleanup;
                }
                else
                {
                    printf("Success!\n");
                }
            }
        }

        free(all_indices_combinations);
        all_indices_combinations = NULL;      
    }
    
    for (uint8_t i = 0; i < subtree->num_shares; ++i) {
        ret_status = test_threshold_tree_verify_all_shares_impl(subtree->children[i]);
        if (ret_status != THRESHOLD_TREE_SUCCESS) goto cleanup;
    }
    
    ret_status = THRESHOLD_TREE_SUCCESS;

cleanup:
    free(all_indices_combinations);
    free(current_child_shares);
    memset(reconstructed_secret, 0, sizeof(shamir_secret_sharing_scalar_t));

    return ret_status;
}

threshold_tree_status test_threshold_tree_verify_all_shares(threshold_tree_ctx_t *tree_ctx)
{
    threshold_tree_status ret_status = threshold_tree_check_complete_structure(tree_ctx);

    if (ret_status != THRESHOLD_TREE_SUCCESS) return ret_status;

    return test_threshold_tree_verify_all_shares_impl(tree_ctx->root);
}

