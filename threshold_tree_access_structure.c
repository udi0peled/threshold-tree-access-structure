#include "threshold_tree_access_structure.h"
#include "secp256k1_algebra.h"
#include "verifiable_secret_sharing.h"

#include <string.h>
#include <assert.h>

typedef struct threshold_tree_node threshold_tree_node_t;

struct threshold_tree_node 
{
    uint8_t num_shares;
    uint8_t threshold;
    
    uint64_t *children_ids;
    struct threshold_tree_node_t **children;
    struct threshold_tree_node_t *parent;
    uint8_t is_authorized_subtree;
};

struct threshold_tree_ctx
{
    threshold_tree_node_t *root;
};

// *********************************** Add path definition

// static threshold_tree_status from_secp256k1_algebra_status(secp256k1_algebra_status status)
// {
//     switch (status)
//     {
//         case COMMITMENTS_SUCCESS: return VERIFIABLE_SECRET_SHARING_SUCCESS;
//         case COMMITMENTS_INTERNAL_ERROR: return VERIFIABLE_SECRET_SHARING_UNKNOWN_ERROR;
//         case COMMITMENTS_INVALID_PARAMETER: return VERIFIABLE_SECRET_SHARING_INVALID_PARAMETER;
//         case COMMITMENTS_INVALID_COMMITMENT: return VERIFIABLE_SECRET_SHARING_INVALID_SHARE;
//         default: return VERIFIABLE_SECRET_SHARING_UNKNOWN_ERROR;
//     }
// }

threshold_tree_ctx_t *threshold_tree_ctx_new(uint8_t num_shares, uint8_t threshold, uint64_t *ids)
{
    threshold_tree_ctx_t *tree_ctx = malloc(sizeof(threshold_tree_ctx_t));

    if (!tree_ctx) goto cleanup_tree_ctx;

    tree_ctx->root = malloc(sizeof(threshold_tree_node_t));

    if (!tree_ctx->root) goto cleanup_tree_ctx_root;

    tree_ctx->root->children = calloc(num_shares, sizeof(threshold_tree_node_t*));

    if (!tree_ctx->root->children) goto cleanup_tree_ctx_root_children;

    for (int i = 0; i < num_shares; ++i)
    {
        tree_ctx->root->children[i] = NULL;
    }

    tree_ctx->root->children_ids = calloc(num_shares, sizeof(uint64_t));

    if (!tree_ctx->root->children_ids) goto cleanup_tree_ctx_root_children_ids;

    memcpy(tree_ctx->root->children_ids, ids, sizeof(uint64_t) * num_shares);

    tree_ctx->root->num_shares = num_shares;
    tree_ctx->root->threshold = threshold;
    
    tree_ctx->root->parent = NULL;
    tree_ctx->root->is_authorized_subtree = 0;

    return tree_ctx;

cleanup_tree_ctx_root_children_ids:
    free(tree_ctx->root->children);
cleanup_tree_ctx_root_children:
    free(tree_ctx->root);
cleanup_tree_ctx_root:
    free(tree_ctx);
cleanup_tree_ctx:
    return NULL;
}

void threshold_tree_free_subtree(threshold_tree_node_t *subtree_root) 
{
    
}

void threshold_tree_ctx_free(threshold_tree_ctx_t *tree_ctx)
{
    if (tree_ctx)
    {
        secp256k1_algebra_ctx_free(tree_ctx->secp256k1_ctx);
        free(tree_ctx);
    }
}

int main () {
    
}