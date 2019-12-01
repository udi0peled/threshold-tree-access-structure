#include "threshold_tree_access_structure.h"

#include <string.h>
#include <assert.h>

typedef struct threshold_tree_node threshold_tree_node_t;

struct threshold_tree_node 
{
    uint8_t num_shares;
    uint8_t threshold;
    
    uint64_t *children_ids;
    struct threshold_tree_node_t *children;
    struct threshold_tree_node_t *parent;

    secp256k1_scalar_t share;
    secp256k1_point_t group_share;
    secp256k1_point_t *group_coefficients;

    uint8_t is_authorized_subtree;
};

struct threshold_tree_ctx
{
    threshold_tree_node_t *root;

    uint8_t tree_height;

    secp256k1_algebra_ctx_t *secp256k1_ctx;
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

threshold_tree_ctx_t *threshold_tree_ctx_new()
{
    threshold_tree_ctx_t *tree_ctx = malloc(sizeof(threshold_tree_ctx_t));

    if (tree_ctx)
    {
        tree_ctx->secp256k1_ctx = secp256k1_algebra_ctx_new();

        if (!tree_ctx->secp256k1_ctx)
        {
            free(tree_ctx);
            return NULL;
        }
    }

    return tree_ctx;
}

void threshold_tree_ctx_free(threshold_tree_ctx_t *tree_ctx)
// free tree recursively {
    if (tree_ctx)
    {
        secp256k1_algebra_ctx_free(tree_ctx->secp256k1_ctx);
        free(tree_ctx);
    }
}

int main () {
    
}