#include "threshold_tree_access_structure.c"

#include <openssl/bn.h>

#define CATCH_CONFIG_MAIN  
#include "catch.hpp"


TEST_CASE( "create", "[ctx]")
{
    threshold_tree_ctx_t *tree_ctx = threshold_tree_ctx_new();

    REQUIRE(tree_ctx->root == NULL);

    SECTION("lookups on empty tree")
    {
    }

    threshold_tree_ctx_free(tree_ctx);
}

