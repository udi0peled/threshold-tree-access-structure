#include "threshold_tree_access_structure.c"

#include <openssl/bn.h>

#define CATCH_CONFIG_MAIN  
#include "catch.hpp"

TEST_CASE( "create", "[ctx]")
{
    const uint8_t path_e[] = {};
    const uint8_t path_0[] = {0};
    const uint8_t path_1[] = {1};
    const uint8_t path_2[] = {2};
    const uint8_t path_3[] = {3};
    const uint8_t path_0_0[] = {0, 0};
    const uint8_t path_0_1[] = {0, 1};
    const uint8_t path_0_2[] = {0, 2};
    const uint8_t path_1_0[] = {1, 0};
    const uint8_t path_1_1[] = {1, 1};
    const uint8_t path_0_1_0[] = {0, 1, 0};
    const uint8_t path_0_1_0_0[] = {0, 1, 0, 0};
    const uint8_t path_0_1_1[] = {0, 1, 1};

    threshold_tree_ctx_t *tree_ctx = threshold_tree_ctx_new();

    REQUIRE(tree_ctx->root == NULL);

    SECTION("lookups on empty tree")
    {
        threshold_tree_node_t *found_node = NULL;

        REQUIRE(threshold_tree_get_node_by_id(tree_ctx, 5432, NULL) == THRESHOLD_TREE_MISSING_ID);
        REQUIRE(threshold_tree_get_node_by_id(tree_ctx, 5432, &found_node) == THRESHOLD_TREE_MISSING_ID); REQUIRE(found_node == NULL);

        REQUIRE(threshold_tree_get_node_by_path(tree_ctx, path_e, 0, NULL) == THRESHOLD_TREE_INVALID_PATH);
        REQUIRE(threshold_tree_get_node_by_path(tree_ctx, path_0, 1, NULL) == THRESHOLD_TREE_INVALID_PATH);
        REQUIRE(threshold_tree_get_node_by_path(tree_ctx, path_3, 1, NULL) == THRESHOLD_TREE_INVALID_PATH);
        REQUIRE(threshold_tree_get_node_by_path(tree_ctx, path_1_1, 2, NULL) == THRESHOLD_TREE_INVALID_PATH);

        REQUIRE(threshold_tree_get_node_by_path(tree_ctx, path_e, 0, &found_node) == THRESHOLD_TREE_INVALID_PATH);   REQUIRE(found_node == NULL);
        REQUIRE(threshold_tree_get_node_by_path(tree_ctx, path_0, 1, &found_node) == THRESHOLD_TREE_INVALID_PATH);   REQUIRE(found_node == NULL);
        REQUIRE(threshold_tree_get_node_by_path(tree_ctx, path_3, 1, &found_node) == THRESHOLD_TREE_INVALID_PATH);   REQUIRE(found_node == NULL);
        REQUIRE(threshold_tree_get_node_by_path(tree_ctx, path_1_1, 2, &found_node) == THRESHOLD_TREE_INVALID_PATH); REQUIRE(found_node == NULL);

        REQUIRE(threshold_tree_check_complete_structure(NULL) == THRESHOLD_TREE_INVALID_CTX);

        REQUIRE(threshold_tree_check_complete_structure(tree_ctx) == THRESHOLD_TREE_INCOMPLETE_STRUCTURE);
    }

    SECTION("build a tree")
    {
        REQUIRE(threshold_tree_check_complete_structure(tree_ctx) == THRESHOLD_TREE_INCOMPLETE_STRUCTURE);

        REQUIRE(threshold_tree_add_node(tree_ctx, path_0, 1, 99, 2, 1) == THRESHOLD_TREE_INVALID_PATH);
        REQUIRE(threshold_tree_add_node(tree_ctx, path_e, 0, 99, 1, 2) == THRESHOLD_TREE_INVALID_THRESHOLD);
        REQUIRE(threshold_tree_add_node(tree_ctx, path_e, 0, 99, 1, 0) == THRESHOLD_TREE_INVALID_THRESHOLD);
        REQUIRE(threshold_tree_add_node(tree_ctx, path_e, 0, 1, 3, 2) == THRESHOLD_TREE_SUCCESS);
        REQUIRE(threshold_tree_add_node(tree_ctx, path_e, 0, 99, 3, 2) == THRESHOLD_TREE_INVALID_PATH);

        REQUIRE(threshold_tree_check_complete_structure(tree_ctx) == THRESHOLD_TREE_INCOMPLETE_STRUCTURE);
        
        REQUIRE(threshold_tree_add_node(tree_ctx, path_1, 1, 11, 1, 1) == THRESHOLD_TREE_SUCCESS);
        REQUIRE(threshold_tree_add_node(tree_ctx, path_1, 1, 99, 2, 2) == THRESHOLD_TREE_INVALID_PATH);
        REQUIRE(threshold_tree_add_node(tree_ctx, path_1_1, 2, 99, 3, 3) == THRESHOLD_TREE_INVALID_PATH);
        REQUIRE(threshold_tree_add_node(tree_ctx, path_1_0, 2, 110, 0, 0) == THRESHOLD_TREE_SUCCESS);

        REQUIRE(threshold_tree_check_complete_structure(tree_ctx) == THRESHOLD_TREE_INCOMPLETE_STRUCTURE);
        
        REQUIRE(threshold_tree_add_node(tree_ctx, path_0, 1, 10, 2, 2) == THRESHOLD_TREE_SUCCESS);
        REQUIRE(threshold_tree_add_node(tree_ctx, path_0_0, 2, 100, 0, 0) == THRESHOLD_TREE_SUCCESS);
        REQUIRE(threshold_tree_add_node(tree_ctx, path_0_1_0, 3, 99, 0, 0) == THRESHOLD_TREE_INVALID_PATH);
        REQUIRE(threshold_tree_add_node(tree_ctx, path_0_1, 2, 101, 1, 1) == THRESHOLD_TREE_SUCCESS);
        REQUIRE(threshold_tree_add_node(tree_ctx, path_0_2, 2, 99, 0, 0) == THRESHOLD_TREE_INVALID_PATH);

        REQUIRE(threshold_tree_check_complete_structure(tree_ctx) == THRESHOLD_TREE_INCOMPLETE_STRUCTURE);

        REQUIRE(threshold_tree_add_node(tree_ctx, path_0_1_0, 3, 1010, 0, 0) == THRESHOLD_TREE_SUCCESS);
        REQUIRE(threshold_tree_add_node(tree_ctx, path_0_1_0, 3, 99, 0, 0) == THRESHOLD_TREE_INVALID_PATH);
        REQUIRE(threshold_tree_add_node(tree_ctx, path_0_1_1, 3, 99, 0, 0) == THRESHOLD_TREE_INVALID_PATH);
        REQUIRE(threshold_tree_add_node(tree_ctx, path_0_1_0_0, 4, 99, 0, 0) == THRESHOLD_TREE_INVALID_PATH);

        REQUIRE(threshold_tree_check_complete_structure(tree_ctx) == THRESHOLD_TREE_INCOMPLETE_STRUCTURE);
        
        REQUIRE(threshold_tree_add_node(tree_ctx, path_2, 1, 101, 0, 0) == THRESHOLD_TREE_INVALID_ID);
        REQUIRE(threshold_tree_add_node(tree_ctx, path_2, 1, 12, 0, 0) == THRESHOLD_TREE_SUCCESS);

        REQUIRE(threshold_tree_check_complete_structure(tree_ctx) == THRESHOLD_TREE_SUCCESS);

        REQUIRE(threshold_tree_add_node(tree_ctx, path_3, 1, 99, 0, 0) == THRESHOLD_TREE_INVALID_PATH);

        REQUIRE(threshold_tree_check_complete_structure(tree_ctx) == THRESHOLD_TREE_SUCCESS);

        SECTION("lookup in built tree")
        {
            threshold_tree_node_t *found_node = NULL;

            REQUIRE(threshold_tree_get_node_by_id(tree_ctx, 0, &found_node) == THRESHOLD_TREE_MISSING_ID);
            REQUIRE(found_node == NULL);

            REQUIRE(threshold_tree_get_node_by_id(tree_ctx, 1, &found_node) == THRESHOLD_TREE_SUCCESS);
            REQUIRE(found_node != NULL);
            REQUIRE(found_node->num_shares == 3);

            REQUIRE(threshold_tree_get_node_by_id(tree_ctx, 12, &found_node) == THRESHOLD_TREE_SUCCESS);
            REQUIRE(found_node != NULL);
            REQUIRE(found_node->num_shares == 0);

            REQUIRE(threshold_tree_get_node_by_id(tree_ctx, 13, &found_node) == THRESHOLD_TREE_MISSING_ID);
            REQUIRE(found_node == NULL);

            REQUIRE(threshold_tree_get_node_by_id(tree_ctx, 10, &found_node) == THRESHOLD_TREE_SUCCESS);
            REQUIRE(found_node != NULL);
            REQUIRE(found_node->num_shares == 2);

            REQUIRE(threshold_tree_get_node_by_id(tree_ctx, 101, &found_node) == THRESHOLD_TREE_SUCCESS);
            REQUIRE(found_node != NULL);
            REQUIRE(found_node->num_shares == 1);

            REQUIRE(threshold_tree_get_node_by_id(tree_ctx, 1011, &found_node) == THRESHOLD_TREE_MISSING_ID);
            REQUIRE(found_node == NULL);

            REQUIRE(threshold_tree_get_node_by_path(tree_ctx, path_e, 0, &found_node) == THRESHOLD_TREE_SUCCESS);
            REQUIRE(found_node != NULL);
            REQUIRE(found_node->id == 1);

            REQUIRE(threshold_tree_get_node_by_path(tree_ctx, path_0, 1, &found_node) == THRESHOLD_TREE_SUCCESS);
            REQUIRE(found_node != NULL);
            REQUIRE(found_node->id == 10);

            REQUIRE(threshold_tree_get_node_by_path(tree_ctx, path_1, 1, &found_node) == THRESHOLD_TREE_SUCCESS);
            REQUIRE(found_node != NULL);
            REQUIRE(found_node->id == 11);
            
            REQUIRE(threshold_tree_get_node_by_path(tree_ctx, path_0_1_0, 3, &found_node) == THRESHOLD_TREE_SUCCESS);
            REQUIRE(found_node != NULL);
            REQUIRE(found_node->id == 1010);

            REQUIRE(threshold_tree_get_node_by_path(tree_ctx, path_0_1_0_0, 4, &found_node) == THRESHOLD_TREE_INVALID_PATH);
            REQUIRE(found_node == NULL);

            REQUIRE(threshold_tree_get_node_by_path(tree_ctx, path_0_1_1, 3, &found_node) == THRESHOLD_TREE_INVALID_PATH);
            REQUIRE(found_node == NULL);
        }
    }

    threshold_tree_ctx_free(tree_ctx);
}

