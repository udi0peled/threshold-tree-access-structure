#include <stdio.h>
#include <assert.h>
#include <inttypes.h>

#include "threshold_tree_access_structure.c"

// -------------------------------------------------- Printing --------------------------------------------------

#pragma region

const char PRINT_INDENT_STR[] = "-->";
const char PRINT_NULL_POINTER[] = "<>";
uint8_t print_max_height = 5;

void printHexBytes(const unsigned char *src, unsigned int len, const char * prefix, const char * suffix) {
  if (len == 0) {
    printf("%s <0 len char array> %s", prefix, suffix);
    return;
  }

  printf("%s", prefix);
  unsigned int i;
  for (i = 0; i < len-1; ++i) {
    printf("%02x",src[i] & 0xff);
  }
  printf("%02x%s",src[i] & 0xff, suffix);
}

void print_subtree_impl(threshold_tree_node_t *root, uint8_t num_indent)
{
  
  for (uint8_t i = 0; i < num_indent; ++i) printf(PRINT_INDENT_STR);
  for (uint8_t i = num_indent; i < print_max_height; ++i) printf("%*s", (int) sizeof(PRINT_INDENT_STR) -1, "");

  if (!root)
  {
    printf("%s\n", PRINT_NULL_POINTER);
  }
  else
  {
    printf("id: %-10lu%u/%u/%u  %s  ", root->id, root->num_authorized_children, root->threshold, root->num_shares, root->is_authorized_node ? "X" : " ");
    printHexBytes(root->secret_share, sizeof(shamir_secret_sharing_scalar_t), "secret: ", "\n");

    for (uint8_t i = 0; i < root->num_shares; ++i) print_subtree_impl(root->children[i], num_indent + 1);
  }
}

void print_threshold_tree(const threshold_tree_ctx_t *tree_ctx, const char *title, const char* suffix)
{
  printf("%s\n", title);
  print_subtree_impl(tree_ctx->root, 0);
  printf("%s", suffix);
}

#pragma endregion

#define REQUIRE(x) assert(x)

const uint8_t *path_e = NULL;
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
const uint8_t path_0_1_1[] = {0, 1, 1};
const uint8_t path_0_1_0_0[] = {0, 1, 0, 0};

void empty_tree_lookup(threshold_tree_ctx_t *tree_ctx)
{
  threshold_tree_node_t *found_node = NULL;

  REQUIRE(threshold_tree_check_complete_structure(tree_ctx) == THRESHOLD_TREE_INCOMPLETE_STRUCTURE);

  REQUIRE(threshold_tree_get_single_node_by_id(tree_ctx, 5432, NULL) == THRESHOLD_TREE_MISSING_ID);
  REQUIRE(threshold_tree_get_single_node_by_id(tree_ctx, 5432, &found_node) == THRESHOLD_TREE_MISSING_ID); REQUIRE(found_node == NULL);

  REQUIRE(threshold_tree_get_node_by_path(tree_ctx, path_e, 0, NULL) == THRESHOLD_TREE_INVALID_PATH);
  REQUIRE(threshold_tree_get_node_by_path(tree_ctx, path_0, 1, NULL) == THRESHOLD_TREE_INVALID_PATH);
  REQUIRE(threshold_tree_get_node_by_path(tree_ctx, path_3, 1, NULL) == THRESHOLD_TREE_INVALID_PATH);
  REQUIRE(threshold_tree_get_node_by_path(tree_ctx, path_1_1, 2, NULL) == THRESHOLD_TREE_INVALID_PATH);

  REQUIRE(threshold_tree_get_node_by_path(tree_ctx, path_e, 0, &found_node) == THRESHOLD_TREE_INVALID_PATH);   REQUIRE(found_node == NULL);
  REQUIRE(threshold_tree_get_node_by_path(tree_ctx, path_0, 1, &found_node) == THRESHOLD_TREE_INVALID_PATH);   REQUIRE(found_node == NULL);
  REQUIRE(threshold_tree_get_node_by_path(tree_ctx, path_3, 1, &found_node) == THRESHOLD_TREE_INVALID_PATH);   REQUIRE(found_node == NULL);
  REQUIRE(threshold_tree_get_node_by_path(tree_ctx, path_1_1, 2, &found_node) == THRESHOLD_TREE_INVALID_PATH); REQUIRE(found_node == NULL);

  REQUIRE(threshold_tree_check_complete_structure(tree_ctx) == THRESHOLD_TREE_SUCCESS);
}

void build_a_tree(threshold_tree_ctx_t *tree_ctx) {
  REQUIRE(threshold_tree_add_node(tree_ctx, path_0, 1, 99, 2, 1) == THRESHOLD_TREE_INVALID_PATH);
  
  REQUIRE(threshold_tree_check_complete_structure(tree_ctx) == THRESHOLD_TREE_INCOMPLETE_STRUCTURE);

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
}

void lookup_in_built_tree(threshold_tree_ctx_t *tree_ctx)
{
  threshold_tree_node_t *found_node = NULL;

  REQUIRE(threshold_tree_get_single_node_by_id(tree_ctx, 0, &found_node) == THRESHOLD_TREE_MISSING_ID);
  REQUIRE(found_node == NULL);

  REQUIRE(threshold_tree_get_single_node_by_id(tree_ctx, 1, &found_node) == THRESHOLD_TREE_SUCCESS);
  REQUIRE(found_node != NULL);
  REQUIRE(found_node->num_shares == 3);

  REQUIRE(threshold_tree_get_single_node_by_id(tree_ctx, 12, &found_node) == THRESHOLD_TREE_SUCCESS);
  REQUIRE(found_node != NULL);
  REQUIRE(found_node->num_shares == 0);

  REQUIRE(threshold_tree_get_single_node_by_id(tree_ctx, 13, &found_node) == THRESHOLD_TREE_MISSING_ID);
  REQUIRE(found_node == NULL);

  REQUIRE(threshold_tree_get_single_node_by_id(tree_ctx, 10, &found_node) == THRESHOLD_TREE_SUCCESS);
  REQUIRE(found_node != NULL);
  REQUIRE(found_node->num_shares == 2);

  REQUIRE(threshold_tree_get_single_node_by_id(tree_ctx, 101, &found_node) == THRESHOLD_TREE_SUCCESS);
  REQUIRE(found_node != NULL);
  REQUIRE(found_node->num_shares == 1);

  REQUIRE(threshold_tree_get_single_node_by_id(tree_ctx, 1011, &found_node) == THRESHOLD_TREE_MISSING_ID);
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

void share_secret(threshold_tree_ctx_t *tree_ctx, const shamir_secret_sharing_scalar_t secret) {
  REQUIRE(threshold_tree_share_secret(tree_ctx, secret) == THRESHOLD_TREE_SUCCESS);
}

// TODO: Add tests for get_nodes by ids

int main() {

  const unsigned char secret[33] = "01234567890123456789012345678912";

  threshold_tree_ctx_t *arbitrary_tree_ctx = NULL;

  REQUIRE(threshold_tree_get_single_node_by_id(NULL, 5432, NULL) == THRESHOLD_TREE_INVALID_CTX);
  
  arbitrary_tree_ctx = threshold_tree_ctx_new();

  print_threshold_tree(arbitrary_tree_ctx, "Empty Tree:", "------------\n");

  build_a_tree(arbitrary_tree_ctx);

  print_threshold_tree(arbitrary_tree_ctx, "After Built:", "\n");

  lookup_in_built_tree(arbitrary_tree_ctx);

  share_secret(arbitrary_tree_ctx, secret);

  print_threshold_tree(arbitrary_tree_ctx, "Arbitrary After Secret Shared:", "\n");

  //REQUIRE(test_threshold_tree_verify_all_shares(arbitrary_tree_ctx) == THRESHOLD_TREE_SUCCESS);

  uint64_t ids[] = {1010, 1010, 12, 100};
  threshold_tree_mark_authorized_subtree_by_ids(arbitrary_tree_ctx, ids, 2);

  print_threshold_tree(arbitrary_tree_ctx, "Arbitrary After Secret Shared:", "\n");

  threshold_tree_ctx_free(arbitrary_tree_ctx);

  threshold_tree_ctx_t *one_level_tree_ctx = threshold_tree_ctx_new();

  threshold_tree_add_node(one_level_tree_ctx, path_e, 0, 1, 4, 3);
  threshold_tree_add_node(one_level_tree_ctx, path_0, 1, 10, 0, 0);
  threshold_tree_add_node(one_level_tree_ctx, path_1, 1, 11, 0, 0);
  threshold_tree_add_node(one_level_tree_ctx, path_2, 1, 12, 0, 0);
  threshold_tree_add_node(one_level_tree_ctx, path_3, 1, 13, 0, 0);

  share_secret(one_level_tree_ctx, secret);

  print_threshold_tree(one_level_tree_ctx, "One Level After Secret Shared:", "\n");

  //REQUIRE(test_threshold_tree_verify_all_shares(one_level_tree_ctx) == THRESHOLD_TREE_SUCCESS);

  threshold_tree_compute_lagrange_coeffs_at_authorized_nodes(one_level_tree_ctx);
  
  threshold_tree_ctx_free(one_level_tree_ctx);
}