#include <stdio.h>
#include <assert.h>
#include <inttypes.h>
#include <stdlib.h>
#include <time.h>

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

// ---------------------------------------- Testing Auxiliary Functions ----------------------------------------

#pragma region

// all_combinations must point to a null pointer (which we be allocated with the num_created combinations)
static int generate_all_combinations_impl(uint8_t input_data[], uint8_t data_index, uint8_t data_size, uint8_t combination_size, uint8_t current_combination[], uint8_t current_index, uint8_t **all_combinations, size_t *num_created) 
{ 
    int ret_status = 1;

    // Current cobination is ready, save it 
    if (current_index >= combination_size)
    { 
        size_t combination_byte_size = sizeof(uint8_t) * combination_size;

        uint8_t *temp_alloc = (uint8_t *) realloc(*all_combinations, (*num_created + 1) * combination_byte_size);
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


static int get_all_combinations(uint8_t data_size, uint8_t combination_size, uint8_t **all_combinations, size_t *num_combinations) 
{ 
    int ret_status = 1; // default error

    if (!all_combinations) return ret_status;
    if (*all_combinations) return ret_status;

    uint8_t *arr = (uint8_t *) malloc(data_size * sizeof(uint8_t));
    if (!arr) goto cleanup;

    for (uint8_t i = 0; i < data_size; ++i) arr[i] = i;

    uint8_t *current_combination = (uint8_t *) malloc(combination_size * sizeof(uint8_t));
    if (!current_combination) goto cleanup;

    *num_combinations = 0;
    
    if (generate_all_combinations_impl(arr, 0, data_size, combination_size, current_combination, 0, all_combinations, num_combinations)) goto cleanup;

    ret_status = 0;

cleanup:
    free(arr);
    free(current_combination);
    
    return ret_status;;
} 
  
static threshold_tree_status test_threshold_tree_verify_all_shares_impl(threshold_tree_party_t subtree)
{
    if (!subtree) return THRESHOLD_TREE_SUCCESS;
    if (!subtree->num_shares) return THRESHOLD_TREE_SUCCESS;

    threshold_tree_status ret_status = THRESHOLD_TREE_UNKNOWN_ERROR;

    uint8_t reconstructed_secret[sizeof(shamir_secret_sharing_scalar_t)];

    uint8_t *all_indices_combinations = NULL;

    shamir_secret_share_t *current_child_shares = (shamir_secret_share_t *) malloc(subtree->num_shares * sizeof(shamir_secret_share_t));
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
                    ret_status = THRESHOLD_TREE_INVALID_SHARE;
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

static threshold_tree_status test_threshold_tree_build_random_subtree_impl(threshold_tree_ctx_t *tree_ctx, threshold_tree_node_t *curr_node, uint64_t *id, uint8_t depth_bound, uint8_t child_bound)
{
  threshold_tree_status ret_status = THRESHOLD_TREE_SUCCESS;

  threshold_tree_node_t *new_child;

  uint8_t num_shares;
  uint8_t threshold;

  for (uint8_t i = 0; i < curr_node->num_shares; ++i)
  {
    if (depth_bound == 0)
    {
      num_shares = 0;
      threshold = 0;
    }
    else
    {
      threshold = 0;
      num_shares = random() % child_bound;
      if (num_shares > 0) threshold = 1 + random() % (num_shares);
    }

    ret_status = threshold_tree_add_new_child(tree_ctx, curr_node, i, *id, num_shares, threshold, &new_child);
    if (ret_status != THRESHOLD_TREE_SUCCESS) goto cleanup;
    (*id) += 1;

    ret_status = test_threshold_tree_build_random_subtree_impl(tree_ctx, new_child, id, depth_bound - 1, child_bound - 1);
    if (ret_status != THRESHOLD_TREE_SUCCESS) goto cleanup;
  }

cleanup:
  return ret_status;
}

threshold_tree_status test_threshold_tree_build_random_tree(threshold_tree_ctx_t *tree_ctx, unsigned int seed, uint8_t depth_bound, uint8_t child_bound)
{
  threshold_tree_status ret_status = THRESHOLD_TREE_SUCCESS;

  if (!tree_ctx) return THRESHOLD_TREE_INVALID_CTX;
  
  srandom(seed);

  uint8_t num_shares;
  uint8_t threshold;
  if (depth_bound == 0)
  {
    num_shares = 0;
    threshold = 0;
  }
  else
  {
    threshold = 0;
    num_shares = random() % child_bound;
    if (num_shares > 0) threshold = 1 + (random() % num_shares);
  }

  uint64_t root_id = 1; 
  ret_status = threshold_tree_add_new_child(tree_ctx, NULL, 0, root_id++, num_shares, threshold, NULL);

  if (ret_status != THRESHOLD_TREE_SUCCESS) goto cleanup;

  ret_status = test_threshold_tree_build_random_subtree_impl(tree_ctx, tree_ctx->root, &root_id, depth_bound-1, child_bound);
  if (ret_status != THRESHOLD_TREE_SUCCESS) goto cleanup;

cleanup:
  return ret_status;
}

#pragma endregion

// ---------------------------------------- Testing Tree ---------------------------------------- 

void empty_tree_lookup(threshold_tree_ctx_t *tree_ctx)
{
  threshold_tree_node_t *found_node = NULL;

  REQUIRE(threshold_tree_check_complete_structure(tree_ctx) == THRESHOLD_TREE_INCOMPLETE_STRUCTURE);

  REQUIRE(threshold_tree_get_single_party_by_id(tree_ctx, 5432, NULL) == THRESHOLD_TREE_MISSING_ID);
  REQUIRE(threshold_tree_get_single_party_by_id(tree_ctx, 5432, &found_node) == THRESHOLD_TREE_MISSING_ID); REQUIRE(found_node == NULL);
}

void build_one_level_tree(threshold_tree_ctx_t *tree_ctx) {

  threshold_tree_party_t dummy = NULL;

  REQUIRE(threshold_tree_add_new_child(NULL, NULL, 0, 99, 2, 1, &dummy) == THRESHOLD_TREE_INVALID_CTX); REQUIRE(dummy == NULL); 
  REQUIRE(threshold_tree_check_complete_structure(tree_ctx) == THRESHOLD_TREE_INCOMPLETE_STRUCTURE);
  REQUIRE(threshold_tree_add_new_child(tree_ctx, NULL, 0, 99, 1, 2, &dummy) == THRESHOLD_TREE_INVALID_PARAMETER); REQUIRE(dummy == NULL);
  REQUIRE(threshold_tree_add_new_child(tree_ctx, NULL, 0, 99, 1, 0, &dummy) == THRESHOLD_TREE_INVALID_PARAMETER); REQUIRE(dummy == NULL);

  threshold_tree_party_t root;
  threshold_tree_party_t level1[3];

  REQUIRE(threshold_tree_add_new_child(tree_ctx, NULL, 0, 1, 3, 2, &root) == THRESHOLD_TREE_SUCCESS);
  REQUIRE(threshold_tree_add_new_child(tree_ctx, NULL, 0, 99, 3, 2, &dummy) == THRESHOLD_TREE_INVALID_PARAMETER); REQUIRE(dummy == NULL);
  REQUIRE(threshold_tree_check_complete_structure(tree_ctx) == THRESHOLD_TREE_INCOMPLETE_STRUCTURE);

  REQUIRE(threshold_tree_add_new_child(tree_ctx, root, 1, 11, 0, 0, &level1[1]) == THRESHOLD_TREE_SUCCESS);
  REQUIRE(threshold_tree_add_new_child(tree_ctx, root, 1, 99, 0, 0, &dummy) == THRESHOLD_TREE_INVALID_INDEX); REQUIRE(dummy == NULL);
  REQUIRE(threshold_tree_add_new_child(tree_ctx, root, 2, 11, 0, 0, &dummy) == THRESHOLD_TREE_INVALID_ID); REQUIRE(dummy == NULL);
  REQUIRE(threshold_tree_add_new_child(tree_ctx, root, 3, 99, 0, 0, &dummy) == THRESHOLD_TREE_INVALID_INDEX); REQUIRE(dummy == NULL);
  REQUIRE(threshold_tree_check_complete_structure(tree_ctx) == THRESHOLD_TREE_INCOMPLETE_STRUCTURE);
  
  REQUIRE(threshold_tree_add_new_child(tree_ctx, root, 0, 10, 0, 0, &level1[0]) == THRESHOLD_TREE_SUCCESS);
  REQUIRE(threshold_tree_add_new_child(tree_ctx, level1[0], 0, 99, 0, 0, &dummy) == THRESHOLD_TREE_INVALID_INDEX); REQUIRE(dummy == NULL);
  REQUIRE(threshold_tree_check_complete_structure(tree_ctx) == THRESHOLD_TREE_INCOMPLETE_STRUCTURE);
  
  REQUIRE(threshold_tree_add_new_child(tree_ctx, root, 0, 10, 0, 0, NULL) == THRESHOLD_TREE_INVALID_ID);
  REQUIRE(threshold_tree_add_new_child(tree_ctx, root, 2, 12, 0, 0, &level1[2]) == THRESHOLD_TREE_SUCCESS);

  REQUIRE(threshold_tree_check_complete_structure(tree_ctx) == THRESHOLD_TREE_SUCCESS);
}

/*
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
}
*/
void share_secret(threshold_tree_ctx_t *tree_ctx, const shamir_secret_sharing_scalar_t secret) {
  REQUIRE(threshold_tree_share_secret(tree_ctx, secret) == THRESHOLD_TREE_SUCCESS);
}

// TODO: Add tests for get_nodes by ids

int main() {

  //const unsigned char secret[33] = "01234567890123456789012345678912";

  threshold_tree_ctx_t *tree_ctx = NULL;

  REQUIRE(threshold_tree_get_single_party_by_id(NULL, 5432, NULL) == THRESHOLD_TREE_INVALID_CTX);
  
  tree_ctx = threshold_tree_ctx_new();

  print_threshold_tree(tree_ctx, "Empty Tree:", "------------\n");

  build_one_level_tree(tree_ctx);

  print_threshold_tree(tree_ctx, "After Built:", "\n");

  //lookup_in_built_tree(arbitrary_tree_ctx);

//  share_secret(arbitrary_tree_ctx, secret);

//  print_threshold_tree(arbitrary_tree_ctx, "Arbitrary After Secret Shared:", "\n");

  //REQUIRE(test_threshold_tree_verify_all_shares(arbitrary_tree_ctx) == THRESHOLD_TREE_SUCCESS);

  uint64_t ids[] = {1010, 1010, 12, 100};
  threshold_tree_mark_authorized_subtree_by_ids(tree_ctx, ids, 2);

  //print_threshold_tree(arbitrary_tree_ctx, "Arbitrary After Secret Shared:", "\n");

  threshold_tree_ctx_free(tree_ctx);

  threshold_tree_ctx_t *random_tree_ctx = threshold_tree_ctx_new();

  unsigned int seed = time(0);

  test_threshold_tree_build_random_tree(random_tree_ctx, seed, 3, 6);

  printf("Seed: %u, ", seed);
  print_threshold_tree(random_tree_ctx, "Random Tree:", "\n");

  threshold_tree_ctx_free(random_tree_ctx);
}