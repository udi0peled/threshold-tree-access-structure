#include <stdio.h>
#include <assert.h>
#include <inttypes.h>
#include <stdlib.h>
#include <time.h>

#include "threshold_tree_access_structure.c"

// -------------------------------------------------- Printing --------------------------------------------------

const char PRINT_INDENT_STR[] = "-->";
const char PRINT_NULL_POINTER[] = "***";
uint8_t print_max_height = 10;

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

void print_node_info(threshold_tree_node_t *node)
{
  if (node)
  {
    printHexBytes(node->secret_share, sizeof(shamir_secret_sharing_scalar_t), "secret: ", " ");
    printHexBytes(node->lagrange_coeff, sizeof(secp256k1_scalar_t), "lagrange: ", " ");
    printf("%2u:%-2u/%2u  %s  ",node->num_authorized_children, node->threshold, node->num_shares, node->is_authorized_node ? "X" : " ");
  }
  else
  {
    printf("secret: %*s lagrange: %*s ", 2* (int) sizeof(shamir_secret_sharing_scalar_t), " ", 2 * (int) sizeof(secp256k1_scalar_t), " ");
    printf("%2u:%-2u/%2u  %s  ",0, 0, 0, " ");
  }
}

void print_subtree_impl(threshold_tree_node_t *subtree, uint64_t parent_id, uint8_t parent_space)
{
  print_node_info(subtree);

  printf("%*lu%s", parent_space, parent_id, PRINT_INDENT_STR);
  if (subtree)
  {
    printf("%-lu", subtree->id);
  }
  else
  {
    printf("%s", PRINT_NULL_POINTER);
  }
  printf("\n");

  if (subtree)
  {
    uint8_t pad = 0;
    if (subtree->id > 9) {
      if (subtree->id > 99) {
        if (subtree->id > 99) {
          pad = 3;
        } else {
          pad = 2;
        }
      } else {
        pad = 1;
      }
    }

    for (uint8_t i = 0; i < subtree->num_shares; ++i)
    {
      print_subtree_impl(subtree->children[i], subtree->id, pad + parent_space+sizeof(PRINT_INDENT_STR));
    }
  }
}

void print_threshold_tree(const threshold_tree_ctx_t *tree_ctx, const char *title, const char* suffix)
{
  printf("%s\n", title);
  print_subtree_impl(tree_ctx->root, 0, 10);
  printf("%s", suffix);
}

#pragma endregion

#define REQUIRE(x) assert(x)

// ---------------------------------------- Testing Auxiliary Functions ----------------------------------------

#pragma region

// all_combinations must point to a null pointer (which we be allocated with the num_created combinations)
static int generate_all_combinations_impl(uint8_t input_data[], uint8_t data_index, uint8_t data_size, uint8_t combination_size, uint8_t current_combination[], uint8_t current_index, uint8_t **all_combinations, uint64_t *num_created) 
{ 
    int ret_status = 1;

    // Current cobination is ready, save it 
    if (current_index >= combination_size)
    { 
        uint64_t combination_byte_size = sizeof(uint8_t) * combination_size;

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


static int get_all_combinations(uint8_t data_size, uint8_t combination_size, uint8_t **all_combinations, uint64_t *num_combinations) 
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

// ---------------------------------------- Testing Secret Sharing ----------------------------------------

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
        uint64_t num_of_comb;

        if (get_all_combinations(subtree->num_shares, thr, &all_indices_combinations, &num_of_comb))
        {
            ret_status = THRESHOLD_TREE_OUT_OF_MEMORY;
            goto cleanup;
        }

        for (uint64_t comb = 0; comb < num_of_comb; ++comb)
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
    threshold_tree_status ret_status = threshold_tree_is_complete_structure(tree_ctx);

    if (ret_status != THRESHOLD_TREE_SUCCESS) return ret_status;

    return test_threshold_tree_verify_all_shares_impl(tree_ctx->root);
}

// ---------------------------------------- Testing Building Random Tree ----------------------------------------

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

    REQUIRE( threshold_tree_add_new_child(tree_ctx, curr_node, i, *id, num_shares, num_shares+1, &new_child) == THRESHOLD_TREE_INVALID_PARAMETER);
    REQUIRE( threshold_tree_add_new_child(tree_ctx, curr_node, i-1, *id, num_shares, threshold, &new_child) == THRESHOLD_TREE_INVALID_INDEX);
    REQUIRE( threshold_tree_add_new_child(tree_ctx, curr_node, i, *id, 1, 0, &new_child) == THRESHOLD_TREE_INVALID_PARAMETER);

    ret_status = threshold_tree_add_new_child(tree_ctx, curr_node, i, *id, num_shares, threshold, &new_child);

    REQUIRE( threshold_tree_add_new_child(tree_ctx, curr_node, i, *id-1, num_shares, threshold, &new_child) == THRESHOLD_TREE_INVALID_ID);
    
    if (ret_status != THRESHOLD_TREE_SUCCESS) goto cleanup;
    (*id) += 1;

    if (i+1 < curr_node->num_shares) {
      REQUIRE( threshold_tree_is_complete_structure(tree_ctx) == THRESHOLD_TREE_INVALID_TREE_STRUCTURE);
    }

    ret_status = test_threshold_tree_build_random_subtree_impl(tree_ctx, new_child, id, depth_bound - 1, child_bound - 1);
    if (ret_status != THRESHOLD_TREE_SUCCESS) goto cleanup;
  }

cleanup:
  return ret_status;
}

threshold_tree_status test_threshold_tree_build_random_tree(threshold_tree_ctx_t *tree_ctx, unsigned int seed, uint8_t depth_bound, uint8_t child_bound)
{
  threshold_tree_status ret_status = THRESHOLD_TREE_SUCCESS;

  if (!tree_ctx) return THRESHOLD_TREE_INVALID_PARAMETER;
  
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

threshold_tree_status test_secret_reconstruction(threshold_tree_ctx_t *tree_ctx, threshold_tree_party_t *parties, uint64_t num_parties)
{
  secp256k1_algebra_ctx_t *algebra_ctx = secp256k1_algebra_ctx_new();
  threshold_tree_status ret_status = THRESHOLD_TREE_UNKNOWN_ERROR;
  secp256k1_scalar_t curr_weighted_secret;
  secp256k1_scalar_t weighted_sum;

  secp256k1_algebra_scalar_from_ul(algebra_ctx, 0, weighted_sum);

  for (uint64_t i = 0; i < num_parties; ++i)
  {
    ret_status = from_secp256k1_algebra_status(
      secp256k1_algebra_mul_scalars(algebra_ctx, &curr_weighted_secret, parties[i]->secret_share, sizeof(secp256k1_scalar_t), parties[i]->lagrange_coeff, sizeof(secp256k1_scalar_t) ));
    if (ret_status != THRESHOLD_TREE_SUCCESS) goto cleanup;


    ret_status = from_secp256k1_algebra_status(
      secp256k1_algebra_add_scalars(algebra_ctx, &weighted_sum, weighted_sum, sizeof(secp256k1_scalar_t), curr_weighted_secret, sizeof(secp256k1_scalar_t) ));
    if (ret_status != THRESHOLD_TREE_SUCCESS) goto cleanup;
  }

  ret_status = memcmp(tree_ctx->root->secret_share, weighted_sum, sizeof(secp256k1_scalar_t)) ? THRESHOLD_TREE_INVALID_SECRET : THRESHOLD_TREE_SUCCESS;

cleanup:
  secp256k1_algebra_ctx_free(algebra_ctx);
  return ret_status;
}
void test_empty_tree_lookup(threshold_tree_ctx_t *tree_ctx)
{
  threshold_tree_node_t *found_node = NULL;

  REQUIRE(threshold_tree_is_complete_structure(tree_ctx) == THRESHOLD_TREE_INVALID_TREE_STRUCTURE);

  REQUIRE(threshold_tree_get_single_party_by_id(tree_ctx, 5432, NULL) == THRESHOLD_TREE_MISSING_ID);
  REQUIRE(threshold_tree_get_single_party_by_id(tree_ctx, 5432, &found_node) == THRESHOLD_TREE_MISSING_ID); REQUIRE(found_node == NULL);
}

void test_one_level_2o3_tree() {

  REQUIRE(threshold_tree_get_single_party_by_id(NULL, 5432, NULL) == THRESHOLD_TREE_INVALID_PARAMETER);

  threshold_tree_ctx_t *tree_ctx = NULL;  
  tree_ctx = threshold_tree_ctx_new(); REQUIRE(tree_ctx != NULL);

  REQUIRE(threshold_tree_is_complete_structure(tree_ctx) == THRESHOLD_TREE_INVALID_TREE_STRUCTURE);
  print_threshold_tree(tree_ctx, "Empty 2/3 Tree:", "\n");

  threshold_tree_party_t dummy = NULL;

  REQUIRE(threshold_tree_add_new_child(NULL, NULL, 0, 99, 2, 1, &dummy) == THRESHOLD_TREE_INVALID_PARAMETER); REQUIRE(dummy == NULL); 

  REQUIRE(threshold_tree_add_new_child(tree_ctx, NULL, 0, 99, 1, 2, &dummy) == THRESHOLD_TREE_INVALID_PARAMETER); REQUIRE(dummy == NULL);
  REQUIRE(threshold_tree_add_new_child(tree_ctx, NULL, 0, 99, 1, 0, &dummy) == THRESHOLD_TREE_INVALID_PARAMETER); REQUIRE(dummy == NULL);
  
  REQUIRE(threshold_tree_is_complete_structure(tree_ctx) == THRESHOLD_TREE_INVALID_TREE_STRUCTURE);
  print_threshold_tree(tree_ctx, "Empty 2/3 Tree:", "\n");

  threshold_tree_party_t root;
  threshold_tree_party_t level1[3];

  REQUIRE(threshold_tree_add_new_child(tree_ctx, NULL, 0, 1, 3, 2, &root) == THRESHOLD_TREE_SUCCESS);
  REQUIRE(threshold_tree_add_new_child(tree_ctx, NULL, 0, 99, 3, 2, &dummy) == THRESHOLD_TREE_INVALID_PARAMETER); REQUIRE(dummy == NULL);
  
  REQUIRE(threshold_tree_is_complete_structure(tree_ctx) == THRESHOLD_TREE_INVALID_TREE_STRUCTURE);
  print_threshold_tree(tree_ctx, "Root 2/3 :", "\n");

  REQUIRE(threshold_tree_add_new_child(tree_ctx, root, 1, 11, 0, 0, &level1[1]) == THRESHOLD_TREE_SUCCESS);
  REQUIRE(threshold_tree_add_new_child(tree_ctx, root, 1, 99, 0, 0, &dummy) == THRESHOLD_TREE_INVALID_INDEX); REQUIRE(dummy == NULL);

  REQUIRE(threshold_tree_is_complete_structure(tree_ctx) == THRESHOLD_TREE_INVALID_TREE_STRUCTURE);
  print_threshold_tree(tree_ctx, "1 Node 2/3:", "\n");

  REQUIRE(threshold_tree_add_new_child(tree_ctx, root, 2, 11, 0, 0, &dummy) == THRESHOLD_TREE_INVALID_ID); REQUIRE(dummy == NULL);
  REQUIRE(threshold_tree_add_new_child(tree_ctx, root, 3, 99, 0, 0, &dummy) == THRESHOLD_TREE_INVALID_INDEX); REQUIRE(dummy == NULL);
  
  REQUIRE(threshold_tree_is_complete_structure(tree_ctx) == THRESHOLD_TREE_INVALID_TREE_STRUCTURE);
  print_threshold_tree(tree_ctx, "1 Node 2/3:", "\n");
  
  REQUIRE(threshold_tree_add_new_child(tree_ctx, root, 0, 10, 0, 0, &level1[0]) == THRESHOLD_TREE_SUCCESS);
  REQUIRE(threshold_tree_add_new_child(tree_ctx, level1[0], 0, 99, 0, 0, &dummy) == THRESHOLD_TREE_INVALID_INDEX); REQUIRE(dummy == NULL);
  
  REQUIRE(threshold_tree_is_complete_structure(tree_ctx) == THRESHOLD_TREE_INVALID_TREE_STRUCTURE);
  print_threshold_tree(tree_ctx, "1,2 Nodes 2/3", "\n");
  
  REQUIRE(threshold_tree_add_new_child(tree_ctx, root, 0, 10, 0, 0, NULL) == THRESHOLD_TREE_INVALID_ID);
  REQUIRE(threshold_tree_add_new_child(tree_ctx, root, 2, 122, 0, 0, &level1[2]) == THRESHOLD_TREE_SUCCESS);

  REQUIRE(threshold_tree_is_complete_structure(tree_ctx) == THRESHOLD_TREE_SUCCESS);
  print_threshold_tree(tree_ctx, "0,1,2 Nodes 2/3", "\n");

  { // Authorization
    REQUIRE(threshold_tree_set_authorized_subtree_by_parties(tree_ctx, &root, 0) == THRESHOLD_TREE_SUCCESS);
    REQUIRE(threshold_tree_is_tree_authorized(tree_ctx) == THRESHOLD_TREE_UNAUTHORIZED_TREE);
    print_threshold_tree(tree_ctx, "No Authorized ", "\n");

    REQUIRE(threshold_tree_set_authorized_subtree_by_parties(tree_ctx, &root, 1) == THRESHOLD_TREE_SUCCESS);
    REQUIRE(threshold_tree_is_tree_authorized(tree_ctx) == THRESHOLD_TREE_SUCCESS);
    print_threshold_tree(tree_ctx, "Root Authorized ", "\n");

    REQUIRE(threshold_tree_set_authorized_subtree_by_parties(tree_ctx, level1, 3) == THRESHOLD_TREE_SUCCESS);
    REQUIRE(threshold_tree_is_tree_authorized(tree_ctx) == THRESHOLD_TREE_SUCCESS);
    print_threshold_tree(tree_ctx, "1,2,3 Authorized ", "\n");

    REQUIRE(threshold_tree_set_authorized_subtree_by_parties(tree_ctx, level1, 0) == THRESHOLD_TREE_SUCCESS);
    REQUIRE(threshold_tree_is_tree_authorized(tree_ctx) == THRESHOLD_TREE_UNAUTHORIZED_TREE);
    print_threshold_tree(tree_ctx, "No Authorized ", "\n");
    
    REQUIRE(threshold_tree_set_authorized_subtree_by_parties(tree_ctx, level1, 1) == THRESHOLD_TREE_SUCCESS);
    REQUIRE(threshold_tree_is_tree_authorized(tree_ctx) == THRESHOLD_TREE_UNAUTHORIZED_TREE);
    print_threshold_tree(tree_ctx, "0 Authorized ", "\n");

    REQUIRE(threshold_tree_set_authorized_subtree_by_parties(tree_ctx, &level1[1], 1) == THRESHOLD_TREE_SUCCESS);
    REQUIRE(threshold_tree_is_tree_authorized(tree_ctx) == THRESHOLD_TREE_UNAUTHORIZED_TREE);
    print_threshold_tree(tree_ctx, "1 Authorized ", "\n");

    REQUIRE(threshold_tree_set_authorized_subtree_by_parties(tree_ctx, &level1[2], 1) == THRESHOLD_TREE_SUCCESS);
    REQUIRE(threshold_tree_is_tree_authorized(tree_ctx) == THRESHOLD_TREE_UNAUTHORIZED_TREE);
    print_threshold_tree(tree_ctx, "2 Authorized ", "\n");

    REQUIRE(threshold_tree_set_authorized_subtree_by_parties(tree_ctx, level1, 2) == THRESHOLD_TREE_SUCCESS);
    REQUIRE(threshold_tree_is_tree_authorized(tree_ctx) == THRESHOLD_TREE_SUCCESS);
    print_threshold_tree(tree_ctx, "0,1 Authorized ", "\n");

    REQUIRE(threshold_tree_set_authorized_subtree_by_parties(tree_ctx, &level1[1], 2) == THRESHOLD_TREE_SUCCESS);
    REQUIRE(threshold_tree_is_tree_authorized(tree_ctx) == THRESHOLD_TREE_SUCCESS);
    print_threshold_tree(tree_ctx, "1,2 Authorized ", "\n");
  }

  threshold_tree_ctx_free(tree_ctx);
}
void test_bakkt_tree()
{
  threshold_tree_party_t root;
  threshold_tree_party_t level1[3];
  threshold_tree_party_t level2[12];

  threshold_tree_ctx_t *tree_ctx = threshold_tree_ctx_new();

  REQUIRE(threshold_tree_add_new_child(tree_ctx, NULL, 0, 5, 3, 3, &root) == THRESHOLD_TREE_SUCCESS);

  REQUIRE(threshold_tree_add_new_child(tree_ctx, root, 0, 500, 4, 2, &level1[0]) == THRESHOLD_TREE_SUCCESS);
  REQUIRE(threshold_tree_add_new_child(tree_ctx, root, 1, 501, 4, 2, &level1[1]) == THRESHOLD_TREE_SUCCESS);
  REQUIRE(threshold_tree_add_new_child(tree_ctx, root, 2, 502 , 4, 2, &level1[2]) == THRESHOLD_TREE_SUCCESS);
  
  REQUIRE(threshold_tree_add_new_child(tree_ctx, level1[0], 0, 50001, 0, 0, &level2[0]) == THRESHOLD_TREE_SUCCESS);
  REQUIRE(threshold_tree_add_new_child(tree_ctx, level1[0], 1, 50002, 0, 0, &level2[1]) == THRESHOLD_TREE_SUCCESS);
  REQUIRE(threshold_tree_add_new_child(tree_ctx, level1[0], 2, 50003, 0, 0, &level2[2]) == THRESHOLD_TREE_SUCCESS);
  REQUIRE(threshold_tree_add_new_child(tree_ctx, level1[0], 3, 50004, 0, 0, &level2[3]) == THRESHOLD_TREE_SUCCESS);

  REQUIRE(threshold_tree_add_new_child(tree_ctx, level1[1], 0, 50100, 0, 0, &level2[4]) == THRESHOLD_TREE_SUCCESS);
  REQUIRE(threshold_tree_add_new_child(tree_ctx, level1[1], 1, 50101, 0, 0, &level2[5]) == THRESHOLD_TREE_SUCCESS);
  REQUIRE(threshold_tree_add_new_child(tree_ctx, level1[1], 2, 50102, 0, 0, &level2[6]) == THRESHOLD_TREE_SUCCESS);
  REQUIRE(threshold_tree_add_new_child(tree_ctx, level1[1], 3, 50103, 0, 0, &level2[7]) == THRESHOLD_TREE_SUCCESS);

  REQUIRE(threshold_tree_add_new_child(tree_ctx, level1[2], 0, 50200, 0, 0, &level2[8]) == THRESHOLD_TREE_SUCCESS);
  REQUIRE(threshold_tree_add_new_child(tree_ctx, level1[2], 1, 50201, 0, 0, &level2[9]) == THRESHOLD_TREE_SUCCESS);
  REQUIRE(threshold_tree_add_new_child(tree_ctx, level1[2], 2, 50202, 0, 0, &level2[10]) == THRESHOLD_TREE_SUCCESS);
  
  REQUIRE(threshold_tree_is_complete_structure(tree_ctx) == THRESHOLD_TREE_INVALID_TREE_STRUCTURE);
  REQUIRE(threshold_tree_add_new_child(tree_ctx, level1[2], 3, 500, 0, 0, &level2[11]) == THRESHOLD_TREE_INVALID_ID);

  REQUIRE(threshold_tree_add_new_child(tree_ctx, level1[2], 3, 50203, 0, 0, &level2[11]) == THRESHOLD_TREE_SUCCESS);

  REQUIRE(threshold_tree_is_complete_structure(tree_ctx) == THRESHOLD_TREE_SUCCESS);
  
  {
    uint64_t ids[6] = {500, 50100, 50202, 50100, 500, 6};
    threshold_tree_party_t found[6];
    uint64_t num_found;

    REQUIRE(threshold_tree_get_parties_by_ids(NULL, ids, 0, found,  &num_found) == THRESHOLD_TREE_INVALID_PARAMETER);
    REQUIRE(threshold_tree_get_parties_by_ids(tree_ctx, NULL, 1, found,  &num_found) == THRESHOLD_TREE_INVALID_PARAMETER);
    REQUIRE(threshold_tree_get_parties_by_ids(tree_ctx, ids, 0, found,  &num_found) == THRESHOLD_TREE_INVALID_PARAMETER);

    REQUIRE(threshold_tree_get_parties_by_ids(tree_ctx, ids, 1, found,  &num_found) == THRESHOLD_TREE_SUCCESS);
    REQUIRE(num_found == 1);
    REQUIRE(found[0]->id == ids[0]);

    REQUIRE(threshold_tree_get_parties_by_ids(tree_ctx, ids, 5, found,  &num_found) == THRESHOLD_TREE_SUCCESS);
    REQUIRE(num_found == 5);
    REQUIRE(found[1] == found[3]);
    REQUIRE(found[0] == found[4]);
    for (int i = 0; i < 5; ++i) REQUIRE(found[i]->id == ids[i]);

    REQUIRE(threshold_tree_get_parties_by_ids(tree_ctx, &ids[5], 1, found,  &num_found) == THRESHOLD_TREE_MISSING_ID);
    REQUIRE(num_found == 0);
    REQUIRE(found[0] == NULL);

    REQUIRE(threshold_tree_get_parties_by_ids(tree_ctx, ids, 6, found,  &num_found) == THRESHOLD_TREE_MISSING_ID);
    REQUIRE(num_found == 5);
    REQUIRE(found[1] == found[3]);
    REQUIRE(found[0] == found[4]);
    for (int i = 0; i < 5; ++i) REQUIRE(found[i]->id == ids[i]);
    REQUIRE(found[5] == NULL); 
  }

  { // Duplication and serialization

  }

  { // Value Clearing 

  }
  
  { // Secret Sharing
    threshold_tree_scalar_t secret = "01234567890123456789012345678901";

    REQUIRE(threshold_tree_share_secret(tree_ctx, secret) == THRESHOLD_TREE_SUCCESS);
    
    print_threshold_tree(tree_ctx, "Bakkt Tree:", "\n");

    REQUIRE(test_threshold_tree_verify_all_shares(tree_ctx) == THRESHOLD_TREE_SUCCESS);

    threshold_tree_party_t parties[9];

    for (uint64_t i = 0; i < 2; ++i)
    {
      for (uint64_t j = 4; j < 6; ++j)
      {
        for (uint64_t k = 8; k < 10; ++k)
        {
          parties[0] = level2[i];
          parties[1] = level2[i+1];
          parties[2] = level2[i+2];
          parties[3] = level2[j];
          parties[4] = level2[j+2];
          parties[5] = level2[k];
          parties[6] = level2[k+1];
          parties[7] = level2[k+2];
          parties[8] = level2[k+1];
          
          REQUIRE(threshold_tree_set_authorized_subtree_by_parties(tree_ctx, parties, 7) == THRESHOLD_TREE_SUCCESS);
          REQUIRE(threshold_tree_compute_lagrange_coeffs_at_authorized_subtree(tree_ctx) == THRESHOLD_TREE_SUCCESS);
          REQUIRE(test_secret_reconstruction(tree_ctx, parties, 7) == THRESHOLD_TREE_SUCCESS);

          REQUIRE(threshold_tree_set_authorized_subtree_by_parties(tree_ctx, parties, 8) == THRESHOLD_TREE_SUCCESS);
          REQUIRE(threshold_tree_compute_lagrange_coeffs_at_authorized_subtree(tree_ctx) == THRESHOLD_TREE_SUCCESS);
          REQUIRE(test_secret_reconstruction(tree_ctx, parties, 8) == THRESHOLD_TREE_SUCCESS);
        
          REQUIRE(threshold_tree_set_authorized_subtree_by_parties(tree_ctx, parties, 9) == THRESHOLD_TREE_SUCCESS);
          REQUIRE(threshold_tree_compute_lagrange_coeffs_at_authorized_subtree(tree_ctx) == THRESHOLD_TREE_SUCCESS);
          REQUIRE(test_secret_reconstruction(tree_ctx, parties, 9) == THRESHOLD_TREE_INVALID_SECRET);

          REQUIRE(test_secret_reconstruction(tree_ctx, parties, 1) == THRESHOLD_TREE_INVALID_SECRET);
          REQUIRE(test_secret_reconstruction(tree_ctx, parties, 2) == THRESHOLD_TREE_INVALID_SECRET);
          REQUIRE(test_secret_reconstruction(tree_ctx, parties, 3) == THRESHOLD_TREE_INVALID_SECRET);
          REQUIRE(test_secret_reconstruction(tree_ctx, parties, 4) == THRESHOLD_TREE_INVALID_SECRET);
          REQUIRE(test_secret_reconstruction(tree_ctx, parties, 5) == THRESHOLD_TREE_INVALID_SECRET);
          REQUIRE(test_secret_reconstruction(tree_ctx, parties, 6) == THRESHOLD_TREE_INVALID_SECRET);
          
        }
      }
    }

    { // group verification

      threshold_tree_clear_values_subtree_impl(tree_ctx->root, 0x01);
      print_threshold_tree(tree_ctx, "Cleared Secrets:", "\n");
      REQUIRE(threshold_tree_verify_group_sharing(tree_ctx) == THRESHOLD_TREE_SUCCESS);

      threshold_tree_group_point_t tmp_group_el;
      memcpy(tmp_group_el, level2[11]->group_share, sizeof(threshold_tree_group_point_t));

      memset(level2[11]->group_share, 0, sizeof(threshold_tree_group_point_t));
      REQUIRE(threshold_tree_verify_group_sharing(tree_ctx) == THRESHOLD_TREE_INVALID_SHARE);

      memcpy(level2[11]->group_share, level2[10]->group_share, sizeof(threshold_tree_group_point_t));
      REQUIRE(threshold_tree_verify_group_sharing(tree_ctx) == THRESHOLD_TREE_INVALID_SHARE);

      memcpy(level2[10]->group_share, tmp_group_el, sizeof(threshold_tree_group_point_t));
      REQUIRE(threshold_tree_verify_group_sharing(tree_ctx) == THRESHOLD_TREE_INVALID_SHARE);

      memcpy(level2[10]->group_share, level2[11]->group_share, sizeof(threshold_tree_group_point_t));
      memcpy(level2[11]->group_share, tmp_group_el, sizeof(threshold_tree_group_point_t));
      REQUIRE(threshold_tree_verify_group_sharing(tree_ctx) == THRESHOLD_TREE_SUCCESS);

      memcpy(tmp_group_el, level1[2]->group_polynom_coeffs[1], sizeof(threshold_tree_group_point_t));

      memset(level1[2]->group_polynom_coeffs[1], 0, sizeof(threshold_tree_group_point_t));
      REQUIRE(threshold_tree_verify_group_sharing(tree_ctx) == THRESHOLD_TREE_INVALID_SHARE);

      memcpy(level1[2]->group_polynom_coeffs[1], level1[2]->group_polynom_coeffs[0], sizeof(threshold_tree_group_point_t));
      REQUIRE(threshold_tree_verify_group_sharing(tree_ctx) == THRESHOLD_TREE_INVALID_SHARE);

      memcpy(level1[2]->group_polynom_coeffs[0], tmp_group_el, sizeof(threshold_tree_group_point_t));
      REQUIRE(threshold_tree_verify_group_sharing(tree_ctx) == THRESHOLD_TREE_INVALID_SHARE);

      memcpy(level1[2]->group_polynom_coeffs[0], level1[2]->group_polynom_coeffs[1], sizeof(threshold_tree_group_point_t));
      memcpy(level1[2]->group_polynom_coeffs[1], tmp_group_el, sizeof(threshold_tree_group_point_t));

      REQUIRE(threshold_tree_verify_group_sharing(tree_ctx) == THRESHOLD_TREE_SUCCESS);
    }
  }
  { // Authorization and reconstruction

    threshold_tree_party_t parties[14];
  
    parties[0] = root;
    
    parties[1] = level1[0];
    parties[2] = level1[0];
    parties[3] = level1[1];
    parties[4] = level1[2];

    parties[5] = level2[0];
    parties[6] = level2[1];
    parties[7] = level2[0];
    parties[8] = level2[1];
    parties[9] = level2[4];
    parties[10] = level2[5];
    parties[11] = level2[8];
    parties[12] = level2[9];
    parties[13] = root;

    REQUIRE(threshold_tree_set_authorized_subtree_by_parties(tree_ctx, parties, 0) == THRESHOLD_TREE_SUCCESS);
    REQUIRE(threshold_tree_is_tree_authorized(tree_ctx) == THRESHOLD_TREE_UNAUTHORIZED_TREE);

    REQUIRE(threshold_tree_set_authorized_subtree_by_parties(tree_ctx, parties, 1) == THRESHOLD_TREE_SUCCESS);
    REQUIRE(threshold_tree_is_tree_authorized(tree_ctx) == THRESHOLD_TREE_SUCCESS);

    REQUIRE(threshold_tree_set_authorized_subtree_by_parties(tree_ctx, parties, 2) == THRESHOLD_TREE_SUCCESS);
    REQUIRE(threshold_tree_is_tree_authorized(tree_ctx) == THRESHOLD_TREE_SUCCESS);
    
    REQUIRE(threshold_tree_set_authorized_subtree_by_parties(tree_ctx, parties, 3) == THRESHOLD_TREE_SUCCESS);
    REQUIRE(threshold_tree_is_tree_authorized(tree_ctx) == THRESHOLD_TREE_SUCCESS);

    REQUIRE(threshold_tree_set_authorized_subtree_by_parties(tree_ctx, &parties[1], 3) == THRESHOLD_TREE_SUCCESS);
    REQUIRE(threshold_tree_is_tree_authorized(tree_ctx) == THRESHOLD_TREE_UNAUTHORIZED_TREE);

    REQUIRE(threshold_tree_set_authorized_subtree_by_parties(tree_ctx, &parties[2], 2) == THRESHOLD_TREE_SUCCESS);
    REQUIRE(threshold_tree_is_tree_authorized(tree_ctx) == THRESHOLD_TREE_UNAUTHORIZED_TREE);
    
    REQUIRE(threshold_tree_set_authorized_subtree_by_parties(tree_ctx, &parties[3], 2) == THRESHOLD_TREE_SUCCESS);
    REQUIRE(threshold_tree_is_tree_authorized(tree_ctx) == THRESHOLD_TREE_UNAUTHORIZED_TREE);

    REQUIRE(threshold_tree_set_authorized_subtree_by_parties(tree_ctx, &parties[3], 3) == THRESHOLD_TREE_SUCCESS);
    REQUIRE(threshold_tree_is_tree_authorized(tree_ctx) == THRESHOLD_TREE_UNAUTHORIZED_TREE);

    REQUIRE(threshold_tree_set_authorized_subtree_by_parties(tree_ctx, &parties[3], 4) == THRESHOLD_TREE_SUCCESS);
    REQUIRE(threshold_tree_is_tree_authorized(tree_ctx) == THRESHOLD_TREE_SUCCESS);

    REQUIRE(threshold_tree_set_authorized_subtree_by_parties(tree_ctx, &parties[3], 6) == THRESHOLD_TREE_SUCCESS);
    REQUIRE(threshold_tree_is_tree_authorized(tree_ctx) == THRESHOLD_TREE_SUCCESS);

    REQUIRE(threshold_tree_set_authorized_subtree_by_parties(tree_ctx, &parties[7], 5) == THRESHOLD_TREE_SUCCESS);

    REQUIRE(threshold_tree_set_authorized_subtree_by_parties(tree_ctx, &parties[7], 6) == THRESHOLD_TREE_SUCCESS);
    REQUIRE(threshold_tree_is_tree_authorized(tree_ctx) == THRESHOLD_TREE_SUCCESS);

    REQUIRE(threshold_tree_set_authorized_subtree_by_parties(tree_ctx, &parties[7], 7) == THRESHOLD_TREE_SUCCESS);
    REQUIRE(threshold_tree_is_tree_authorized(tree_ctx) == THRESHOLD_TREE_SUCCESS);
  }

  threshold_tree_ctx_free(tree_ctx);
}

void test_random_tree()
{
  threshold_tree_ctx_t *random_tree_ctx = threshold_tree_ctx_new();

  unsigned int seed = time(0);
  //seed = 1576077298;

  printf("creating random tree with seed: %u\n", seed);

  test_threshold_tree_build_random_tree(random_tree_ctx, seed, 10, 6);

  printf("Seed: %u, ", seed);
  print_threshold_tree(random_tree_ctx, "Random Tree:", "\n");

  threshold_tree_ctx_free(random_tree_ctx);
}

// TODO: Add tests for get_nodes by ids

int main() {

  test_one_level_2o3_tree();

  test_bakkt_tree();
}