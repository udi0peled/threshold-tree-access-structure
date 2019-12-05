Test_Name := test
Play_Name := playground

App_C_Flags := -g -O0 -Wall -Wextra -Wvla -I.
App_Cpp_Flags := $(App_C_Flags) -std=c++14
App_Link_Flags := -lcrypto

all: $(Play_Name)

test_threhsold_tree.o: test_threshold_tree.cpp
	@$(CXX) $(App_Cpp_Flags) -c $< -o $@
	@echo "CXX  <=  $<"

playground.o: playground.c threshold_tree_access_structure.c
	@$(CC) $(App_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"

threshold_tree_access_structure.o: threshold_tree_access_structure.c
	@$(CC) $(App_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"

verifiable_secret_sharing.o: verifiable_secret_sharing.c
	@$(CC) $(App_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"

secp256k1_algebra.o: secp256k1_algebra.c
	@$(CC) $(App_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"

commitments.o: commitments.c
	@$(CC) $(App_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"

$(Test_Name): test_threhsold_tree.o verifiable_secret_sharing.o secp256k1_algebra.o commitments.o
	@$(CXX) $^ -o $@ $(App_Link_Flags)
	@echo "LINK =>  $@"

$(Play_Name): playground.o verifiable_secret_sharing.o secp256k1_algebra.o commitments.o
	@$(CXX) $^ -o $@ $(App_Link_Flags)
	@echo "LINK =>  $@"

clean:
	@rm -rf $(Test_Name) $(Play_Name) *.o

run:
	./$(Test_Name)