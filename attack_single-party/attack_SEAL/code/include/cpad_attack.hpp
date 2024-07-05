#ifndef _CPAD_ATTACK_H_
#define _CPAD_ATTACK_H_

#include <vector>

#include "seal/seal.h"
#include "seal/plaintext.h"
#include "seal/util/common.h"

#include "../include/print_functions.hpp"

#define DEBUG 0
#define CHECK_FOUND_NOISE 1

#define SECURITY_LEVEL 256//256 //192 //128 by default
#define POLY_MODULUS_DEGREE 4096
#define PLAIN_MODULUS 1024

#ifndef SECURITY_LEVEL
#define SECURITY_LEVEL 256// by default
#endif //SECURITY_LEVEL

using namespace std;
using namespace seal;


/** Functions Prototypes **/

/* Different strategies to find the n linear equations:
 * Strategy 0:
   Find the noise of one coefficient of a ciphertext c0 to get an equation b = <a,s> + |e| of this LWE coefficient. Search n linear equations for the LWE coefficient of a ciphertext, where  b' = <a',s> + |e'| such that e and e' have the same sign.
 * Strategy 1:
   Find n noiseless LWE coefficients of different ciphertexts to get n linear equations b = <a,s>.
*/

void strategy0(bool verbose=true);

void strategy1(bool verbose=true);

/* Other useful functions */

// Get the secret/true noise of a BFV ciphertext
uint64_t bfv_get_secret_noise(Decryptor&, const Ciphertext&, MemoryPoolHandle);

// Get the secret/true noise of a BGV ciphertext
uint64_t bgv_get_secret_noise(Decryptor&, const Ciphertext&, MemoryPoolHandle);

// Function to estimate the absolute noise of a ciphertext using CPAD requests
vector<uint64_t> noiseAbsEstim(uint128_t, uint128_t, Evaluator&, Decryptor&, Ciphertext&, uint64_t, vector<pair<uint128_t,Ciphertext>>&);

// Check if the absolute found noise is the same as the true/secret noise. The noises are inputs of this function.
bool is_correct_noise(uint64_t, vector<uint64_t>&, uint128_t, bool);

// Function to print the found absolute noise given in argument
void print_found_absolute_noise(string, vector<uint64_t>&, uint128_t);

// Return a string of the found absolute noise given in argument
std::string found_noise_to_string(vector<uint64_t>&, uint128_t);

#endif //_CPAD_ATTACK_H_

