#ifndef _PRINT_FUNCTIONS_H_
#define _PRINT_FUNCTIONS_H_

#include <vector>
#include "seal/seal.h"

using namespace std;
using namespace seal;

/** prototypes **/

// Print the parameters of the scheme.
void print_parameters(const seal::SEALContext &context);

// Overload of the << operator for uint128_t type
std::ostream& 
operator<<( std::ostream&, uint128_t);

// Return a string for uint128_t values
std::string 
to_string(uint128_t);

// Print the (true) noise given in parameters
void 
print_noise(uint64_t, uint128_t);

// Return a string of the (true) noise given in argument
std::string 
true_noise_to_string(uint64_t, uint128_t);

// Print the progress of the attack: when an absolute noise is found, print the true noise of the ciphertext, the found absolute noise and if the attack found exactly one absolute noise, if the noise have the sign of the first noise found or if it is a sign mismatch.
void 
print_attack_progress(std::string scheme, std::string true_noise, std::string found_noise, int found_noise_size, bool same_sign, bool CHECK_FOUND_NOISE, bool is_correct_noise, uint64_t nb_of_absolute_noise_of_same_sign_found, uint64_t nb_of_linear_equation_needed);

#endif //_PRINT_FUNCTIONS_H_
