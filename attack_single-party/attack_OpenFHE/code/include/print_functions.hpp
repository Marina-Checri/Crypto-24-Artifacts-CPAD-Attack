#ifndef _PRINT_FUNCTIONS_H_
#define _PRINT_FUNCTIONS_H_

#include <vector>
#include <ostream>

#include "openfhe.h"
#include "../include/parameters.hpp"

using namespace lbcrypto;

/** prototypes **/

// Overload of the << operator for uint128_t type
std::ostream& 
operator<<( std::ostream&, uint128_t);

// Return a string for uint128_t values
std::string 
to_string(uint128_t value);

// Print the (true) noise given in parameters
void 
print_noise(lbcrypto::NativeInteger noise, lbcrypto::NativeInteger modulus, Scheme scheme = Scheme::BFV);

// Return a string of the (true) noise given in argument
std::string 
true_noise_to_string(NativeInteger noise, NativeInteger modulus, Scheme scheme = Scheme::BFV);

// Print the progress of the attack: when an absolute noise is found, print the true noise of the ciphertext, the found absolute noise and if the attack found exactly one absolute noise, if the noise have the sign of the first noise found or if it is a sign mismatch.
void 
print_attack_progress(std::string scheme, std::string true_noise, std::string found_noise, int found_noise_size, bool same_sign, bool check_found_noise, bool is_correct_noise, uint64_t nb_of_absolute_noise_of_same_sign_found, uint64_t nb_of_linear_equation_needed);

// Save a ciphertext and the founded noise in a csv file
int 
save_csv_ciphertext(std::string file_name, Ciphertext<DCRTPoly>& ciphertext, std::vector<uint64_t>& found_noise);

#endif //_PRINT_FUNCTIONS_H_
