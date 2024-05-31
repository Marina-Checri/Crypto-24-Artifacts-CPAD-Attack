#ifndef _PRINT_FUNCTIONS_H_
#define _PRINT_FUNCTIONS_H_

#include <vector>
#include <ostream>

#include "openfhe.h"
using namespace lbcrypto;

/** prototypes **/

// Overload of the << operator for uint128_t type
std::ostream& 
operator<<( std::ostream&, uint128_t);

// Return a string for uint128_t values
std::string 
to_string(uint128_t value);

// Print the progress of the attack: when an absolute noise is found, print the true noise of the ciphertext, the found absolute noise and if the attack found exactly one absolute noise, if the noise have the sign of the first noise found or if it is a sign mismatch.
void 
print_attack_progress(std::string, std::string, std::string, int, bool, bool, bool, uint64_t, uint64_t);

#endif //_PRINT_FUNCTIONS_H_
