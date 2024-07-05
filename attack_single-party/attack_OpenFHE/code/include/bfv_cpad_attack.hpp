#ifndef _CPAD_ATTACK_H_
#define _CPAD_ATTACK_H_

#define PARALLEL NOK

#include "openfhe.h"
    
#include "cryptocontext.h"
#include "schemerns/rns-pke.h"
#include "scheme/bfvrns/bfvrns-cryptoparameters.h"

#include <iostream>
#include <fstream>
#include <cmath>
#include <chrono>
#include <vector>

#include "../include/print_functions.hpp"
#include "../include/parameters.hpp"

// header files needed for serialization
#include "ciphertext-ser.h"
#include "cryptocontext-ser.h"
#include "key/key-ser.h"
#include "scheme/bfvrns/bfvrns-ser.h"

using namespace lbcrypto;
using namespace std::chrono_literals;

/** Functions Prototypes **/

// Find the noise of one coefficient of a ciphertext c0 to get an equation b = <a,s> + |e| of this LWE coefficient. Search n linear equations for the LWE coefficient of a ciphertext, where  b' = <a',s> + |e'| such that e and e' have the same sign.
void 
bfv_strategy0(bool verbose=true);

/* Other useful functions */

// Set the parameters of the BFV scheme. Return the runtime of the parameters setting.
std::chrono::duration<double>
setParameters(CryptoContext<DCRTPoly>& cc, usint ringDim, int plaintextModulus = 65537, usint batchSize = 16, usint multDepth = 1, usint digitSize = 30, usint dcrtBits = 60, double sigma = 3.2);

// Get the secret/true noise of a BFV ciphertext
std::pair<NativeInteger, NativeInteger> 
bfv_get_secret_noise(CryptoContext<DCRTPoly>& cc, ConstCiphertext<DCRTPoly> ciphertext, const PrivateKey<DCRTPoly> privateKey);

// Estimate the absolute noise of a ciphertext using CPAD requests.
std::vector<uint64_t> 
noiseAbsEstim(CryptoContext<DCRTPoly>& cc, KeyPair<DCRTPoly>& keyPair, uint128_t q, uint128_t coeff_modulus_q0, Ciphertext<DCRTPoly>& c0, std::vector<std::pair<uint128_t,Ciphertext<DCRTPoly>>>& aca);

// Check if the absolute found noise is the same as the true/secret noise. The noises are inputs of this function.
bool 
is_correct_noise(NativeInteger true_noise, std::vector<uint64_t>& found_noise, NativeInteger modulus, bool print);

// Function to print the found absolute noise given in argument
void 
print_found_absolute_noise(std::string name, std::vector<uint64_t>& e0);

// Return a string of the found absolute noise given in argument
std::string 
found_noise_to_string(std::vector<uint64_t>& e0);

#endif //_CPAD_ATTACK_H_

