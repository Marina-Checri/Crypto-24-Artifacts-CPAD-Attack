#ifndef _CPAD_THRESHOLD_ATTACK_H_
#define _CPAD_THRESHOLD_ATTACK_H_

#define PARALLEL NOK

#include "openfhe.h"

#include "scheme/bfvrns/bfvrns-cryptoparameters.h"
#include "schemerns/rns-pke.h"
#include "cryptocontext.h"

#include <iostream>
#include <cmath>
#include <chrono>

#include <boost/multiprecision/cpp_int.hpp>
namespace mp = boost::multiprecision;

#define DEBUG 0

#define RING_DIMENSION 8192 //16384//8192//4096
#define PT_MODULUS 1024     //65537//33832961//134250497//132120577
#define MULT_DEPTH 0
#define SIGMA 3.19

#define CHECK_FOUND_NOISE 1

#define NB_USERS 5
#define ENABLE_NOISE_FLOODING_FEATURE false

using namespace lbcrypto;
using namespace std::chrono_literals;

/** Functions Prototypes **/

// Find the noise of one coefficient of a ciphertext c0 to get an equation b = <a,s> + |e| of this LWE coefficient. Search n linear equations for the LWE coefficient of a ciphertext, where  b' = <a',s> + |e'| such that e and e' have the same sign.
void 
strategy0(bool verbose=true);

/* Other useful functions */

// Set the parameters of the BFV scheme. Return the runtime of the parameters setting.
// if the macro ENABLE_NOISE_FLOODING_FEATURE is set to true, enables the flooding using the NOISE_FLOODING_MULTIPARTY mode, and disable it otherwise.
std::chrono::duration<double>
setParameters(CryptoContext<DCRTPoly>& cc, usint ringDim, int plaintextModulus = 65537, usint batchSize = 16, usint multDepth = 1, usint digitSize = 30, usint dcrtBits = 60, double sigma = 3.2);

// Generate the different key-pairs of the users and return an int (=0) if the function terminates well, the runtime for the keygen() call (the first key generated) and the runtime for generating all the keys (USERS different keys).
std::tuple<int, std::chrono::duration<double>, std::chrono::duration<double>> 
keyGen(const CryptoContext<DCRTPoly>&, int, KeyPair<DCRTPoly>&, KeyPair<DCRTPoly>&, std::vector<lbcrypto::KeyPair<lbcrypto::DCRTPoly>>&);

// Computes all partial decryptions and return the runtime of the first partial decryption (multiparty decrypt main) and the runtime of the computation of all partial decryptions (USERS different partial decryptions).
std::tuple<std::chrono::duration<double>, std::chrono::duration<double>> 
partialDecryptions(const CryptoContext<DCRTPoly>&, const lbcrypto::Ciphertext<lbcrypto::DCRTPoly>&, const std::vector<lbcrypto::KeyPair<lbcrypto::DCRTPoly>>&, std::vector<Ciphertext<DCRTPoly>>&, bool disable_noise_flooding=false);

// Get the secret/true noise of a BFV ciphertext
std::pair<NativeInteger, NativeInteger> 
bfv_get_secret_noise(const CryptoContext<DCRTPoly>&, const std::vector<Ciphertext<DCRTPoly>>&);
std::pair<NativeInteger, NativeInteger> 
bfv_get_secret_noise(const CryptoContext<DCRTPoly>&, const Ciphertext<DCRTPoly>&, const std::vector<lbcrypto::KeyPair<lbcrypto::DCRTPoly>>&);

// Estimate the absolute noise of a ciphertext using CPAD requests.
std::vector<double> 
noiseAbsEstim(const CryptoContext<DCRTPoly>&, const std::vector<lbcrypto::KeyPair<lbcrypto::DCRTPoly>>&, double q, double coeff_modulus_q0, const Ciphertext<DCRTPoly>&, std::vector<std::pair<uint128_t,Ciphertext<DCRTPoly>>>&);

// Check if the absolute found noise is the same as the true/secret noise. The noises are inputs of this function.
bool 
is_correct_noise(NativeInteger, const std::vector<double>&, NativeInteger, bool);

// Print the (true) noise given in parameters
void 
print_noise(lbcrypto::NativeInteger noise, lbcrypto::NativeInteger modulus);

// Return a string of the (true) noise given in argument
std::string 
true_noise_to_string(NativeInteger noise, NativeInteger modulus);

// Function to print the found absolute noise given in argument
void 
print_found_absolute_noise(std::string, const std::vector<double>&);

// Return a string of the found absolute noise given in argument
std::string 
found_noise_to_string(std::vector<double>& e0);




#endif //_CPAD_THRESHOLD_ATTACK_H_

