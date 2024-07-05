#ifndef _PARAMETERS_H_
#define _PARAMETERS_H_

#include <vector>
#include <ostream>

#include "openfhe.h"
using namespace lbcrypto;

enum Scheme {
    BFV,
    BGV
};

#define DEBUG 0
#define CHECK_FOUND_NOISE 1

#define RING_DIMENSION 8192//16384
#define PT_MODULUS 1024
#define MULT_DEPTH 0
#define SIGMA 3.19

#define SAVING_CSV false
#define SERIALIZE false

const std::string FOLDER_NAME = "serial_attack_c_k/";
const std::string CSV_FILE_NAME_A_B_E = FOLDER_NAME+"info_attack_a_b_|e|.csv";
const std::string CSV_FILE_NAME_SK = FOLDER_NAME+"info_attack_secret_key.csv";
const std::string CSV_FILE_NAME_SK_POLY = FOLDER_NAME+"info_attack_secret_key_poly.csv";


#endif //_PARAMETERS_H_
