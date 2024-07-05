#include "../include/bfv_cpad_attack.hpp"


static uint64_t number_of_evaluations = 0;
static uint64_t number_of_decryptions = 0;


void bfv_strategy0(bool verbose){
  std::cout << "\n*********************************************\n"
       << "**************** STRATEGY 0 *****************"
       << "\n*********************************************\n\n";

    // Parameters generation 
    // Set CryptoContext
    CryptoContext<DCRTPoly> cc;
    usint batchSize      = 1;
    usint digitSize = 30U;
    usint dcrtBits = 80U;//60U;

    setParameters(cc, RING_DIMENSION, PT_MODULUS, batchSize, MULT_DEPTH, digitSize, dcrtBits, SIGMA);
    
    int64_t n = cc->GetCryptoParameters()->GetElementParams()->GetCyclotomicOrder() / 2;
    uint128_t q = cc->GetCryptoParameters()->GetElementParams()->GetModulus().ConvertToDouble();

    // Print out the parameters
    if(DEBUG){
        std::cout << "p = " << cc->GetCryptoParameters()->GetPlaintextModulus() << std::endl;
        std::cout << "n = " << cc->GetCryptoParameters()->GetElementParams()->GetCyclotomicOrder() / 2 << std::endl;
        std::cout << "n = " << n << std::endl;
        std::cout << "q = " << cc->GetCryptoParameters()->GetElementParams()->GetModulus() << std::endl;
        std::cout << "q = " << q << std::endl;
        std::cout << "log2 q = " << log2(cc->GetCryptoParameters()->GetElementParams()->GetModulus().ConvertToDouble()) << std::endl;
    }

    ////////////////////////////////////////////////////////////
    // Key Generation
    ////////////////////////////////////////////////////////////

    if(DEBUG) std::cout << "Key generation...\n";
    KeyPair<DCRTPoly> keyPair;
    keyPair = cc->KeyGen();
    if (!keyPair.good()){
        std::cerr << "Key generation failed!" << std::endl; exit(1);
    }
    // Generate the relinearization key
    //cc->EvalMultKeyGen(keyPair.secretKey);

    //Save the secret key in a CSV file
    if(SAVING_CSV){
      const DCRTPoly& s = keyPair.secretKey->GetPrivateElement();
      std::ofstream file(CSV_FILE_NAME_SK);
      if (!file.is_open()) {
          std::cerr << "Error: Unable to open the CSV file for writing!" << std::endl;
          return;
      }
      file << s << std::endl;
      file.close();


    Poly sPoly = s.CRTInterpolate();
      std::ofstream file2(CSV_FILE_NAME_SK_POLY);
      if (!file2.is_open()) {
          std::cerr << "Error: Unable to open the CSV file for writing!" << std::endl;
          return;
      }
      file2 << sPoly << std::endl;
      file2.close();
    }

        // Serialize the public key
    if(SERIALIZE){
        if (!Serial::SerializeToFile(FOLDER_NAME+"public_key.txt", keyPair.publicKey, SerType::BINARY)) {
            std::cerr << "Error writing serialization of public key to key-public.txt" << std::endl;
            std::exit(1);
        }
        std::cout << "The public key has been serialized." << std::endl;
    }
    // Serialize the secret key
    if(SERIALIZE){
        if (!Serial::SerializeToFile(FOLDER_NAME+"single_secret_key.txt", keyPair.secretKey, SerType::BINARY)) {
            std::cerr << "Error writing serialization of secret key to key-public.txt" << std::endl;
            std::exit(1);
        }
        std::cout << "The secret key has been serialized." << std::endl;
    }

    if(DEBUG) std::cout << "Key generation: done\n";

    // Parameters of the scheme

    std::cout << "\033[7;33m> Parameters of the scheme <\033[0m" << "\n";
    std::cout << "\033[1;33m[OpenFHE][BFV] " << " n        = " << "\033[0m"<< cc->GetCryptoParameters()->GetElementParams()->GetCyclotomicOrder() / 2 << "\n";
    std::cout << "\033[1;33m[OpenFHE][BFV] " << " log_2(q) = " << "\033[0m"<< log2(cc->GetCryptoParameters()->GetElementParams()->GetModulus().ConvertToDouble()) << "\n";
    std::cout << "\033[1;33m[OpenFHE][BFV] " << " sigma    = " << "\033[0m"<< 3.19 << "\n";
    std::cout << "\033[1;33m[OpenFHE][BFV] " << " t        = " << "\033[0m"<< cc->GetCryptoParameters()->GetPlaintextModulus() << "\n\n";

    ////////////////////////////////////////////////////////////
    // Attack
    ////////////////////////////////////////////////////////////

    int generated_ciphertexts=0;
    int ciphertexts_which_noise_has_been_found=0;

    int number_of_noiseless = 0;
    int number_of_fully_identified_noises = 0;
    
    Plaintext pt = cc->MakeCoefPackedPlaintext({0});
    Plaintext pt_decrypt;

    std::string string_true_noise = "";
    std::string string_found_noise = "";
    bool correct_noise = false;

    //Complete determination of absolute noise for a ciphertext c0 that will be the reference ciphertext.
  
    Ciphertext<DCRTPoly> c0;
    noise_found_incorrect_after_checking_it:
    c0 = cc->Encrypt(keyPair.publicKey, pt);   
    ++generated_ciphertexts;
    std::vector<std::pair<uint128_t, Ciphertext<DCRTPoly>>> aca0;
    std::pair<NativeInteger, NativeInteger> noise_and_modulus =  bfv_get_secret_noise(cc, c0, keyPair.secretKey);
    std::vector<uint64_t> e0 = noiseAbsEstim(cc, keyPair, q, q, c0, aca0);

    while (e0.size()>1 || e0[0] == 0){
        c0 = cc->Encrypt(keyPair.publicKey, pt);   
        ++generated_ciphertexts;
        noise_and_modulus =  bfv_get_secret_noise(cc, c0, keyPair.secretKey);
        e0 = noiseAbsEstim(cc, keyPair, q, q, c0, aca0);
    }

    uint128_t a0 = std::get<0>(aca0[0]);
    Ciphertext<DCRTPoly> ca0 = std::get<1>(aca0[0]);

    //Bingo!
    string_true_noise = true_noise_to_string(std::get<0>(noise_and_modulus), std::get<1>(noise_and_modulus));
    string_found_noise = found_noise_to_string(e0);
    correct_noise = is_correct_noise(std::get<0>(noise_and_modulus), e0, std::get<1>(noise_and_modulus), false);
    if(verbose) print_attack_progress("BFV", string_true_noise, string_found_noise, e0.size(), true,CHECK_FOUND_NOISE, correct_noise, ciphertexts_which_noise_has_been_found+1, n);

    if(CHECK_FOUND_NOISE){
      if(correct_noise){
        ++ciphertexts_which_noise_has_been_found;
        ++number_of_fully_identified_noises;
      } else {
       goto noise_found_incorrect_after_checking_it;
      }
    } else {
      ++ciphertexts_which_noise_has_been_found;
      ++number_of_fully_identified_noises;
    }
    if(SAVING_CSV) save_csv_ciphertext(CSV_FILE_NAME_A_B_E, c0, e0);

    //Search for n linear equations by completely determining the noise of n ciphertexts of same noise sign.

    while (ciphertexts_which_noise_has_been_found<n){
        //First, we try to determine the absolute value of the noise of c1.
        
        Ciphertext<DCRTPoly> c1;
        c1 = cc->Encrypt(keyPair.publicKey, pt);
        ++generated_ciphertexts;
        noise_and_modulus =  bfv_get_secret_noise(cc, c1, keyPair.secretKey);
        std::vector<std::pair<uint128_t, Ciphertext<DCRTPoly>>> aca1;
        std::vector<uint64_t> e1 = noiseAbsEstim(cc, keyPair, q, q, c1, aca1);

        while (e1.size()>1){
            c1 = cc->Encrypt(keyPair.publicKey, pt);
            ++generated_ciphertexts;
            noise_and_modulus =  bfv_get_secret_noise(cc, c1, keyPair.secretKey);
            e1 = noiseAbsEstim(cc, keyPair, q, q, c1, aca1);
        }

        //If we succeed to determine the absolute noise of c1, we look to see if its noise the one of c0 have the same sign.

        uint128_t a1 = std::get<0>(aca1[0]);
        Ciphertext<DCRTPoly> ca1 = std::get<1>(aca1[0]);
        if(e1[0] == 0){
          
          //Bingo!
          string_true_noise = true_noise_to_string(std::get<0>(noise_and_modulus), std::get<1>(noise_and_modulus));
          string_found_noise = found_noise_to_string(e1);
          correct_noise = is_correct_noise(std::get<0>(noise_and_modulus), e1, std::get<1>(noise_and_modulus), false);
          if(verbose) print_attack_progress("BFV", string_true_noise, string_found_noise, e1.size(), true,CHECK_FOUND_NOISE, correct_noise, ciphertexts_which_noise_has_been_found+1, n);

          if(CHECK_FOUND_NOISE){
            if(correct_noise){
              ++ciphertexts_which_noise_has_been_found;
              ++number_of_noiseless;
              ++number_of_fully_identified_noises;
              }
          } else {
            ++ciphertexts_which_noise_has_been_found;
            ++number_of_noiseless;
            ++number_of_fully_identified_noises;
          }
          if(SAVING_CSV) save_csv_ciphertext(CSV_FILE_NAME_A_B_E, c1, e1);
        }
        else {
        if((e0[0]*a0+e1[0]*a1) > (q/(2*PT_MODULUS))){
        //To see if c1 noise and c0 noise have the same sign, we add the ciphertexts and try to decrypt.
        Ciphertext<DCRTPoly> cz;
        cz = cc->EvalAdd(ca0, ca1);
        ++number_of_evaluations;

        cc->Decrypt(keyPair.secretKey, cz, &pt_decrypt);
        ++number_of_decryptions;
        auto nativePolyRes = pt_decrypt->GetElement<NativePoly>();
        
        //If the decryption is incorrect, the noises have the same sign. We have a new linear equation
        if(nativePolyRes.at(0) != ((NativeInteger)0)){ //Incorrect decryption

          //Bingo!
          string_true_noise = true_noise_to_string(std::get<0>(noise_and_modulus), std::get<1>(noise_and_modulus));
          string_found_noise = found_noise_to_string(e1);
          correct_noise = is_correct_noise(std::get<0>(noise_and_modulus), e1, std::get<1>(noise_and_modulus), false);
          if(verbose) print_attack_progress("BFV", string_true_noise, string_found_noise, e1.size(), true,CHECK_FOUND_NOISE, correct_noise, ciphertexts_which_noise_has_been_found+1, n);

          if(CHECK_FOUND_NOISE){
            if(correct_noise){
              ++ciphertexts_which_noise_has_been_found;
              ++number_of_fully_identified_noises;
            }
          } else {
            ++ciphertexts_which_noise_has_been_found;
            ++number_of_fully_identified_noises;
          }
          if(SAVING_CSV) save_csv_ciphertext(CSV_FILE_NAME_A_B_E, c1, e1);
          } else {    
          //If not, there is a sign mismatch and we continue with a new cipher.

          //Sign mismatch!
          string_true_noise = true_noise_to_string(std::get<0>(noise_and_modulus), std::get<1>(noise_and_modulus));
          string_found_noise = found_noise_to_string(e1);
          correct_noise = is_correct_noise(std::get<0>(noise_and_modulus), e1, std::get<1>(noise_and_modulus), false);
          if(verbose) print_attack_progress("BFV", string_true_noise, string_found_noise, e1.size(), false, CHECK_FOUND_NOISE, correct_noise, ciphertexts_which_noise_has_been_found, n);

          if(CHECK_FOUND_NOISE){
            if(correct_noise){
            ++number_of_fully_identified_noises;
            }
          } else {
            ++number_of_fully_identified_noises;
          }
        }
      }
    }
  }

  if(verbose){
    std::cout << "\033[7;33m> Parameters of the scheme <\033[0m" << "\n";
    std::cout << "\033[1;33m[OpenFHE][BFV] " << " n        = " << "\033[0m"<< cc->GetCryptoParameters()->GetElementParams()->GetCyclotomicOrder() / 2 << "\n";
    std::cout << "\033[1;33m[OpenFHE][BFV] " << " log_2(q) = " << "\033[0m"<< log2(cc->GetCryptoParameters()->GetElementParams()->GetModulus().ConvertToDouble()) << "\n";
    std::cout << "\033[1;33m[OpenFHE][BFV] " << " sigma    = " << "\033[0m"<< 3.19 << "\n";
    std::cout << "\033[1;33m[OpenFHE][BFV] " << " t        = " << "\033[0m"<< cc->GetCryptoParameters()->GetPlaintextModulus() << "\n\n";
  }

  std::cout << "\033[7;33m> " << ciphertexts_which_noise_has_been_found << " linear equations have been found! <\033[0m" << "\n";
  std::cout << "\033[1;33m[OpenFHE][BFV] " << "number of ciphertexts generated: " << "\033[0m"<< generated_ciphertexts << "\n";
  std::cout << "\033[1;33m[OpenFHE][BFV] " << "number of noiseless samples: " << "\033[0m"<< number_of_noiseless << "/" << generated_ciphertexts << "\n";
  std::cout << "\033[1;33m[OpenFHE][BFV] " << "number of ciphertexts which absolute noise fully determined: " << "\033[0m"<< number_of_fully_identified_noises << "/"<< generated_ciphertexts << "\n";
  std::cout << "\033[1;33m[OpenFHE][BFV] " << "number of evaluations: " << "\033[0m"<< number_of_evaluations << "\n";
  std::cout << "\033[1;33m[OpenFHE][BFV] " << "number of decryptions: " << "\033[0m"<< number_of_decryptions << "\n";

}



/**********************************************/
/************** USEFUL FUNCTIONS **************/
/**********************************************/


std::chrono::duration<double>
setParameters(CryptoContext<DCRTPoly>& cc, usint ringDim, int plaintextModulus, usint batchSize, usint multDepth, usint digitSize, usint dcrtBits, double sigma) {
    
    std::chrono::duration<double> elapsed_seconds_params_set = std::chrono::duration_cast<std::chrono::microseconds>(0s);
    auto start_params_gen = std::chrono::steady_clock::now();

    lbcrypto::SecurityLevel securityLevel = lbcrypto::SecurityLevel::HEStd_128_classic;//HEStd_256_classic;

    lbcrypto::CCParams<lbcrypto::CryptoContextBFVRNS> parameters;

    parameters.SetRingDim(ringDim);
    parameters.SetPlaintextModulus(plaintextModulus);
    parameters.SetMultiplicativeDepth(multDepth);
    parameters.SetBatchSize(batchSize);

    parameters.SetSecurityLevel(securityLevel);
    if(DEBUG) std::cout<<"SecurityLevel: "<<parameters.GetSecurityLevel()<<".\n";
    parameters.SetStandardDeviation(sigma);
    parameters.SetSecretKeyDist(UNIFORM_TERNARY);
    //parameters.SetDigitSize(digitSize);
    //parameters.SetScalingModSize(dcrtBits);

    cc = GenCryptoContext(parameters);
    // enable features that you wish to use
    cc->Enable(PKE);
    //cc->Enable(KEYSWITCH);
    cc->Enable(LEVELEDSHE);
    cc->Enable(ADVANCEDSHE);

    auto end_params_gen = std::chrono::steady_clock::now();
    elapsed_seconds_params_set += end_params_gen - start_params_gen;

    return elapsed_seconds_params_set;
}

/*
 * bfv_get_secret_noise returns the real noise of a ciphertext
 * It is a forbidden action, but this function is only used to verify that our attack recover correctly the noise.
 */
std::pair<NativeInteger, NativeInteger> bfv_get_secret_noise(CryptoContext<DCRTPoly>& cc, ConstCiphertext<DCRTPoly> ciphertext, const PrivateKey<DCRTPoly> privateKey) {
    const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersBFVRNS>(privateKey->GetCryptoParameters());
    DCRTPoly b                      = cc->GetScheme()->DecryptCore(ciphertext, privateKey);
    b.SetFormat(Format::COEFFICIENT);
    Poly bpoly = b.CRTInterpolate();
    BigInteger bcoef0 = bpoly.at(0);
    return std::make_pair(((NativeInteger)bcoef0), bpoly.GetModulus());
}

/*
  noiseAbsEstim estimate the absolute noise in a ciphertext, using CPAD actions.
*/
std::vector<uint64_t> noiseAbsEstim(CryptoContext<DCRTPoly>& cc, KeyPair<DCRTPoly>& keyPair, uint128_t q, uint128_t coeff_modulus_q0, 
                                    Ciphertext<DCRTPoly>& c0, std::vector<std::pair<uint128_t,Ciphertext<DCRTPoly>>>& aca){
  std::vector<Ciphertext<DCRTPoly>> cladder;
  cladder.push_back(c0);
  int k = 1;
  uint128_t a = 0, b = 0, z = 0;
  uint128_t l, u;
  Ciphertext<DCRTPoly> ca, cb;

  Plaintext pt_decrypt;

  Ciphertext<DCRTPoly> c;
  while(true){
    Ciphertext<DCRTPoly> c_k_minus_1 = cladder[k-1];
    c = cc->EvalAdd(c_k_minus_1, c_k_minus_1);
    ++number_of_evaluations;
    cladder.push_back(c);
    cc->Decrypt(keyPair.secretKey, c, &pt_decrypt);
    ++number_of_decryptions;
    auto nativePolyRes = pt_decrypt->GetElement<NativePoly>();
    if(nativePolyRes.at(0) != ((NativeInteger)0)){ //Incorrect decryption
      a = ((uint128_t)1)<<(k-1);
      ca = cladder[k-1];
      b = ((uint128_t)1)<<k;
      cb = cladder[k];
      k = k-1;
      break;
    }
    if ( (((uint128_t)1)<<k) > q){
      aca.clear();
      aca.push_back(make_pair(a,ca));
      //std::cout << "k=" << k <<", 2^k="<< (((uint128_t)1)<<k) << ", q=" <<q<<"\n";
      return {0}; // If we cannot switch to 1, noise is 0
      break;
    }
    k = k+1;
  }

  Ciphertext<DCRTPoly> cz;
  while (k>0){
    z = a + (((uint128_t)1)<<(k-1));
    Ciphertext<DCRTPoly> c_k_minus_1 = cladder[k-1];
    cz = cc->EvalAdd(ca, c_k_minus_1);
    ++number_of_evaluations;

    cc->Decrypt(keyPair.secretKey, cz, &pt_decrypt);
    ++number_of_decryptions;
    auto nativePolyRes = pt_decrypt->GetElement<NativePoly>();
    if(nativePolyRes.at(0) != ((NativeInteger)0)){ //Incorrect decryption
      b =  z;
      cb = cz;
    }
    else{
      a = z;
      ca = cz;
    }
    k=k-1;
  }

  l = ceil(q/(((double)4)*b));
  u = floor(q/(((double)4)*a));
  l=2*l/PT_MODULUS;
  u=2*u/PT_MODULUS;
  //cout << "a="<<a<<"; b="<<b<<";\n";
  //std::cout << "l="<<l<<"; u="<<u<<";\n\n";
  aca.clear();
  aca.push_back(make_pair(a,ca));
  if (l==u && l!=0)
    return {(uint64_t)l};
  else
    return {(uint64_t)l, (uint64_t)u};
}


/*
  Print the found absolute noise
*/
void print_found_absolute_noise(std::string name, std::vector<uint64_t>& e0){
  std::cout << name << " = [ ";
  for(int i = 0; i<(int)e0.size(); ++i){
    if( (e0[i]) > (PT_MODULUS>>1) ){
      std::cout << PT_MODULUS-e0[i] << " ";
    } else {
      std::cout << e0[i] << " ";
    }
  }
  std::cout << "]\n";
}

/*
  Make a string for the found absolute noise
*/
std::string found_noise_to_string(std::vector<uint64_t>& e0){
  std::string found_absolute_noise = "";
  found_absolute_noise = found_absolute_noise +"[ ";
  for(int i = 0; i<(int)e0.size(); ++i){
    if( (e0[i]) > (PT_MODULUS>>1) ){
      found_absolute_noise = found_absolute_noise + to_string(PT_MODULUS-e0[i]) + " ";
    } else {
      found_absolute_noise = found_absolute_noise + to_string(e0[i]) + " ";
    }
  }
  found_absolute_noise = found_absolute_noise + "]";
  return found_absolute_noise;
}


/*
  Check if the found noise is the true noise of the original ciphertext
*/
bool is_correct_noise(NativeInteger true_noise, std::vector<uint64_t>& found_noise, NativeInteger modulus, bool print){
  if (true_noise > (modulus>>1))
    true_noise = modulus - true_noise;
  true_noise = true_noise%PT_MODULUS;
  if(found_noise.size() != 1)
    return false;
  if( ((found_noise[0])%PT_MODULUS) > (PT_MODULUS>>1) ){
    if(true_noise == (PT_MODULUS - ((found_noise[0])%PT_MODULUS ))){
      if(print) std::cout << "\033[32mNoise found correct! \n\033[39m";
      return true;
    }
  } 
  if(true_noise == ((found_noise[0])%PT_MODULUS)){
    if(print) std::cout << "\033[32mNoise found correct! \n\033[39m";
    return true;
  }
  if(print){ 
    std::cout << "\033[31mNoise found incorrect!\n";
    std::cout << "true noise: " << true_noise << " and found noise: "<< (((uint128_t)found_noise[0])%PT_MODULUS) <<"\033[39m\n";
  }
  return false;    
}


