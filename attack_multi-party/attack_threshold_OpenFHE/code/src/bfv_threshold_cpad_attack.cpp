#include "../include/bfv_threshold_cpad_attack.hpp"
#include "../include/print_functions.hpp"


static uint64_t number_of_evaluations = 0;
static uint64_t number_of_decryptions = 0;


void strategy0(bool verbose){
    if (NB_USERS < 2)
        exit(1);

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
    double q = cc->GetCryptoParameters()->GetElementParams()->GetModulus().ConvertToDouble();

    // Print out the parameters
    if(DEBUG){
        std::cout << "p = " << cc->GetCryptoParameters()->GetPlaintextModulus() << std::endl;
        std::cout << "n = " << cc->GetCryptoParameters()->GetElementParams()->GetCyclotomicOrder() / 2 << std::endl;
        std::cout << "n = " << n << std::endl;
        std::cout << "q = " << cc->GetCryptoParameters()->GetElementParams()->GetModulus() << std::endl;
        std::cout << "q = " << q << std::endl;
        std::cout << "log2 q = " << log2(cc->GetCryptoParameters()->GetElementParams()->GetModulus().ConvertToDouble()) << std::endl;
        //std::cout << "sigma = " << cc->GetCryptoParameters()->GetStandardDeviation() << std::endl;
    }

    // Key Generation

    std::vector<lbcrypto::KeyPair<lbcrypto::DCRTPoly>> keyPairs;

    KeyPair<DCRTPoly> kp1;
    KeyPair<DCRTPoly> kpMultiparty;

    if(DEBUG) std::cout << "Key generation...\n";

    auto keygen_results = keyGen(cc, NB_USERS, kp1, kpMultiparty, keyPairs);
    int keygen_done = std::get<0>(keygen_results);
    std::chrono::duration<double> time_one_key_generation = std::get<1>(keygen_results);
    std::chrono::duration<double> time_keys_generation = std::get<2>(keygen_results);
    if(keygen_done < 0){
        std::cerr << "Key generation of "<< keygen_done <<" failed!" << std::endl; exit(1);
    }

    if(DEBUG) std::cout << "Key generation: done\n";
    if(DEBUG) std::cout << "Number of parties:" << NB_USERS << ". Number of keys generated:" << keyPairs.size() << "\n";

    // Attack

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
    c0 = cc->Encrypt(kpMultiparty.publicKey, pt);   
    ++generated_ciphertexts;
    std::vector<std::pair<uint128_t, Ciphertext<DCRTPoly>>> aca0;
    std::pair<NativeInteger, NativeInteger> noise_and_modulus =  bfv_get_secret_noise(cc, c0, keyPairs);
    std::vector<double> e0 = noiseAbsEstim(cc, keyPairs, q, q, c0, aca0);

    while (e0.size()>1 || e0[0] == 0){
        c0 = cc->Encrypt(kpMultiparty.publicKey, pt);   
        ++generated_ciphertexts;
        noise_and_modulus =  bfv_get_secret_noise(cc, c0, keyPairs);
        e0 = noiseAbsEstim(cc, keyPairs, q, q, c0, aca0);
    }

    uint128_t a0 = std::get<0>(aca0[0]);
    Ciphertext<DCRTPoly> ca0 = std::get<1>(aca0[0]);

    //Bingo!
    string_true_noise = true_noise_to_string(std::get<0>(noise_and_modulus), std::get<1>(noise_and_modulus));
    string_found_noise = found_noise_to_string(e0);
    correct_noise = is_correct_noise(std::get<0>(noise_and_modulus), e0, std::get<1>(noise_and_modulus), false);
    if(verbose) print_attack_progress("BFV ThHE", string_true_noise, string_found_noise, e0.size(), true,CHECK_FOUND_NOISE, correct_noise, ciphertexts_which_noise_has_been_found+1, n);

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

    //Search for n linear equations by completely determining the noise of n ciphertexts of same noise sign.

    int count=0;
    while (ciphertexts_which_noise_has_been_found<n) {//&& count<50){
        ++count;
        //First, we try to determine the absolute value of the noise of c1.
        
        Ciphertext<DCRTPoly> c1;
        c1 = cc->Encrypt(kpMultiparty.publicKey, pt);
        ++generated_ciphertexts;
        noise_and_modulus =  bfv_get_secret_noise(cc, c1, keyPairs);
        std::vector<std::pair<uint128_t, Ciphertext<DCRTPoly>>> aca1;
        std::vector<double> e1 = noiseAbsEstim(cc, keyPairs, q, q, c1, aca1);

        while (e1.size()>1){
            c1 = cc->Encrypt(kpMultiparty.publicKey, pt);
            ++generated_ciphertexts;
            noise_and_modulus =  bfv_get_secret_noise(cc, c1, keyPairs);
            e1 = noiseAbsEstim(cc, keyPairs, q, q, c1, aca1);
        }

        //If we succeed to determine the absolute noise of c1, we look to see if its noise the one of c0 have the same sign.

        uint128_t a1 = std::get<0>(aca1[0]);
        Ciphertext<DCRTPoly> ca1 = std::get<1>(aca1[0]);
        if(e1[0] == 0){

          //Bingo!
          string_true_noise = true_noise_to_string(std::get<0>(noise_and_modulus), std::get<1>(noise_and_modulus));
          string_found_noise = found_noise_to_string(e1);
          correct_noise = is_correct_noise(std::get<0>(noise_and_modulus), e1, std::get<1>(noise_and_modulus), false);
          if(verbose) print_attack_progress("BFV ThHE", string_true_noise, string_found_noise, e1.size(), true,CHECK_FOUND_NOISE, correct_noise, ciphertexts_which_noise_has_been_found+1, n);
          
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
        }
        else {
        if((e0[0]*a0+e1[0]*a1) > (q/(2*PT_MODULUS))){
        //To see if c1 noise and c0 noise have the same sign, we add the ciphertexts and try to decrypt.
        Ciphertext<DCRTPoly> cz;
        cz = cc->EvalAdd(ca0, ca1);
        ++number_of_evaluations;

        std::vector<Ciphertext<DCRTPoly>> partialsCiphertextVec;
        partialDecryptions(cc, cz, keyPairs, partialsCiphertextVec);
        cc->MultipartyDecryptFusion(partialsCiphertextVec, &pt_decrypt);
        ++number_of_decryptions;
        auto nativePolyRes = pt_decrypt->GetElement<NativePoly>();
        
        //If the decryption is incorrect, the noises have the same sign. We have a new linear equation
        if(nativePolyRes.at(0) != ((NativeInteger)0)){ //Incorrect decryption

          //Bingo!
          string_true_noise = true_noise_to_string(std::get<0>(noise_and_modulus), std::get<1>(noise_and_modulus));
          string_found_noise = found_noise_to_string(e1);
          correct_noise = is_correct_noise(std::get<0>(noise_and_modulus), e1, std::get<1>(noise_and_modulus), false);
          if(verbose) print_attack_progress("BFV ThHE", string_true_noise, string_found_noise, e1.size(), true,CHECK_FOUND_NOISE, correct_noise, ciphertexts_which_noise_has_been_found+1, n);

          if(CHECK_FOUND_NOISE){
            if(correct_noise){
              ++ciphertexts_which_noise_has_been_found;
              ++number_of_fully_identified_noises;
            }
          } else {
            ++ciphertexts_which_noise_has_been_found;
            ++number_of_fully_identified_noises;
          }
        } else {
        //If not, there is a sign mismatch and we continue with a new cipher.

          //Sign mismatch!
          string_true_noise = true_noise_to_string(std::get<0>(noise_and_modulus), std::get<1>(noise_and_modulus));
          string_found_noise = found_noise_to_string(e1);
          correct_noise = is_correct_noise(std::get<0>(noise_and_modulus), e1, std::get<1>(noise_and_modulus), false);
          if(verbose) print_attack_progress("BFV ThHE", string_true_noise, string_found_noise, e1.size(), false, CHECK_FOUND_NOISE, correct_noise, ciphertexts_which_noise_has_been_found, n);

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
  std::cout << "\033[7;33m> " << ciphertexts_which_noise_has_been_found << " linear equations have been found! <\033[0m" << "\n";
  std::cout << "\033[1;33m[OpenFHE][BFV ThHE] " << "number of ciphertexts generated: " << "\033[0m"<< generated_ciphertexts << "\n";
  std::cout << "\033[1;33m[OpenFHE][BFV ThHE] " << "number of noiseless samples: " << "\033[0m"<< number_of_noiseless << "/" << generated_ciphertexts << "\n";
  std::cout << "\033[1;33m[OpenFHE][BFV ThHE] " << "number of ciphertexts which absolute noise fully determined: " << "\033[0m"<< number_of_fully_identified_noises << "/"<< generated_ciphertexts << "\n";
  std::cout << "\033[1;33m[OpenFHE][BFV ThHE] " << "number of evaluations: " << "\033[0m"<< number_of_evaluations << "\n";
  std::cout << "\033[1;33m[OpenFHE][BFV ThHE] " << "number of decryptions: " << "\033[0m"<< number_of_decryptions << "\n";
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
    //parameters.SetMultiplicativeDepth(multDepth);
    parameters.SetBatchSize(batchSize);

    parameters.SetSecurityLevel(securityLevel);
    if(DEBUG) std::cout<<"SecurityLevel: "<<parameters.GetSecurityLevel()<<".\n";
    parameters.SetStandardDeviation(sigma);
    parameters.SetSecretKeyDist(UNIFORM_TERNARY);
    //parameters.SetDigitSize(digitSize);
    //parameters.SetScalingModSize(dcrtBits);
    parameters.SetThresholdNumOfParties(NB_USERS);

    if(ENABLE_NOISE_FLOODING_FEATURE){
      // NOISE_FLOODING_MULTIPARTY is most secure mode of threshold FHE for BFV and BGV.
      parameters.SetMultipartyMode(NOISE_FLOODING_MULTIPARTY);
    }

    cc = GenCryptoContext(parameters);
    // enable features that we wish to use
    cc->Enable(PKE);
    //cc->Enable(KEYSWITCH);
    cc->Enable(LEVELEDSHE);
    cc->Enable(ADVANCEDSHE);
    cc->Enable(MULTIPARTY);

    auto end_params_gen = std::chrono::steady_clock::now();
    elapsed_seconds_params_set += end_params_gen - start_params_gen;

    return elapsed_seconds_params_set;
}


std::tuple<int, std::chrono::duration<double>, std::chrono::duration<double>>
keyGen(const CryptoContext<DCRTPoly>& cc, int K, KeyPair<DCRTPoly>& kp1, KeyPair<DCRTPoly>& kpMultiparty, std::vector<lbcrypto::KeyPair<lbcrypto::DCRTPoly>>& keyPairs){

    std::chrono::duration<double> elapsed_seconds_one_key_gen = std::chrono::duration_cast<std::chrono::microseconds>(0s);
    std::chrono::duration<double> elapsed_seconds_key_gen = std::chrono::duration_cast<std::chrono::microseconds>(0s);

    //K parties
    auto start_key_gen1 = std::chrono::steady_clock::now();
    kp1 = cc->KeyGen();
    auto end_key_gen1 = std::chrono::steady_clock::now();
    elapsed_seconds_one_key_gen += end_key_gen1 - start_key_gen1;
    elapsed_seconds_key_gen += elapsed_seconds_one_key_gen;

    if (!kp1.good()){
        std::cerr << "Key generation of user "<< 1 <<" failed!" << std::endl; return make_tuple(-1, elapsed_seconds_one_key_gen, elapsed_seconds_key_gen);
    }
    keyPairs.push_back(kp1);

    for(int i = 1; i<K; ++i){
        auto start_key_gen = std::chrono::steady_clock::now();
        kpMultiparty = cc->MultipartyKeyGen(keyPairs[i-1].publicKey);
        auto end_key_gen = std::chrono::steady_clock::now();
        elapsed_seconds_key_gen += end_key_gen - start_key_gen;

        if (!kpMultiparty.good()){
            return make_tuple(-(i-1), elapsed_seconds_one_key_gen, elapsed_seconds_key_gen);
	}
        keyPairs.push_back(kpMultiparty);
    }

    return make_tuple(0, elapsed_seconds_one_key_gen, elapsed_seconds_key_gen);
}

std::tuple<std::chrono::duration<double>, std::chrono::duration<double>> 
partialDecryptions(const CryptoContext<DCRTPoly>& cc, const lbcrypto::Ciphertext<lbcrypto::DCRTPoly>& ciphertext, const std::vector<lbcrypto::KeyPair<lbcrypto::DCRTPoly>>& keyPairs, std::vector<Ciphertext<DCRTPoly>>& partialCiphertextVec, bool disable_noise_flooding){

    std::chrono::duration<double> elapsed_seconds_one_partial_decryption = std::chrono::duration_cast<std::chrono::microseconds>(0s);
    std::chrono::duration<double> elapsed_seconds_partial_decryptions = std::chrono::duration_cast<std::chrono::microseconds>(0s);

    //K parties
    size_t K = keyPairs.size();

    auto start_part_dec1 = std::chrono::steady_clock::now();
    // partial decryption by first party (lead)
    auto ciphertextPartial1 = cc->MultipartyDecryptLead({ciphertext}, keyPairs[0].secretKey, disable_noise_flooding);
    auto end_part_dec1 = std::chrono::steady_clock::now();
    partialCiphertextVec.push_back(ciphertextPartial1[0]);

    elapsed_seconds_one_partial_decryption += end_part_dec1 - start_part_dec1;
    elapsed_seconds_partial_decryptions += elapsed_seconds_one_partial_decryption;

    // partial decryption by other parties (main)
    for(int i = 1; i < (int)K; ++i){
        auto start_part_dec = std::chrono::steady_clock::now();
        auto ciphertextPartial = cc->MultipartyDecryptMain({ciphertext}, keyPairs[i].secretKey, disable_noise_flooding);
        auto end_part_dec = std::chrono::steady_clock::now();
        elapsed_seconds_partial_decryptions += end_part_dec - start_part_dec;

        partialCiphertextVec.push_back(ciphertextPartial[0]);
    }
    return make_tuple(elapsed_seconds_one_partial_decryption, elapsed_seconds_partial_decryptions);
}

/*
 * bfv_get_secret_noise returns the real noise of a ciphertext
 * It is a forbidden action, but this function is only used to verify that our attack recover correctly the noise.
 */
std::pair<NativeInteger, NativeInteger>
 bfv_get_secret_noise(const CryptoContext<DCRTPoly>& cc, const std::vector<Ciphertext<DCRTPoly>>& ciphertextVec) {
    const std::vector<DCRTPoly>& cv0 = ciphertextVec[0]->GetElements();
    DCRTPoly b = cv0[0];
    for (size_t i = 1; i < ciphertextVec.size(); i++) {
        const std::vector<DCRTPoly>& cvi = ciphertextVec[i]->GetElements();
        b += cvi[0];
    }
    b.SetFormat(Format::COEFFICIENT);

    Poly bpoly = b.CRTInterpolate();
    BigInteger bcoef0 = bpoly.at(0);

    return std::make_pair(((NativeInteger)bcoef0), bpoly.GetModulus());
}


std::pair<NativeInteger, NativeInteger> 
bfv_get_secret_noise(const CryptoContext<DCRTPoly>& cc, const Ciphertext<DCRTPoly>& ciphertext, const std::vector<lbcrypto::KeyPair<lbcrypto::DCRTPoly>>& keyPairs) {
    std::vector<Ciphertext<DCRTPoly>> partialsCiphertextVec;
    partialDecryptions(cc, ciphertext, keyPairs, partialsCiphertextVec, true);
    return bfv_get_secret_noise(cc, partialsCiphertextVec);
}

/*
  noiseAbsEstim estimate the absolute noise in a ciphertext, using CPAD actions.
*/
std::vector<double> noiseAbsEstim(const CryptoContext<DCRTPoly>& cc, const std::vector<lbcrypto::KeyPair<lbcrypto::DCRTPoly>>& keyPairs, double q, double coeff_modulus_q0, const Ciphertext<DCRTPoly>& c0, std::vector<std::pair<uint128_t,Ciphertext<DCRTPoly>>>& aca){
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

    //cc->Decrypt(keyPair.secretKey, c, &pt_decrypt);
    std::vector<Ciphertext<DCRTPoly>> partialsCiphertextVec;
    partialDecryptions(cc, c, keyPairs, partialsCiphertextVec);
    cc->MultipartyDecryptFusion(partialsCiphertextVec, &pt_decrypt);
    
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
    if ((mp::cpp_int(1) << k) > mp::cpp_int(q)) {
      aca.clear();
      aca.push_back(make_pair(a,ca));
      //std::cout << "k=" << k <<", 2^k="<< ((mp::cpp_int(1))<<k) << ", q=" <<q<<"\n";
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

    //cc->Decrypt(keyPair.secretKey, cz, &pt_decrypt);
    std::vector<Ciphertext<DCRTPoly>> partialsCiphertextVec;
    partialDecryptions(cc, cz, keyPairs, partialsCiphertextVec);
    cc->MultipartyDecryptFusion(partialsCiphertextVec, &pt_decrypt);

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

  //std::cout << "l="<<l<<"; u="<<u<<";\n\n";
  aca.clear();
  aca.push_back(make_pair(a,ca));
  if (l==u && l!=0)
    return {(double)l};
  else
    return {(double)l, (double)u};
}

/*
  Print noise in the interval [-modulus/2, modulus/2[
*/
void print_noise(NativeInteger noise, NativeInteger modulus){
  if (noise > (modulus>>1)){
    noise = modulus - noise;
    noise = noise%PT_MODULUS;
    std::cout << "**********************************************\n"
	 << "Noise of this ciphertext: -" << noise << "\n";
  }else{
    noise = noise%PT_MODULUS;
    std::cout << "**********************************************\n"
	 << "Noise of this ciphertext: +" << noise << "\n";
  }
}

std::string true_noise_to_string(NativeInteger noise, NativeInteger modulus){
  if (noise > (modulus>>1)){
    noise = modulus - noise;
    noise = noise%PT_MODULUS;
    return "-"+std::to_string((long unsigned int)noise);
  }
  noise = noise%PT_MODULUS;
  return "+"+std::to_string((long unsigned int)noise);
}

/*
  Print the found absolute noise
*/
void print_found_absolute_noise(std::string name, const std::vector<double>& e0){
  std::cout << name << " = [ ";
  for(int i = 0; i<(int)e0.size(); ++i){
      std::cout << (((uint128_t)e0[i])%PT_MODULUS) << " ";
  }
  std::cout << "]\n";
}

/*
  Make a string for the found absolute noise
*/
std::string found_noise_to_string(std::vector<double>& e0){
  std::string found_absolute_noise = "";
  found_absolute_noise = found_absolute_noise +"[ ";
  for(int i = 0; i<(int)e0.size(); ++i){
      found_absolute_noise = found_absolute_noise + to_string(((uint128_t)e0[i])%PT_MODULUS) + " ";
  }
  found_absolute_noise = found_absolute_noise + "]";
  return found_absolute_noise;
}


/*
  Check if the found noise is the true noise of the original ciphertext
*/
bool is_correct_noise(NativeInteger true_noise, const std::vector<double>& found_noise, NativeInteger modulus, bool print){
  if (true_noise > (modulus>>1))
    true_noise = modulus - true_noise;
  true_noise = true_noise%PT_MODULUS;
  if(found_noise.size() != 1)
    return false;
  if(print) std::cout << "true noise: " << true_noise << " and found noise: "<< (((uint128_t)found_noise[0])%PT_MODULUS) <<"\033[39m\n";
  if(true_noise == (((uint128_t)found_noise[0])%PT_MODULUS)){
    if(print) std::cout << "\033[32mNoise found correct! \n\033[39m";
    return true;
  }
  if(print){ 
    std::cout << "\033[31mNoise found incorrect!\n";
    std::cout << "true noise: " << true_noise << " and found noise: "<< (((uint128_t)found_noise[0])%PT_MODULUS) <<"\033[39m\n";
  }
  return false;
    
}

