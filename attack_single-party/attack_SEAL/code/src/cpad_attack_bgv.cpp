#include "../include/cpad_attack.hpp"

static uint64_t number_of_evaluations = 0;
static uint64_t number_of_decryptions = 0;

void strategy0(bool verbose){

  cout << "\n*********************************************\n"
       << "**************** STRATEGY 0 *****************"
       << "\n*********************************************\n\n";

  /* Parameters generation */

  EncryptionParameters parms(scheme_type::bgv);
  parms.set_poly_modulus_degree(POLY_MODULUS_DEGREE);
  sec_level_type sec_level = sec_level_type::tc256;
  cout << "Security Level: " << 256 << endl;

  parms.set_coeff_modulus(CoeffModulus::BFVDefault(POLY_MODULUS_DEGREE, sec_level));
  parms.set_plain_modulus(PLAIN_MODULUS);
  SEALContext context(parms, false, sec_level);

  cout << "Set encryption parameters and print" << endl;
  print_parameters(context);
  cout << "Parameter validation (success): " << context.parameter_error_message() << endl;

  
  uint64_t n = parms.poly_modulus_degree();
  uint128_t q;
  uint128_t coeff_modulus_q0;

    q = ((uint128_t)1) <<58;
    coeff_modulus_q0 = 0x3ffffffff040001;
  cout<< "n = "<< n <<"\n";
  cout<< "q = "<< q <<"\n";
  cout<< "coeff_modulus_q0 = "<< coeff_modulus_q0 <<"\n\n";
  //SECURITY 256 - { 4096, { 0x3ffffffff040001 } },

  KeyGenerator keygen(context);
  SecretKey secret_key = keygen.secret_key();
  PublicKey public_key;
  keygen.create_public_key(public_key);
  //RelinKeys relin_keys;
  //keygen.create_relin_keys(relin_keys);

  Encryptor encryptor(context, public_key);
  Evaluator evaluator(context);
  Decryptor decryptor(context, secret_key);
  
  /* Attack */

  int generated_ciphertexts=0;
  int ciphertexts_which_noise_has_been_found=0;

  int number_of_noiseless = 0;
  int number_of_fully_identified_noises = 0;

  Plaintext pt("0");
  Plaintext pt_decrypt;

  std::string string_true_noise = "";
  std::string string_found_noise = "";
  bool correct_noise = false;

  //Complete determination of absolute noise for a ciphertext c0 that will be the reference ciphertext.
  
  Ciphertext c0;
 noise_found_incorrect_after_checking_it:
  encryptor.encrypt(pt, c0);
  ++generated_ciphertexts;
  vector<pair<uint128_t, Ciphertext>> aca0;
  uint64_t noise =  bgv_get_secret_noise(decryptor, c0, decryptor.pool_);
  vector<uint64_t> e0 = noiseAbsEstim(q, coeff_modulus_q0, evaluator, decryptor, c0, 0, aca0);

  while (e0.size()>1 || e0[0] == 0){
    encryptor.encrypt(pt, c0);
    ++generated_ciphertexts;
    uint64_t noise =  bgv_get_secret_noise(decryptor, c0, decryptor.pool_);
    e0 = noiseAbsEstim(q, coeff_modulus_q0, evaluator, decryptor, c0, 0, aca0);
  }

  uint128_t a0 = std::get<0>(aca0[0]);
  Ciphertext ca0 = std::get<1>(aca0[0]);

  //Bingo!
  string_true_noise = true_noise_to_string(noise, coeff_modulus_q0);
  string_found_noise = found_noise_to_string(e0, coeff_modulus_q0);
  correct_noise = is_correct_noise(noise, e0, coeff_modulus_q0, false);
  if(verbose) print_attack_progress("BGV", string_true_noise, string_found_noise, e0.size(), true,CHECK_FOUND_NOISE, correct_noise, ciphertexts_which_noise_has_been_found+1, n);

  if(CHECK_FOUND_NOISE){
    if(correct_noise){
      ++ciphertexts_which_noise_has_been_found;
      ++number_of_fully_identified_noises;
    }
    else goto noise_found_incorrect_after_checking_it;
  } else {
    ++ciphertexts_which_noise_has_been_found;
    ++number_of_fully_identified_noises;
  }

  //Search for n linear equations by completely determining the noise of n ciphertexts of same noise sign.

  while (ciphertexts_which_noise_has_been_found<n){
    //First, we try to determine the absolute value of the noise of c1.
    
    Ciphertext c1;
    encryptor.encrypt(pt, c1);
    ++generated_ciphertexts;
    uint64_t noise =  bgv_get_secret_noise(decryptor, c1, decryptor.pool_);
    vector<pair<uint128_t, Ciphertext>> aca1;
    vector<uint64_t> e1 = noiseAbsEstim(q, coeff_modulus_q0, evaluator, decryptor, c1, 0, aca1);

    while (e1.size()>1){
      encryptor.encrypt(pt, c1);
      ++generated_ciphertexts;
      uint64_t noise =  bgv_get_secret_noise(decryptor, c1, decryptor.pool_);
      e1 = noiseAbsEstim(q, coeff_modulus_q0, evaluator, decryptor, c1, 0, aca1);
    }

    //If we succeed to determine the absolute noise of c1, we look to see if its noise the one of c0 have the same sign.

    uint128_t a1 = std::get<0>(aca1[0]);
    Ciphertext ca1 = std::get<1>(aca1[0]);
    if(e1[0] == 0){
      //Bingo: same sign!
      string_true_noise = true_noise_to_string(noise, coeff_modulus_q0);
      string_found_noise = found_noise_to_string(e1, coeff_modulus_q0);
      correct_noise = is_correct_noise(noise, e1, coeff_modulus_q0, false);
      if(verbose) print_attack_progress("BGV", string_true_noise, string_found_noise, e1.size(), true, CHECK_FOUND_NOISE, correct_noise, ciphertexts_which_noise_has_been_found+1, n);

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
      if((e0[0]*a0+e1[0]*a1) > (q/4)){
	//To see if c1 noise and c0 noise have the same sign, we add the ciphertexts and try to decrypt.
	Ciphertext cz;
	evaluator.add(ca0, ca1, cz);
	++number_of_evaluations;

	decryptor.decrypt(cz, pt_decrypt);
	++number_of_decryptions;
	//If the decryption is incorrect, the noises have the same sign. We have a new linear equation
	if(pt_decrypt[0] != 0){ //Incorrect decryption
          //Bingo: same sign!
          string_true_noise = true_noise_to_string(noise, coeff_modulus_q0);
          string_found_noise = found_noise_to_string(e1, coeff_modulus_q0);
          correct_noise = is_correct_noise(noise, e1, coeff_modulus_q0, false);
          if(verbose) print_attack_progress("BGV", string_true_noise, string_found_noise, e1.size(), true, CHECK_FOUND_NOISE, correct_noise, ciphertexts_which_noise_has_been_found+1, n);
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
          string_true_noise = true_noise_to_string(noise, coeff_modulus_q0);
          string_found_noise = found_noise_to_string(e1, coeff_modulus_q0);
          correct_noise = is_correct_noise(noise, e1, coeff_modulus_q0, false);
          if(verbose) print_attack_progress("BGV", string_true_noise, string_found_noise, e1.size(), false, CHECK_FOUND_NOISE, correct_noise, ciphertexts_which_noise_has_been_found, n);
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
  std::cout << "\033[1;33m[SEAL][BGV] " << "number of ciphertexts generated: " << "\033[0m"<< generated_ciphertexts << "\n";
  std::cout << "\033[1;33m[SEAL][BGV] " << "number of noiseless samples: " << "\033[0m"<< number_of_noiseless << "/" << generated_ciphertexts << "\n";
  std::cout << "\033[1;33m[SEAL][BGV] " << "number of ciphertexts which absolute noise fully determined: " << "\033[0m"<< number_of_fully_identified_noises << "/"<< generated_ciphertexts << "\n";
  std::cout << "\033[1;33m[SEAL][BGV] " << "number of evaluations: " << "\033[0m"<< number_of_evaluations << "\n";
  std::cout << "\033[1;33m[SEAL][BGV] " << "number of decryptions: " << "\033[0m"<< number_of_decryptions << "\n";

}


void strategy1(bool verbose){
  cout << "\n*********************************************\n"
       << "**************** STRATEGY 1 *****************"
       <<"\n*********************************************\n\n";

  /* Parameters generation */
  
  EncryptionParameters parms(scheme_type::bgv);
  parms.set_poly_modulus_degree(POLY_MODULUS_DEGREE);
  sec_level_type sec_level = sec_level_type::tc256;
  parms.set_coeff_modulus(CoeffModulus::BFVDefault(POLY_MODULUS_DEGREE, sec_level));
  parms.set_plain_modulus(PLAIN_MODULUS);
  SEALContext context(parms, false, sec_level);
  
  cout << "Set encryption parameters and print" << endl;
  print_parameters(context);
  cout << "Parameter validation (success): " << context.parameter_error_message() << endl;

  uint64_t n = parms.poly_modulus_degree();
  uint128_t q;
  uint128_t coeff_modulus_q0;

  q = ((uint128_t)1) <<58;
  coeff_modulus_q0 = 0x3ffffffff040001;
  cout<< "n = "<< n <<"\n";
  cout<< "q = "<< q <<"\n";
  cout<< "coeff_modulus_q0 = "<< coeff_modulus_q0 <<"\n\n";
  //SECURITY 256 - { 4096, { 0x3ffffffff040001 } },
  //SECURITY 192 - { 4096, { 0x1ffc001, 0x1fce001, 0x1fc0001 } },
  //SECURITY 128 - { 4096, { 0xffffee001, 0xffffc4001, 0x1ffffe0001 } },
  
  KeyGenerator keygen(context);
  SecretKey secret_key = keygen.secret_key();
  PublicKey public_key;
  keygen.create_public_key(public_key);
  //RelinKeys relin_keys;
  //keygen.create_relin_keys(relin_keys);

  Encryptor encryptor(context, public_key);
  Evaluator evaluator(context);
  Decryptor decryptor(context, secret_key);

  /* Attack */
  
  int generated_ciphertexts=0;
  int ciphertexts_which_noise_has_been_found=0;

  Plaintext pt("0");
  Plaintext pt_decrypt;

  bool correct_noise = false;

  //Search for n linear equations by founding n noiseless ciphertexts.
  
  while (ciphertexts_which_noise_has_been_found<n){
    Ciphertext c1;
    encryptor.encrypt(pt, c1);
    ++generated_ciphertexts;
    uint64_t noise =  bgv_get_secret_noise(decryptor, c1, decryptor.pool_);
    print_noise(noise, coeff_modulus_q0);
    vector<pair<uint128_t, Ciphertext>> aca1;
    vector<uint64_t> e1 = noiseAbsEstim(q, coeff_modulus_q0, evaluator, decryptor, c1, 0, aca1);
    print_found_absolute_noise("e1", e1, coeff_modulus_q0);
    while (e1.size()>1 || e1[0] != 0){
      encryptor.encrypt(pt, c1);
      ++generated_ciphertexts;
      uint64_t noise =  bgv_get_secret_noise(decryptor, c1, decryptor.pool_);
      print_noise(noise, coeff_modulus_q0);
      e1 = noiseAbsEstim(q, coeff_modulus_q0, evaluator, decryptor, c1, 0, aca1);
      print_found_absolute_noise("e1", e1, coeff_modulus_q0);
    }

    //We succeeded to determine a noiseless ciphertext c1

    //Bingo: same sign!
    std::string string_true_noise = true_noise_to_string(noise, coeff_modulus_q0);
    std::string string_found_noise = found_noise_to_string(e1, coeff_modulus_q0);
    correct_noise = is_correct_noise(noise, e1, coeff_modulus_q0, false);
    if(verbose) print_attack_progress("BGV", string_true_noise, string_found_noise, e1.size(), true, CHECK_FOUND_NOISE, correct_noise, ciphertexts_which_noise_has_been_found+1, n);

    if(CHECK_FOUND_NOISE){
      if(correct_noise) ++ciphertexts_which_noise_has_been_found;
    } else {
      ++ciphertexts_which_noise_has_been_found;
    }
    cout << "\033[36m++++++++++++++++++++++++++++++++++++++++++++++\033[39m\n\n";
  }
  std::cout << "\033[7;33m> " << ciphertexts_which_noise_has_been_found << " linear equations have been found! <\033[0m" << "\n";
  std::cout << "\033[1;33m[SEAL][BGV] " << "number of ciphertexts generated: " << "\033[0m"<< generated_ciphertexts << "\n";
  std::cout << "\033[1;33m[SEAL][BGV] " << "number of evaluations: " << "\033[0m"<< number_of_evaluations << "\n";
  std::cout << "\033[1;33m[SEAL][BGV] " << "number of decryptions: " << "\033[0m"<< number_of_decryptions << "\n";

}




/**********************************************/
/************** USEFUL FUNCTIONS **************/
/**********************************************/

/*
 * bgv_get_secret_noise returns the real noise of a ciphertext
 * It is a forbidden action, and to do so, we had to modify the lib, but this function is only used to verify that our attack recover correctly the noise.
 * We modify the SEAL library to access (make public) the variables (normally private) context_ and pool_ as well as the dot_product_ct_sk_array() function.
 * This modification is only used to execute the function `bgv_get_secret_noise` in our code, to verify that the attack correctly recover the noise of a ciphertext. 
 * **The modification of the SEAL lib is not used for the attack itself!**
 */
uint64_t bgv_get_secret_noise(Decryptor& decryptor, const Ciphertext &encrypted, MemoryPoolHandle pool) {
        if (!encrypted.is_ntt_form())
        {
            throw invalid_argument("encrypted must be in NTT form");
        }
  SEALContext context_ = decryptor.context_;

        auto &context_data = *context_.get_context_data(encrypted.parms_id());
        auto &parms = context_data.parms();
        auto &coeff_modulus = parms.coeff_modulus();
        auto &plain_modulus = parms.plain_modulus();
        size_t coeff_count = parms.poly_modulus_degree();
        size_t coeff_modulus_size = coeff_modulus.size();
        auto ntt_tables = iter(context_data.small_ntt_tables());

        SEAL_ALLOCATE_ZERO_GET_RNS_ITER(noise, coeff_count, coeff_modulus_size, pool);
        decryptor.dot_product_ct_sk_array(encrypted, noise, decryptor.pool_);

        inverse_ntt_negacyclic_harvey(noise, coeff_modulus_size, ntt_tables);

        //context_data.rns_tool()->decrypt_modt(noise, destination.data(), pool);


  // Return the noise of this ciphertext
  return *((uint64_t*)noise);
}

/*
  noiseAbsEstim estimate the absolute noise in a ciphertext, using CPAD actions.
*/
vector<uint64_t> noiseAbsEstim(uint128_t q, uint128_t coeff_modulus_q0, Evaluator& evaluator, Decryptor& decryptor, Ciphertext& c0, uint64_t nb_to_compare, vector<pair<uint128_t,Ciphertext>>& aca){
  vector<Ciphertext> cladder;
  cladder.push_back(c0);
  int k = 1;
  uint128_t a = 0, b = 0, z = 0;
  uint128_t l, u;
  Ciphertext ca, cb;

  Plaintext pt_decrypt;

  Ciphertext c;
  while(true){
    Ciphertext c_k_minus_1 = cladder[k-1];
    evaluator.add(c_k_minus_1, c_k_minus_1, c);
    ++number_of_evaluations;
    cladder.push_back(c);
    decryptor.decrypt(c, pt_decrypt);
    ++number_of_decryptions;
    if(pt_decrypt[0] != 0){ //Incorrect decryption
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
      //cout << "k=" << k <<", 2^k="<< (((uint128_t)1)<<k) << ", q=" <<q<<"\n";
      return {0}; // If we cannot switch to 1, noise is 0
      break;
    }
    k = k+1;
  }

  Ciphertext cz;
  while (k>0){
    z = a + (((uint128_t)1)<<(k-1));
    Ciphertext c_k_minus_1 = cladder[k-1];
    evaluator.add(ca, c_k_minus_1, cz);
    ++number_of_evaluations;
    decryptor.decrypt(cz, pt_decrypt);
    ++number_of_decryptions;
    if(pt_decrypt[0] != nb_to_compare){ //Incorrect decryption
      b =  z;
      cb = cz;
    }
    else{
      a = z;
      ca = cz;
    }
    k=k-1;
  }

  //int noise_budget = decryptor.invariant_noise_budget(c);
  //cout << "noise_budget="<<noise_budget<<"\n";

  l = ceil(q/(((uint128_t)4)*b));
  u = floor(q/(((uint128_t)4)*a));
  //cout << "a="<<a<<"; b="<<b<<";\n";
  //cout << "l="<<l<<"; u="<<u<<";\n\n";
  aca.clear();
  aca.push_back(make_pair(a,ca));
  if (l == u)
    return {(uint64_t)l};
  else
    return {(uint64_t)l, (uint64_t)u};

}


/*
  Print the found absolute noise
*/
void print_found_absolute_noise(string name, vector<uint64_t>& e0, uint128_t coeff_modulus_q0){
  cout << name << " = [ ";
  for(int i = 0; i<(int)e0.size(); ++i)
    cout << (2*e0[i] % coeff_modulus_q0)<<" ";
  cout << "]\n";
}

std::string found_noise_to_string(vector<uint64_t>& e0, uint128_t coeff_modulus_q0){
  std::string found_absolute_noise = "";
  found_absolute_noise = found_absolute_noise+"[ ";
  for(int i = 0; i<(int)e0.size(); ++i)
    found_absolute_noise = found_absolute_noise + to_string(2*e0[i] % coeff_modulus_q0)+" ";
  found_absolute_noise = found_absolute_noise+"]";
  return found_absolute_noise;
}



/*
  Check if the found noise is the true noise of the original ciphertext
*/
bool is_correct_noise(uint64_t true_noise, vector<uint64_t>& found_noise, uint128_t coeff_modulus_q0, bool print){
  if (true_noise > (coeff_modulus_q0>>1))
    true_noise = coeff_modulus_q0 - true_noise;
  if(found_noise.size() != 1)
    return false;
  if(true_noise == ((2*found_noise[0] % coeff_modulus_q0))){
    if(print) cout << "\033[32mNoise found correct! \n\033[39m";
    return true;
  }else{
    if(print) cout << "\033[31mNoise found incorrect!\n\033[39m";
    cout << "true noise: " << true_noise << " and found noise: "<< ((found_noise[0] % coeff_modulus_q0))<<"\n";
    return false;
  }
}





