#include "cpad.h"

using namespace std;

static TFheGateBootstrappingParameterSet* default_parameters()
{
  const int32_t N = 1024;
  const int32_t k = 1;
  const int32_t n = 630;
  const int32_t bk_l = 3;
  const int32_t bk_Bgbit = 7;
  const int32_t ks_basebit = 2;
  const int32_t ks_length = 8;
  const double ks_stdev = pow(2.,-15); //standard deviation
  const double bk_stdev = pow(2.,-15); //standard deviation
  const double max_stdev = 0.012467; //max standard deviation for a 1/4 msg space

  LweParams* params_in = new_LweParams(n, ks_stdev, max_stdev);
  TLweParams* params_accum = new_TLweParams(N, k, bk_stdev, max_stdev);
  TGswParams* params_bk = new_TGswParams(bk_l, bk_Bgbit, params_accum);

  TfheGarbageCollector::register_param(params_in);
  TfheGarbageCollector::register_param(params_accum);
  TfheGarbageCollector::register_param(params_bk);

  return new TFheGateBootstrappingParameterSet(ks_length, ks_basebit, params_in, params_bk);
}

static TFheGateBootstrappingParameterSet* wahc23_b16_parameters()
{
  const int32_t N = 2048;
  const int32_t k = 1;
  const int32_t n = 1024;
  const int32_t bk_l = 3;
  const int32_t bk_Bgbit = 8;
  const int32_t ks_basebit = 10;
  const int32_t ks_length = 2;
  const double ks_stdev = 6.5 * pow(10,-8); //standard deviation
  const double bk_stdev = 9.6 * pow(10,-11); //standard deviation
  const double max_stdev = 0.015625; //max standard deviation for a 1/16 msg space

  LweParams* params_in = new_LweParams(n, ks_stdev, max_stdev);
  TLweParams* params_accum = new_TLweParams(N, k, bk_stdev, max_stdev);
  TGswParams* params_bk = new_TGswParams(bk_l, bk_Bgbit, params_accum);

  TfheGarbageCollector::register_param(params_in);
  TfheGarbageCollector::register_param(params_accum);
  TfheGarbageCollector::register_param(params_bk);

  return new TFheGateBootstrappingParameterSet(ks_length, ks_basebit, params_in, params_bk);
}

static TFheGateBootstrappingParameterSet* wahc23_b4_parameters()
{
  const int32_t N = 1024;
  const int32_t k = 1;
  const int32_t n = 1024;
  const int32_t bk_l = 5;
  const int32_t bk_Bgbit = 4;
  const int32_t ks_basebit = 10;
  const int32_t ks_length = 2;
  const double ks_stdev = 1.9 * pow(10,-5); //standard deviation
  const double bk_stdev = 5.6 * pow(10,-8); //standard deviation
  const double max_stdev = 0.0625; //max standard deviation for a 1/4 msg space

  LweParams* params_in = new_LweParams(n, ks_stdev, max_stdev);
  TLweParams* params_accum = new_TLweParams(N, k, bk_stdev, max_stdev);
  TGswParams* params_bk = new_TGswParams(bk_l, bk_Bgbit, params_accum);

  TfheGarbageCollector::register_param(params_in);
  TfheGarbageCollector::register_param(params_accum);
  TfheGarbageCollector::register_param(params_bk);

  return new TFheGateBootstrappingParameterSet(ks_length, ks_basebit, params_in, params_bk);
}

int compute_poweroftwo(LweSample* ct, const LweParams* params, const LweKey* key, uint64_t plain_mod, bool print_info)
{
  int out = 0, i = 0;
  int n =  params->n;

  while (out != 1) {
    ++i;
    if (i == 32) {
      if(print_info) cout << "\033[1;34m[tfhe] noise = 0 \033[0m" << endl;
      out = 1;
      ++i;
    }
    else {
      LweSample* tmp = new_LweSample(params);
      int powtwo = (int)pow(2,i);
      tmp->b = powtwo * ct->b;
      for (int j = 0; j < n; ++j)
        tmp->a[j] = powtwo * ct->a[j];

      Torus32 decr = lweSymDecrypt(tmp, key, plain_mod);
      out = modSwitchFromTorus32(decr, plain_mod);
      Torus32 phase = lwePhase(tmp, key);

      if (print_info) {
        cout << "[tfhe] powtwo: " << powtwo << endl;
        cout << "[tfhe] out (torus): " << decr  << "\t out: "<< out << endl;
        cout << "[tfhe] phase: " << phase << endl;
      }
      delete_LweSample(tmp);
    }
  }
  return (i-1);
}

int compute_alpha(LweSample* ct, const LweParams* params, const LweKey* key, uint64_t plain_mod, int k, bool print_info)
{
  if (k == 32) {
    if(print_info) cout << "\033[1;34m[tfhe] noise = 0 \033[0m" << endl;
    return 0;
  }
  else {
    int out = 0, alpha = 0;
    int n =  params->n;
    int down = (int)pow(2,k);
    int up = (int)pow(2,k+1);

    while (out == 0) {
      int i = (int)(up-down)/2 + down;
      LweSample* tmp = new_LweSample(params);
      tmp->b = i * ct->b;
      for (int j = 0; j < n; ++j)
        tmp->a[j] = i * ct->a[j];

      Torus32 decr = lweSymDecrypt(tmp, key, plain_mod);
      out = modSwitchFromTorus32(decr, plain_mod);
      Torus32 phase = lwePhase(tmp, key);

      if (print_info) {
        cout << "[tfhe] 1st: " << i << endl;
        cout << "[tfhe] out (torus): " << decr  << "\t out: "<< out << endl;
        cout << "[tfhe] phase: " << phase << endl;
      }

      int out_tmp = out;
      if (out == 0) {
        tmp->b = (i+1) * ct->b;
        for (int j = 0; j < n; ++j)
          tmp->a[j] = (i+1) * ct->a[j];

        decr = lweSymDecrypt(tmp, key, plain_mod);
        out = modSwitchFromTorus32(decr, plain_mod);
        phase = lwePhase(tmp, key);

        alpha = i;
        down = i+1;

        if (print_info)
          cout << "[tfhe] 2nd: " << i+1 << endl;
      }
      else {
        tmp->b = (i-1) * ct->b;
        for (int j = 0; j < n; ++j)
          tmp->a[j] = (i-1) * ct->a[j];

        decr = lweSymDecrypt(tmp, key, plain_mod);
        out = modSwitchFromTorus32(decr, plain_mod);
        phase = lwePhase(tmp, key);

        alpha = i-1;
        up = i;

        if (print_info)
          cout << "[tfhe] 2nd: " << i-1 << endl;
      }

      if (print_info) {
        cout << "[tfhe] out (torus): " << decr  << "\t out: "<< out << endl;
        cout << "[tfhe] phase: " << phase << endl;
      }

      out ^= out_tmp;

      delete_LweSample(tmp);
    }
    return alpha;
  }
}

int compute_alpha(LweSample* ct, const LweParams* params, const LweKey* key, uint64_t plain_mod, int k, int& ctr, bool print_info)
{
  if (k == 32) {
    if(print_info) cout << "\033[1;34m[tfhe] noise = 0 \033[0m" << endl;
    return 0;
  }
  else {
    int out = 0, alpha = 0;
    int n =  params->n;
    int down = (int)pow(2,k);
    int up = (int)pow(2,k+1);
    ctr = 0;

    while (out == 0) {
      int i = (int)(up-down)/2 + down;
      LweSample* tmp = new_LweSample(params);
      tmp->b = i * ct->b;
      for (int j = 0; j < n; ++j)
        tmp->a[j] = i * ct->a[j];

      Torus32 decr = lweSymDecrypt(tmp, key, plain_mod);
      out = modSwitchFromTorus32(decr, plain_mod);
      Torus32 phase = lwePhase(tmp, key);

      if (print_info) {
        cout << "[tfhe] 1st: " << i << endl;
        cout << "[tfhe] out (torus): " << decr  << "\t out: "<< out << endl;
        cout << "[tfhe] phase: " << phase << endl;
      }

      int out_tmp = out;
      if (out == 0) {
        tmp->b = (i+1) * ct->b;
        for (int j = 0; j < n; ++j)
          tmp->a[j] = (i+1) * ct->a[j];

        decr = lweSymDecrypt(tmp, key, plain_mod);
        out = modSwitchFromTorus32(decr, plain_mod);
        phase = lwePhase(tmp, key);

        alpha = i;
        down = i+1;

        if (print_info)
          cout << "[tfhe] 2nd: " << i+1 << endl;
      }
      else {
        tmp->b = (i-1) * ct->b;
        for (int j = 0; j < n; ++j)
          tmp->a[j] = (i-1) * ct->a[j];

        decr = lweSymDecrypt(tmp, key, plain_mod);
        out = modSwitchFromTorus32(decr, plain_mod);
        phase = lwePhase(tmp, key);

        alpha = i-1;
        up = i;

        if (print_info)
          cout << "[tfhe] 2nd: " << i-1 << endl;
      }

      if (print_info) {
        cout << "[tfhe] out (torus): " << decr  << "\t out: "<< out << endl;
        cout << "[tfhe] phase: " << phase << endl;
      }

      out ^= out_tmp;
      ctr += 2;
      delete_LweSample(tmp);
    }
    return alpha;
  }
}

std::vector<int> compute_noise(int a0, int a1)
{
  if (a0 == 0) {
    return {0};
  }
  else {
    int down = (int)floor(pow(2.,32)/(4*a0));
    int up = (int)ceil(pow(2.,32)/(4*a1));

    if (down == up) {
      return {down};
    }
    else {
      return {down, up};
    }
  }
}

std::vector<int> compute_noise(int a0, int a1, int& noise)
{
  if (a0 == 0) {
    noise = 0;
    return {0};
  }
  else {
    int down = (int)floor(pow(2.,32)/(4*a0));
    int up = (int)ceil(pow(2.,32)/(4*a1));

    if (down == up) {
      noise  = down;
      return {down};
    }
    else {
      noise =  -1;
      return {down, up};
    }
  }
}

void test_cpad(uint64_t plain_mod, int64_t pt_msg, int n_samples, bool print_info, bool verbose)
{
  cout << "************************" << endl;
  cout << "**** test tfhe cpad ****" << endl;
  cout << "************************" << endl;

  TFheGateBootstrappingParameterSet* params = wahc23_b4_parameters();
  TFheGateBootstrappingSecretKeySet* key = new_random_gate_bootstrapping_secret_keyset(params);

  double alpha_min = key->lwe_key->params->alpha_min;
  Torus32 pt = modSwitchToTorus32(pt_msg, plain_mod);

  int ctr = 0;
  int ctr_zero = 0;

  for (int i = 0; i < n_samples; ++i) {
    cout << "[tfhe] sample number: " << i+1 << endl;
    LweSample* ct = new_LweSample(key->lwe_key->params);
    lweSymEncrypt(ct, pt, alpha_min, key->lwe_key);

    Torus32 decr = lweSymDecrypt(ct, key->lwe_key, plain_mod);
    Torus32 phase = lwePhase(ct, key->lwe_key);

    cout << "[tfhe] out (torus): " << decr  << "\t out: "<< modSwitchFromTorus32(decr, plain_mod) << endl;
    cout << "[tfhe] phase: " << phase << endl;

    int k = compute_poweroftwo(ct, key->lwe_key->params, key->lwe_key, plain_mod, print_info);
    int alpha = compute_alpha(ct, key->lwe_key->params, key->lwe_key, plain_mod, k, print_info);
    std::vector<int> ret = compute_noise(alpha, alpha+1);
    if (ret.size() == 1 && ret[0] != 0)
      ctr += 1;
    if (ret.size() == 1 && ret[0] == 0)
      ctr_zero += 1;

    delete_LweSample(ct);
    cout << endl;
  }

  cout << "\033[1;33m[tfhe] number of good samples: \033[0m" << ctr << "/" << n_samples << endl;
  cout << "\033[1;33m[tfhe] number of noiseless samples: \033[0m" << ctr_zero << "/" << n_samples << endl;


  delete_gate_bootstrapping_secret_keyset(key);
  delete_gate_bootstrapping_parameters(params);
}

void test_cpad_simple(uint64_t plain_mod, int64_t pt_msg, bool print_info, bool verbose)
{
  cout << "************************" << endl;
  cout << "**** test tfhe cpad ****" << endl;
  cout << "************************" << endl;

  /*** lwe params and key ***/
/*
  const int32_t n = 630;
  const double ks_stdev = pow(2.,-15); //standard deviation
  const double max_stdev = 0.012467; //max standard deviation for a 2 msg space
*/

/*
     const int32_t n = 1024;
     const double ks_stdev = 1.9 * pow(10,-5); //standard deviation
     const double max_stdev = 0.0625; //max standard deviation for a 4 msg space
*/

     const int32_t n = 1024;
     const double ks_stdev = 6.5 * pow(10,-8); //standard deviation
     const double max_stdev = 0.015625; //max standard deviation for a 16 msg space


/*
     const int32_t n = 700;
     const double ks_stdev = 1.9 * pow(10,-5); //standard deviation
     const double max_stdev = 0.25; //max standard deviation for a 2 msg space
*/

  //cout << "Parameters.\n";
  //cout << "Lwe sample dimension n: " << n << endl;
  //cout << "Noise standard deviation: " << ks_stdev << endl;

  //Parameters of the scheme

  std::cout << "\033[7;33m> Parameters of the scheme <\033[0m" << "\n";
  std::cout << "\033[1;33m[tfheLib][TFHE] " << " n        = " << "\033[0m"<< n << "\n";
  std::cout << "\033[1;33m[tfheLib][TFHE] " << " log_2(q) = " << "\033[0m"<< 32 << "\n";
  std::cout << "\033[1;33m[tfheLib][TFHE] " << " sigma    = " << "\033[0m"<< ks_stdev << "\n";
  std::cout << "\033[1;33m[tfheLib][TFHE] " << " t        = " << "\033[0m"<< plain_mod << "\n\n";

  LweParams* lwe_params = new_LweParams(n, ks_stdev, max_stdev);
  TfheGarbageCollector::register_param(lwe_params);
  LweKey* lwe_key = new_LweKey(lwe_params);
  lweKeyGen(lwe_key);
  Torus32 pt = modSwitchToTorus32(pt_msg, plain_mod);

  int ctr = 0;
  int ctr_zero = 0;
  int ctr_pwroftwo = 0;
  int ctr_dicho = 0;
  int ctr_sign = 0;
  vector<LweSample*> ct_out;
  vector<int> ct_noise(0);
  int noise = 0;
  int alpha_zero = 0;
  int nbr_samples = 0;
  int i = 0;

  while (i < n) {
    ++nbr_samples;
    LweSample* ct = new_LweSample(lwe_params);
    lweSymEncrypt(ct, pt, lwe_params->alpha_min, lwe_key);
    Torus32 decr = lweSymDecrypt(ct, lwe_key, plain_mod);
    Torus32 phase = lwePhase(ct, lwe_key);

    int k = compute_poweroftwo(ct, lwe_params, lwe_key, plain_mod, print_info);
    ctr_pwroftwo += k+1;
    int ktr = 0;
    int alpha = compute_alpha(ct, lwe_params, lwe_key, plain_mod, k, ktr, print_info);
    ctr_dicho += ktr;
    std::vector<int> ret = compute_noise(alpha, alpha+1, noise);

    if (ret.size() == 1 && ret[0] != 0){
      //We fully determined the absolute value of the noise
      ctr += 1;
      if (ct_out.empty()) {
        //Bingo!
        ct_out.push_back(ct);
        ct_noise.push_back(noise);
        alpha_zero = alpha;
        ++i;
        if(verbose) print_attack_progress("TFHE", to_string(phase), found_noise_to_string(ret), ret.size(), true, false, false, i, n);
      }
      else {
        //To see if ct noise and ct_out noise have the same sign, we add the ciphertexts and try to decrypt.
        LweSample* ct_tmp = new_LweSample(lwe_params);
        ct_tmp->b = alpha * ct->b + alpha_zero * ct_out[0]->b;
        for (int j = 0; j < n; ++j)
          ct_tmp->a[j] = alpha * ct->a[j] + alpha_zero * ct_out[0]->a[j];
        decr = lweSymDecrypt(ct_tmp, lwe_key, plain_mod);
        int out = modSwitchFromTorus32(decr, plain_mod);
        delete_LweSample(ct_tmp);
        ctr_sign += 1;
        //If the decryption is incorrect (1 instead of 0), the noises have the same sign. We have a new linear equation
        if (out == 1) {
          //Bingo!
          ct_out.push_back(ct);
          ct_noise.push_back(noise);
          ++i;
          if(verbose) print_attack_progress("TFHE", to_string(phase), found_noise_to_string(ret), ret.size(), true, false, false, i, n);
        } else {
          //Sign mismatch
          if(verbose) print_attack_progress("TFHE", to_string(phase), found_noise_to_string(ret), ret.size(), false, false, false, i, n);
        }
      }
    }
    if (ret.size() == 1 && ret[0] == 0){
      //Bingo! Found a noiseless ciphertext
      ctr_zero += 1;
      if (!ct_out.empty()) {
        ct_out.push_back(ct);
        ct_noise.push_back(noise);
        ++i;
        if(verbose) print_attack_progress("TFHE", to_string(phase), found_noise_to_string(ret), ret.size(), true, false, false, i, n);
      }
    }
    if(ret.size() > 1){
      // Found an interval for the noise value
      if(verbose) print_attack_progress("TFHE", to_string(phase), found_noise_to_string(ret), ret.size(), true, false, false, i, n);
    }
  }

  if(verbose){
    std::cout << "\033[7;33m> Parameters of the scheme <\033[0m" << "\n";
    std::cout << "\033[1;33m[tfheLib][TFHE] " << " n        = " << "\033[0m"<< n << "\n";
    std::cout << "\033[1;33m[tfheLib][TFHE] " << " log_2(q) = " << "\033[0m"<< 32 << "\n";
    std::cout << "\033[1;33m[tfheLib][TFHE] " << " sigma    = " << "\033[0m"<< ks_stdev << "\n";
    std::cout << "\033[1;33m[tfheLib][TFHE] " << " t        = " << "\033[0m"<< plain_mod << "\n\n";
  }

  cout << "\033[7;33m> " << i << " linear equations have been found! <\033[0m" << "\n";
  cout << "\033[1;33m[tfheLib][TFHE] " << "number of ciphertexts generated: " << "\033[0m"<< nbr_samples << "\n";
  cout << "\033[1;33m[tfheLib][TFHE] " << "number of noiseless samples: " << "\033[0m"<< ctr_zero << "/" << nbr_samples << "\n";
  cout << "\033[1;33m[tfheLib][TFHE] " << "number of ciphertexts which absolute noise fully determined: " << "\033[0m"<< ctr << "/"<< nbr_samples << "\n";
  cout << "\033[1;33m[tfheLib][TFHE] " << "number of evaluations: " << "\033[0m"<< ctr_pwroftwo + ctr_dicho + ctr_sign << "\n";
  cout << "\033[1;33m[tfheLib][TFHE] " << "number of decryptions: " << "\033[0m"<< ctr_pwroftwo + ctr_dicho + ctr_sign << "\n";

  for (int l = 0; l < ct_out.size(); ++l) {
    vector<int64_t> in_csv(n+2);
    for (int m = 0; m < n; ++m)
      in_csv[m] = (int64_t)ct_out[l]->a[m];
    in_csv[n] = (int64_t)ct_out[l]->b;
    in_csv[n+1] = (int64_t)ct_noise[l];
    write_to_csv_file("lwe.csv", in_csv, 1);

    delete_LweSample(ct_out[l]);
  }
  delete_LweKey(lwe_key);
  delete_LweParams(lwe_params);
}


/*
  Print the progress of the attack: when an absolute noise is found, print the true noise of the ciphertext, the found absolute noise and if the attack found exactly one absolute noise, if the noise have the sign of the first noise found or if it is a sign mismatch.
*/
void print_attack_progress(std::string scheme, std::string true_noise, std::string found_noise, int found_noise_size, bool same_sign, bool check_found_noise, bool is_correct_noise, uint64_t nb_of_absolute_noise_of_same_sign_found, uint64_t nb_of_linear_equation_needed){
  std::string lib = "tfheLib";
  std::cout << "["<< lib<<"]["<<scheme<<"] Ciphertext true noise:   "<<true_noise<<"\n";
  std::cout << "["<< lib<<"]["<<scheme<<"] Found noise:            "<<found_noise<<"\n";
  if(found_noise_size == 1){
    std::cout << "["<< lib<<"]["<<scheme<<"] Same sign or sign mismatch: ";
    if(same_sign){
      std::cout << "\033[36mSame sign\033[39m";
    }else{
      std::cout << "\033[35mSign mismatch\033[39m";
    }
    std::cout <<".\n";
    if(check_found_noise){
      std::cout << "["<< lib<<"]["<<scheme<<"] Is absolute noise found correct? ";
      if(is_correct_noise){
        std::cout << "\033[32mYes!\033[39m";
      }else{
        std::cout << "\033[31mNo.\033[39m";
      }
      std::cout << "\n";
    }
  
    std::cout << "Nb of absolute noise of same sign found:  "<<nb_of_absolute_noise_of_same_sign_found<<"/"<<nb_of_linear_equation_needed<<"\n";
  }
  std::cout <<"\n";
}

/*
  Make a string for the found absolute noise
*/
std::string found_noise_to_string(std::vector<int>& found_noise){
  std::string found_absolute_noise = "";
  found_absolute_noise = found_absolute_noise +"[ ";
  for(int i = 0; i<(int)found_noise.size(); ++i){
      found_absolute_noise = found_absolute_noise + to_string(found_noise[i]) + " ";
  }
  found_absolute_noise = found_absolute_noise + "]";
  return found_absolute_noise;
}

