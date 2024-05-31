#include "../include/print_functions.hpp"

/**********************************************/
/************ AUXILIARY FUNCTIONS *************/
/**********************************************/

/*
  Helper function: Prints the parameters in a SEALContext.
*/
void print_parameters(const seal::SEALContext &context) {
  auto &context_data = *context.key_context_data();

  //Print scheme
  std::string scheme_name;
  switch (context_data.parms().scheme())
    {
    case seal::scheme_type::bfv:
      scheme_name = "BFV";
      break;
    case seal::scheme_type::ckks:
      scheme_name = "CKKS";
      break;
    case seal::scheme_type::bgv:
      scheme_name = "BGV";
      break;
    default:
      throw std::invalid_argument("unsupported scheme");
    }
  std::cout << "/" << std::endl;
  std::cout << "| Encryption parameters :" << std::endl;
  std::cout << "|   scheme: " << scheme_name << std::endl;
  std::cout << "|   poly_modulus_degree: " << context_data.parms().poly_modulus_degree() << std::endl;

  // Print the size of the true (product) coefficient modulus.
  std::cout << "|   coeff_modulus size: ";
  std::cout << context_data.total_coeff_modulus_bit_count() << " (";
  auto coeff_modulus = context_data.parms().coeff_modulus();
  std::size_t coeff_modulus_size = coeff_modulus.size();
  for (std::size_t i = 0; i < coeff_modulus_size - 1; i++)
    {
      std::cout << coeff_modulus[i].bit_count() << " + ";
    }
  std::cout << coeff_modulus.back().bit_count();
  std::cout << ") bits" << std::endl;

  //For the BFV scheme print the plain_modulus parameter.
  if (context_data.parms().scheme() == seal::scheme_type::bfv)
    {
      std::cout << "|   plain_modulus: " << context_data.parms().plain_modulus().value() << std::endl;
    }

  std::cout << "\\" << std::endl;
}

/*
  Override << for uint128_t
*/
std::ostream& operator<<(std::ostream& dest, uint128_t value){
  std::ostream::sentry s(dest);
  if (s) {
    uint128_t tmp = value < 0 ? -value : value;
    char buffer[128];
    char* d = std::end(buffer);
    do{
      --d;
      *d = "0123456789"[tmp%10];
      tmp /= 10;
    } while(tmp != 0);
    if(value < 0) {
      --d;
      *d = '-';
    }
    int len = std::end(buffer)-d;
    if(dest.rdbuf()->sputn(d, len) != len) {
      dest.setstate(std::ios_base::badbit);
    }
  }
  return dest;
}

std::string to_string(uint128_t value) {
    std::ostringstream oss;
    oss << value;
    return oss.str();
}

/*
  Print noise in the interval [-coeff_modulus_q0/2, coeff_modulus_q0/2[
*/
void print_noise(uint64_t noise, uint128_t coeff_modulus_q0){
  if (noise > (coeff_modulus_q0>>1)){
    noise = coeff_modulus_q0 - noise;
    cout << "**********************************************\n"
	 << "Noise of this ciphertext: -" << noise << "\n";
  }else{
    cout << "**********************************************\n"
	 << "Noise of this ciphertext: +" << noise << "\n";
  }
}

std::string true_noise_to_string(uint64_t noise, uint128_t coeff_modulus_q0){
  if (noise > (coeff_modulus_q0>>1)){
    noise = coeff_modulus_q0 - noise;
    return "-"+std::to_string(noise);
  }else{
    return "+"+std::to_string(noise);
  }
}

/*
  Print the progress of the attack: when an absolute noise is found, print the true noise of the ciphertext, the found absolute noise and if the attack found exactly one absolute noise, if the noise have the sign of the first noise found or if it is a sign mismatch.
*/
void print_attack_progress(std::string scheme, std::string true_noise, std::string found_noise, int found_noise_size, bool same_sign, bool CHECK_FOUND_NOISE, bool is_correct_noise, uint64_t nb_of_absolute_noise_of_same_sign_found, uint64_t nb_of_linear_equation_needed){
  std::string lib = "SEAL";
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
    if(CHECK_FOUND_NOISE){
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

