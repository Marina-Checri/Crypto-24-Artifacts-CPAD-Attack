#include "../include/print_functions.hpp"

/**********************************************/
/************ AUXILIARY FUNCTIONS *************/
/**********************************************/

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
  Print the progress of the attack: when an absolute noise is found, print the true noise of the ciphertext, the found absolute noise and if the attack found exactly one absolute noise, if the noise have the sign of the first noise found or if it is a sign mismatch.
*/
void print_attack_progress(std::string scheme, std::string true_noise, std::string found_noise, int found_noise_size, bool same_sign, bool check_found_noise, bool is_correct_noise, uint64_t nb_of_absolute_noise_of_same_sign_found, uint64_t nb_of_linear_equation_needed){
  std::string lib = "OpenFHE";
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
