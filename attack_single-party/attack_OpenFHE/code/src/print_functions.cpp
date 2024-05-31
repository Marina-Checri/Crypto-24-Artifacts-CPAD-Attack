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
  Print noise in the interval [-modulus/2, modulus/2[
*/
void print_noise(NativeInteger noise, NativeInteger modulus, Scheme scheme){
  switch (scheme) {
    case BGV:
      {
        if (noise > (modulus>>1)){
          noise = modulus - noise;
          noise = noise / PT_MODULUS - 1;
          std::cout << "**********************************************\n"
	 << "Noise of this ciphertext: -" << noise << "\n";
        }else{
          noise = noise / PT_MODULUS - 1;
          std::cout << "**********************************************\n"
	 << "Noise of this ciphertext: +" << noise << "\n";
        }
        break;
      }
    case BFV:
    default:
      {
        //noise = noise % PT_MODULUS;
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
        break;
      }
  }
}

std::string true_noise_to_string(NativeInteger noise, NativeInteger modulus, Scheme scheme){
  switch (scheme) {
    case BGV:
      {
        if (noise > (modulus>>1)){
          noise = modulus - noise;
          noise = noise / PT_MODULUS - 1;
          return "-"+std::to_string((long unsigned int)noise);
        }
        noise = noise / PT_MODULUS - 1;
        return "+"+std::to_string((long unsigned int)noise);
      }
    case BFV:
    default:
      {
        //noise = noise % PT_MODULUS;
        if (noise > (modulus>>1)){
          noise = modulus - noise;
          noise = noise%PT_MODULUS;
          return "-"+std::to_string((long unsigned int)noise);
        }
        noise = noise%PT_MODULUS;
        return "+"+std::to_string((long unsigned int)noise);
      }
  }
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

int save_csv_ciphertext(std::string file_name, Ciphertext<DCRTPoly>& ciphertext, std::vector<uint64_t>& found_noise){
    if(found_noise.size()!=1) return -1;
    //Ciphertext c0 -> get a and b, then get bPoly and bcoeff0
    auto elements = ciphertext->GetElements();
    DCRTPoly b = elements[0];
    DCRTPoly a = elements[1];

    b.SetFormat(Format::COEFFICIENT);
    // Interpolate b DCRTPoly to get a bPoly
    Poly bPoly = b.CRTInterpolate();
    //Get the first coefficient of the interpolated Poly
    BigInteger bcoef0 = bPoly.at(0);
    if (bcoef0 > (bPoly.GetModulus() >> 1))
      bcoef0 = bPoly.GetModulus() - bcoef0;


    // Open the CSV file for appending
    std::ofstream file(file_name, std::ios::app);
    if (!file.is_open()) {
        std::cerr << "Error: Unable to open the CSV file!\n";
        return -1;
    }

    //Save a and bcoeff0 and found_noise[0] in the CSV file
    //file << ciphertext << ","; // Modify this line based on how you want to serialize ciphertext
    file << a << ","; // Modify this line based on how you want to serialize ciphertext
    file << bcoef0 << ","; // Modify this line based on how you want to serialize ciphertext
    file << found_noise[0];
    //file << ",";    
    file << std::endl;

    // Close the file
    file.close();
    return 0;
}

