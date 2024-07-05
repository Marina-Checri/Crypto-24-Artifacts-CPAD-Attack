#include "../include/print_functions.hpp"
#include "../include/bgv_cpad_attack.hpp"

/**********************************************/
/******************** MAIN ********************/
/**********************************************/

int main(int argc, char *argv[]){
  bool verbose = true;
  if (argc>1) {
    std::string argv1(argv[1]);
    verbose = (argv1 == "--no-verbose") ? false : true;
  }
  bgv_strategy0(verbose);
    
  return 0;
}



