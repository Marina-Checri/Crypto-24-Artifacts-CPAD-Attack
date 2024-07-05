#include <string>
#include "cpad.h"

using namespace std;

int main(int argc, char **argv)
{
  bool verbose = true;
  if (argc>1) {
    std::string argv1(argv[1]);
    verbose = (argv1 == "--no-verbose") ? false : true;
  }

  /* tfhe cpad attack */

  //test_cpad(2, 0, 1000, 0, verbose);

  test_cpad_simple(2, 0, 0, verbose);

  return 0;
}
