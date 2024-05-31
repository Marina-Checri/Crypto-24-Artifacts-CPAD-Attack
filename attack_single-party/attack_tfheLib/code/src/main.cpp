#include <string>
#include "cpad.h"

using namespace std;

int main(int argc, char **argv)
{
  /* tfhe cpad attack */
  //test_cpad(2, 0, 1000, 0);
  test_cpad_simple(2, 0, 0);
  return 0;
}
