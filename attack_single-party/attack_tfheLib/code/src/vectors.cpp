#include "vectors.h"

using namespace std;

void print_vectors(vector<int64_t> &v)
{
  for (size_t i = 0; i < v.size(); ++i)
    cout << v[i] << " ";
  cout << endl;
}

void print_vectors(vector<double> &v)
{
  for (size_t i = 0; i < v.size(); ++i)
    cout << v[i] << " ";
  cout << endl;
}

void print_matrix(vector<vector<int64_t>> &m)
{
  for (size_t i = 0; i < m.size(); ++i)
    print_vectors(m[i]);
}

void print_matrix(vector<vector<double>> &m)
{
  for (size_t i = 0; i < m.size(); ++i)
    print_vectors(m[i]);
}

/*void rand_vector(int seed, uint64_t v_space, uint32_t v_size, vector<int64_t>& v)
{
  srand(seed);
  for (uint32_t i = 0; i < v_size; ++i)
    v[i] = rand() % v_space;
}
*/

void rand_vector(int seed, uint64_t v_space, uint32_t v_size, vector<int64_t>& v)
{
  std::uniform_real_distribution<double> unif(0, v_space);
  std::default_random_engine re;
  re.seed(seed);
  for (uint32_t i = 0; i < v_size; ++i)
    v[i] = (int64_t)unif(re) % v_space;
}

void rand_vector(int seed, uint64_t v_space, uint32_t v_size, vector<double>& v)
{
  std::uniform_real_distribution<double> unif(0, v_space);
  std::default_random_engine re;
  re.seed(seed);
  for (uint32_t i = 0; i < v_size; ++i)
    v[i] = unif(re);
}
