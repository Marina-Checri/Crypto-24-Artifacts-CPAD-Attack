#ifndef _VECTORS_H_
#define _VECTORS_H_

/* includes */
#include <iostream>
#include <random>
#include <cstdio>
#include <vector>
#include <time.h>

/* prototypes */
void print_vectors(std::vector<int64_t>& v);
void print_vectors(std::vector<double> &v);

void print_matrix(std::vector<std::vector<int64_t>>& m);
void print_matrix(std::vector<std::vector<double>>& m);

void rand_vector(int seed, uint64_t v_space, uint32_t v_size, std::vector<int64_t>& v);
void rand_vector(int seed, uint64_t v_space, uint32_t v_size, std::vector<double>& v);

#endif
