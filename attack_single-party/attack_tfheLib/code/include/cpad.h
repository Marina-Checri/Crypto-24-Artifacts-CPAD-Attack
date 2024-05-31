#ifndef _CPAD_H_
#define _CPAD_H_

/* includes */
#include <chrono>
#include <iostream>
#include <cassert>
#include <tfhe/tfhe_io.h>
#include <tfhe/tfhe_garbage_collector.h>
#include <tfhe/tfhe.h>
#include "csv.h"

/* prototypes */
int compute_poweroftwo(LweSample* ct, const LweParams* params, const LweKey* key, uint64_t plain_mod, bool print_info);
int compute_alpha(LweSample* ct, const LweParams* params, const LweKey* key, uint64_t plain_mod, int k, bool print_info);
int compute_alpha(LweSample* ct, const LweParams* params, const LweKey* key, uint64_t plain_mod, int k, int& ctr, bool print_info);
std::vector<int> compute_noise(int a0, int a1);
std::vector<int> compute_noise(int a0, int a1, int& noise);
void test_cpad(uint64_t plain_mod, int64_t pt_msg, int n_samples, bool print_info);
void test_cpad_simple(uint64_t plain_mod, int64_t pt_msg, bool print_info);

std::string found_noise_to_string(std::vector<int>& found_noise);
void print_attack_progress(std::string scheme, std::string true_noise, std::string found_noise, int found_noise_size, bool same_sign, bool check_found_noise, bool is_correct_noise, uint64_t nb_of_absolute_noise_of_same_sign_found, uint64_t nb_of_linear_equation_needed);

#endif
