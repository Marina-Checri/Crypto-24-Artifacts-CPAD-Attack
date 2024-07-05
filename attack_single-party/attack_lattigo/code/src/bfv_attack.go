package main

import (
	"flag"
	"fmt"
	"log"
	"math/big"
	"os"
	"strconv"
	"strings"

	"github.com/tuneinsight/lattigo/v5/core/rlwe"
	"github.com/tuneinsight/lattigo/v5/he/heint"
	"github.com/tuneinsight/lattigo/v5/utils/sampling"

	"github.com/tuneinsight/lattigo/v5/ring"
	"github.com/tuneinsight/lattigo/v5/utils"
)

var DEBUG bool = false

var number_of_evaluations int64
var CHECK_FOUND_NOISE bool = true

// Find the noise of one coefficient of a ciphertext c0 to get an equation b = <a,s> + |e| of this LWE coefficient. Search n linear equations for the LWE coefficient of a ciphertext, where  b' = <a',s> + |e'| such that e and e' have the same sign.
func strategy0(verbose bool) {

	l := log.New(os.Stderr, "", 0)
	var err error

	if verbose {
		l.Println("> Parameters Setting")
	}

	// Creating encryption parameters

	/*
		PN12QP109 := heint.ParametersLiteral{
				LogN:             12,
				Q:                []uint64{0x7ffffec001, 0x8000016001}, // 39 + 39 bits					P:                []uint64{0x40002001},                 // 30 bits
				PlaintextModulus: 65537,
		}
	*/
	/*
		PN12QP101pq := heint.ParametersLiteral{ // LogQP = 101.00005709794536
			LogN:             12,
			Q:                []uint64{0x800004001, 0x800008001}, // 2*35
			P:                []uint64{0x80014001},               // 1*31
			PlaintextModulus: 65537,
		}
	*/
	/*
		HEIntParamsN12QP109 := heint.ParametersLiteral{
				LogN:             12,
				LogQ:             []int{39, 31},
				LogP:             []int{39},
				PlaintextModulus: 0x10001,
		}
	*/
	PersonnalParameters := heint.ParametersLiteral{
		LogN:             12,
		LogQ:             []int{20, 20}, // 54 + 54 + 54 bits
		LogP:             []int{20},     // 54 + 54 + 54 bits
		PlaintextModulus: 65537,
	}
	params, err := heint.NewParametersFromLiteral(PersonnalParameters)

	if err != nil {
		panic(err)
	}
	_, err = sampling.NewKeyedPRNG([]byte{'l', 'a', 't', 't', 'i', 'g', 'o'})
	if err != nil {
		panic(err)
	}

	q := params.Q()[0]
	t := params.PlaintextModulus()

	fmt.Println("BFV Parameters:")
	fmt.Printf("params: %v\n\n", params)
	fmt.Printf("N: %v\n", params.N())
	fmt.Printf("Modulus q = %v\n", params.Q())
	fmt.Printf("log_2(q) = %v\n", params.LogQ())
	fmt.Printf("Modulus p = %v\n", params.P())
	fmt.Printf("log_2(p) = %v\n", params.LogP())
	fmt.Printf("log_2(qp) = %v\n", params.LogQP())
	fmt.Printf("Modulus q0 = %v\n", q)
	fmt.Printf("Plainmodulus = %v\n\n", params.PlaintextModulus())

	// Key Generation
	if verbose {
		l.Println("> Key Generation")
	}

	kgen := heint.NewKeyGenerator(params)
	sk, pk := kgen.GenKeyPairNew()

	encoder := heint.NewEncoder(params)
	encryptor := heint.NewEncryptor(params, pk)
	decryptor := heint.NewDecryptor(params, sk)
	evaluator := heint.NewEvaluator(params, nil)

	level := params.MaxLevel()

	// Attack

	var generated_ciphertexts, ciphertexts_which_noise_has_been_found int
	var number_of_noiseless, number_of_fully_identified_noises int

	pt := heint.NewPlaintext(params, level)
	if err := encoder.Encode([]uint64{0}, pt); err != nil {
		panic(err)
	}

	string_true_noise := ""
	string_found_noise := ""
	correct_noise := false

	//Complete determination of absolute noise for a ciphertext c0 that will be the reference ciphertext.
	c0, err := encryptor.EncryptNew(pt)
	if err != nil {
		panic(err)
	}
	generated_ciphertexts = generated_ciphertexts + 1

	noise := bfv_get_secret_noise(params, c0, decryptor, encoder)
	e0, a0, ca0 := noiseAbsEstim(params, pk, sk, c0, encoder, encryptor, evaluator, decryptor)

	for len(e0) > 1 || e0[0] == 0 {
		c0, err = encryptor.EncryptNew(pt)
		if err != nil {
			panic(err)
		}
		generated_ciphertexts = generated_ciphertexts + 1
		noise = bfv_get_secret_noise(params, c0, decryptor, encoder)
		e0, a0, ca0 = noiseAbsEstim(params, pk, sk, c0, encoder, encryptor, evaluator, decryptor)
	}

	//Bingo!
	string_true_noise = true_noise_to_string(noise, t)
	string_found_noise = found_noise_to_string(e0)
	correct_noise = is_correct_noise(noise, e0, t, false)
	if verbose {
		print_attack_progress("BFV", string_true_noise, string_found_noise, len(e0), true, CHECK_FOUND_NOISE, correct_noise, ciphertexts_which_noise_has_been_found+1, int(params.N()))
	}
	if CHECK_FOUND_NOISE {
		if correct_noise {
			ciphertexts_which_noise_has_been_found = ciphertexts_which_noise_has_been_found + 1
			number_of_fully_identified_noises = number_of_fully_identified_noises + 1
		}
	} else {
		ciphertexts_which_noise_has_been_found = ciphertexts_which_noise_has_been_found + 1
		number_of_fully_identified_noises = number_of_fully_identified_noises + 1
	}

	//Search for n linear equations by completely determining the noise of n ciphertexts of same noise sign.

	for ciphertexts_which_noise_has_been_found < params.N() {
		//First, we try to determine the absolute value of the noise of c1.

		c1, err := encryptor.EncryptNew(pt)
		if err != nil {
			panic(err)
		}
		generated_ciphertexts = generated_ciphertexts + 1
		noise := bfv_get_secret_noise(params, c1, decryptor, encoder)
		e1, a1, ca1 := noiseAbsEstim(params, pk, sk, c1, encoder, encryptor, evaluator, decryptor)

		for len(e1) > 1 {
			c1, err = encryptor.EncryptNew(pt)
			if err != nil {
				panic(err)
			}
			generated_ciphertexts = generated_ciphertexts + 1
			noise = bfv_get_secret_noise(params, c1, decryptor, encoder)
			e1, a1, ca1 = noiseAbsEstim(params, pk, sk, c1, encoder, encryptor, evaluator, decryptor)
		}

		//If we succeed to determine the absolute noise of c1, we look to see if its noise the one of c0 have the same sign.

		if e1[0] == 0 {
			//Bingo!
			string_true_noise = true_noise_to_string(noise, t)
			string_found_noise = found_noise_to_string(e1)
			correct_noise = is_correct_noise(noise, e1, t, false)
			if verbose {
				print_attack_progress("BFV", string_true_noise, string_found_noise, len(e1), true, CHECK_FOUND_NOISE, correct_noise, ciphertexts_which_noise_has_been_found+1, int(params.N()))
			}

			if CHECK_FOUND_NOISE {
				if correct_noise {
					ciphertexts_which_noise_has_been_found = ciphertexts_which_noise_has_been_found + 1
					number_of_noiseless = number_of_noiseless + 1
					number_of_fully_identified_noises = number_of_fully_identified_noises + 1
				}
			} else {
				ciphertexts_which_noise_has_been_found = ciphertexts_which_noise_has_been_found + 1
				number_of_fully_identified_noises = number_of_fully_identified_noises + 1
				number_of_noiseless = number_of_noiseless + 1
			}

		} else {
			if (e0[0]*a0 + e1[0]*a1) > (q / 4) {
				//To see if c1 noise and c0 noise have the same sign, we add the ciphertexts and try to decrypt.

				var cz *rlwe.Ciphertext
				cz, err = evaluator.AddNew(ca0, ca1)
				if err != nil {
					panic(err)
				}
				number_of_evaluations = number_of_evaluations + 1
				res := make([]uint64, params.MaxSlots())
				if err := encoder.Decode(decryptor.DecryptNew(cz), res); err != nil {
					panic(err)
				}

				var N, logN, pow, pos uint64 = uint64(params.N()), uint64(params.LogN()), 1, 0
				const GaloisGen uint64 = ring.GaloisGen
				mask := 2*N - 1
				indexMatrix := make([]uint64, N)
				for i, j := 0, int(N>>1); i < int(N>>1); i, j = i+1, j+1 {
					pos = utils.BitReverse64(pow>>1, int(logN))
					indexMatrix[i] = pos
					indexMatrix[j] = N - pos - 1
					pow *= GaloisGen
					pow &= mask
				}

				polyRes := ring.NewPoly(params.N(), params.MaxLevel())
				for i := 0; int64(i) < int64(N); i++ {
					polyRes.Coeffs[0][indexMatrix[i]] = res[i]
				}
				params.RingT().INTT(polyRes, polyRes)
				if polyRes.Coeffs[0][0] != 0 { //Incorrect decryption
					//If the decryption is incorrect, the noises have the same sign. We have a new linear equation

					//Bingo!
					string_true_noise = true_noise_to_string(noise, t)
					string_found_noise = found_noise_to_string(e1)
					correct_noise = is_correct_noise(noise, e1, t, false)
					if verbose {
						print_attack_progress("BFV", string_true_noise, string_found_noise, len(e1), true, CHECK_FOUND_NOISE, correct_noise, ciphertexts_which_noise_has_been_found+1, int(params.N()))
					}

					if CHECK_FOUND_NOISE {
						if correct_noise {
							ciphertexts_which_noise_has_been_found = ciphertexts_which_noise_has_been_found + 1
							number_of_fully_identified_noises = number_of_fully_identified_noises + 1
						}
					} else {
						ciphertexts_which_noise_has_been_found = ciphertexts_which_noise_has_been_found + 1
						number_of_fully_identified_noises = number_of_fully_identified_noises + 1
					}
				} else {
					//If not, there is a sign mismatch and we continue with a new cipher.

					//Sign mismatch!
					string_true_noise = true_noise_to_string(noise, t)
					string_found_noise = found_noise_to_string(e1)
					correct_noise = is_correct_noise(noise, e1, t, false)
					if verbose {
						print_attack_progress("BFV", string_true_noise, string_found_noise, len(e1), false, CHECK_FOUND_NOISE, correct_noise, ciphertexts_which_noise_has_been_found, int(params.N()))
					}

					if CHECK_FOUND_NOISE {
						if correct_noise {
							number_of_fully_identified_noises = number_of_fully_identified_noises + 1
						}
					} else {
						number_of_fully_identified_noises = number_of_fully_identified_noises + 1
					}
				}
			}
		}
	}
	fmt.Printf("\033[7;33m> %d linear equations have been found! <\033[0m\n", ciphertexts_which_noise_has_been_found)
	fmt.Printf("\033[1;33m[Lattigo][BFV] number of ciphertexts generated: \033[0m%d\n", generated_ciphertexts)
	fmt.Printf("\033[1;33m[Lattigo][BFV] number of noiseless samples: \033[0m%d/%d\n", number_of_noiseless, generated_ciphertexts)
	fmt.Printf("\033[1;33m[Lattigo][BFV] number of ciphertexts which absolute noise fully determined: \033[0m%d/%d\n", number_of_fully_identified_noises, generated_ciphertexts)
	fmt.Printf("\033[1;33m[Lattigo][BFV] number of evaluations: \033[0m%d\n", number_of_evaluations)
	fmt.Printf("\033[1;33m[Lattigo][BFV] number of decryptions: \033[0m%d\n", number_of_evaluations)

}

// Find n noiseless LWE coefficients of different ciphertexts to get n linear equations b = <a,s>.
func strategy1(verbose bool) {

	l := log.New(os.Stderr, "", 0)
	var err error

	if verbose {
		l.Println("> Parameters Setting")
	}

	// Creating encryption parameters
	// LogN = 12 & LogQP = 109
	HEIntParamsN12QP109 := heint.ParametersLiteral{
		LogN:             12,
		LogQ:             []int{39, 31},
		LogP:             []int{39},
		PlaintextModulus: 0x10001,
	}
	params, err := heint.NewParametersFromLiteral(HEIntParamsN12QP109)
	if err != nil {
		panic(err)
	}

	_, err = sampling.NewKeyedPRNG([]byte{'l', 'a', 't', 't', 'i', 'g', 'o'})
	if err != nil {
		panic(err)
	}

	q := params.Q()[0]
	t := params.PlaintextModulus()

	fmt.Println("BFV Parameters:")
	fmt.Printf("params: %v\n\n", params)
	fmt.Printf("N: %v\n", params.N())
	fmt.Printf("Modulus q = %v\n", params.Q())
	fmt.Printf("log_2(q) = %v\n", params.LogQ())
	fmt.Printf("Modulus p = %v\n", params.P())
	fmt.Printf("log_2(p) = %v\n", params.LogP())
	fmt.Printf("log_2(qp) = %v\n", params.LogQP())
	fmt.Printf("Modulus q0 = %v\n", q)
	fmt.Printf("Plainmodulus = %v\n\n", params.PlaintextModulus())

	// Key Generation
	if verbose {
		l.Println("> Key Generation")
	}

	kgen := heint.NewKeyGenerator(params)
	sk, pk := kgen.GenKeyPairNew()

	encoder := heint.NewEncoder(params)
	encryptor := heint.NewEncryptor(params, pk)
	decryptor := heint.NewDecryptor(params, sk)
	evaluator := heint.NewEvaluator(params, nil)

	level := params.MaxLevel()

	// Attack

	var generated_ciphertexts, ciphertexts_which_noise_has_been_found int
	var number_of_noiseless int

	pt := heint.NewPlaintext(params, level)
	if err := encoder.Encode([]uint64{0}, pt); err != nil {
		panic(err)
	}

	string_true_noise := ""
	string_found_noise := ""
	correct_noise := false

	for ciphertexts_which_noise_has_been_found < params.N() {
		//First, we try to determine the absolute value of the noise of c1.

		c1, err := encryptor.EncryptNew(pt)
		if err != nil {
			panic(err)
		}
		generated_ciphertexts = generated_ciphertexts + 1
		noise := bfv_get_secret_noise(params, c1, decryptor, encoder)
		e1, _, _ := noiseAbsEstim(params, pk, sk, c1, encoder, encryptor, evaluator, decryptor)

		for len(e1) > 1 || e1[0] != 0 {
			c1, err = encryptor.EncryptNew(pt)
			if err != nil {
				panic(err)
			}
			generated_ciphertexts = generated_ciphertexts + 1
			noise = bfv_get_secret_noise(params, c1, decryptor, encoder)
			e1, _, _ = noiseAbsEstim(params, pk, sk, c1, encoder, encryptor, evaluator, decryptor)
		}

		//We succeed to determine a noiseless ciphertext.
		//Bingo!
		string_true_noise = true_noise_to_string(noise, t)
		string_found_noise = found_noise_to_string(e1)
		correct_noise = is_correct_noise(noise, e1, t, false)
		if verbose {
			print_attack_progress("BFV", string_true_noise, string_found_noise, len(e1), true, CHECK_FOUND_NOISE, correct_noise, ciphertexts_which_noise_has_been_found+1, int(params.N()))
		}

		if CHECK_FOUND_NOISE {
			if correct_noise {
				ciphertexts_which_noise_has_been_found = ciphertexts_which_noise_has_been_found + 1
				number_of_noiseless = number_of_noiseless + 1
			} else {
				ciphertexts_which_noise_has_been_found = ciphertexts_which_noise_has_been_found + 1
				number_of_noiseless = number_of_noiseless + 1
			}
		}
	}

	fmt.Printf("\033[7;33m> %d linear equations have been found! <\033[0m\n", ciphertexts_which_noise_has_been_found)
	fmt.Printf("\033[1;33m[Lattigo][BFV] number of ciphertexts generated: \033[0m%d\n", generated_ciphertexts)
	fmt.Printf("\033[1;33m[Lattigo][BFV] number of noiseless samples: \033[0m%d/%d\n", number_of_noiseless, generated_ciphertexts)
	fmt.Printf("\033[1;33m[Lattigo][BFV] number of evaluations: \033[0m%d\n", number_of_evaluations)
	fmt.Printf("\033[1;33m[Lattigo][BFV] number of decryptions: \033[0m%d\n", number_of_evaluations)

}

// Strategy explained for large parameters in the Lattigo paragraph (section 4.1) of the paper https://eprint.iacr.org/2024/116
/*
"When we tried to carry out our attack with larger parameters, we
could not determine the exact error, but we did find an interval containing two
possible absolute values for the error.
[...]
 Still, we experimentally noticed that when the ciphertext had a
negative noise, the absolute value of this noise was equal to the left-hand bound,
and that when the ciphertext had a positive noise, this noise was equal to the
right-hand bound. Having noticed that this phenomenon occurred systemati-
cally, we adapted our attack.
[...]
With this slight adaptation, we still determine the n equations needed to find
the secret key."
*/
func strategy2(verbose bool) {

	l := log.New(os.Stderr, "", 0)
	var err error

	if verbose {
		l.Println("> Parameters Setting")
	}

	// Creating encryption parameters
	// LogN = 13 & LogQP = 218
	PN13QP218 := heint.ParametersLiteral{
		LogN:             13,
		Q:                []uint64{0x3fffffffef8001, 0x4000000011c001, 0x40000000120001}, // 54 + 54 + 54 bits
		P:                []uint64{0x7ffffffffb4001},                                     // 55 bits
		PlaintextModulus: 65537,
	}

	params, err := heint.NewParametersFromLiteral(PN13QP218)
	if err != nil {
		panic(err)
	}

	_, err = sampling.NewKeyedPRNG([]byte{'l', 'a', 't', 't', 'i', 'g', 'o'})
	if err != nil {
		panic(err)
	}

	q := params.Q()[0]
	t := params.PlaintextModulus()

	fmt.Println("BFV Parameters:")
	fmt.Printf("params: %v\n\n", params)
	fmt.Printf("N: %v\n", params.N())
	fmt.Printf("Modulus q = %v\n", params.Q())
	fmt.Printf("log_2(q) = %v\n", params.LogQ())
	fmt.Printf("Modulus p = %v\n", params.P())
	fmt.Printf("log_2(p) = %v\n", params.LogP())
	fmt.Printf("log_2(qp) = %v\n", params.LogQP())
	fmt.Printf("Modulus q0 = %v\n", q)
	fmt.Printf("Plainmodulus = %v\n\n", params.PlaintextModulus())

	// Key Generation
	if verbose {
		l.Println("> Key Generation")
	}

	kgen := heint.NewKeyGenerator(params)
	sk, pk := kgen.GenKeyPairNew()

	encoder := heint.NewEncoder(params)
	encryptor := heint.NewEncryptor(params, pk)
	decryptor := heint.NewDecryptor(params, sk)
	evaluator := heint.NewEvaluator(params, nil)

	level := params.MaxLevel()

	// Attack

	var generated_ciphertexts, ciphertexts_which_noise_has_been_found int
	var number_of_noiseless, number_of_fully_identified_noises int
	var number_of_sign_mismatch int

	pt := heint.NewPlaintext(params, level)
	if err := encoder.Encode([]uint64{0}, pt); err != nil {
		panic(err)
	}

	string_true_noise := ""
	string_found_noise := ""
	//correct_noise := false

	var true_noises []uint64
	var found_noises [][]uint64
	var found_noises_same_sign [][]uint64
	var found_noises_sign_mismatch [][]uint64
	var true_noises_same_sign []uint64
	var true_noises_sign_mismatch []uint64

	//Complete determination of absolute noise for a ciphertext c0 that will be the reference ciphertext.
	c0, err := encryptor.EncryptNew(pt)
	if err != nil {
		panic(err)
	}
	generated_ciphertexts = generated_ciphertexts + 1
	noise := bfv_get_secret_noise(params, c0, decryptor, encoder)
	true_noises = append(true_noises, noise)
	e0, a0, ca0 := noiseAbsEstim(params, pk, sk, c0, encoder, encryptor, evaluator, decryptor)
	found_noises = append(found_noises, e0)

	for len(e0) > 2 || e0[0] == 0 {
		c0, err = encryptor.EncryptNew(pt)
		if err != nil {
			panic(err)
		}
		generated_ciphertexts = generated_ciphertexts + 1
		noise = bfv_get_secret_noise(params, c0, decryptor, encoder)
		true_noises = append(true_noises, noise)
		e0, a0, ca0 = noiseAbsEstim(params, pk, sk, c0, encoder, encryptor, evaluator, decryptor)
		found_noises = append(found_noises, e0)
	}

	if len(e0) == 1 {
		//Bingo!
		string_true_noise = true_noise_to_string(noise, t)
		string_found_noise = found_noise_to_string(e0)
		if verbose {
			print_attack_progress("BFV", string_true_noise, string_found_noise, len(e0), true, false, false, max(ciphertexts_which_noise_has_been_found+1, number_of_sign_mismatch+1), int(params.N()))
		}

		ciphertexts_which_noise_has_been_found = ciphertexts_which_noise_has_been_found + 1
		number_of_fully_identified_noises = number_of_fully_identified_noises + 1
	}
	if len(e0) == 2 {
		if verbose {
			fmt.Printf("\033[36m> Trying 2 systems of linear equations - 1st sign <\033[39m\n")
		}

		//Bingo!
		string_true_noise = true_noise_to_string(noise, t)
		string_found_noise = found_noise_to_string(e0)
		if verbose {
			print_attack_progress("BFV", string_true_noise, string_found_noise, len(e0), true, false, false, max(ciphertexts_which_noise_has_been_found+1, number_of_sign_mismatch+1), int(params.N()))
		}

		ciphertexts_which_noise_has_been_found = ciphertexts_which_noise_has_been_found + 1

		true_noises_same_sign = append(true_noises_same_sign, noise)
		found_noises_same_sign = append(found_noises_same_sign, e0)
	}

	//Search for n linear equations by completely determining the noise of n ciphertexts of same noise sign.

	for ciphertexts_which_noise_has_been_found < params.N() && number_of_sign_mismatch < params.N() {
		//First, we try to determine the absolute value of the noise of c1.

		c1, err := encryptor.EncryptNew(pt)
		if err != nil {
			panic(err)
		}
		generated_ciphertexts = generated_ciphertexts + 1
		noise := bfv_get_secret_noise(params, c1, decryptor, encoder)
		true_noises = append(true_noises, noise)
		e1, a1, ca1 := noiseAbsEstim(params, pk, sk, c1, encoder, encryptor, evaluator, decryptor)
		found_noises = append(found_noises, e1)

		for len(e0) > 2 {
			c1, err = encryptor.EncryptNew(pt)
			if err != nil {
				panic(err)
			}
			generated_ciphertexts = generated_ciphertexts + 1
			noise = bfv_get_secret_noise(params, c1, decryptor, encoder)
			true_noises = append(true_noises, noise)
			e1, a1, ca1 = noiseAbsEstim(params, pk, sk, c1, encoder, encryptor, evaluator, decryptor)
			found_noises = append(found_noises, e1)
		}

		//If we succeed to determine the absolute noise of c1, we look to see if its noise the one of c0 have the same sign.

		if e1[0] == 0 {
			//Bingo!
			string_true_noise = true_noise_to_string(noise, t)
			string_found_noise = found_noise_to_string(e1)
			if verbose {
				print_attack_progress("BFV", string_true_noise, string_found_noise, len(e1), true, false, false, max(ciphertexts_which_noise_has_been_found+1, number_of_sign_mismatch+1), int(params.N()))
			}

			ciphertexts_which_noise_has_been_found = ciphertexts_which_noise_has_been_found + 1
			number_of_fully_identified_noises = number_of_fully_identified_noises + 1
			number_of_noiseless = number_of_noiseless + 1
		} else {
			if (e0[0]*a0 + e1[0]*a1) > (q / 4) {
				//To see if c1 noise and c0 noise have the same sign, we add the ciphertexts and try to decrypt.

				var cz *rlwe.Ciphertext
				cz, err = evaluator.AddNew(ca0, ca1)
				if err != nil {
					panic(err)
				}
				number_of_evaluations = number_of_evaluations + 1
				res := make([]uint64, params.MaxSlots())
				if err := encoder.Decode(decryptor.DecryptNew(cz), res); err != nil {
					panic(err)
				}

				var N, logN, pow, pos uint64 = uint64(params.N()), uint64(params.LogN()), 1, 0
				const GaloisGen uint64 = ring.GaloisGen
				mask := 2*N - 1
				indexMatrix := make([]uint64, N)
				for i, j := 0, int(N>>1); i < int(N>>1); i, j = i+1, j+1 {
					pos = utils.BitReverse64(pow>>1, int(logN))
					indexMatrix[i] = pos
					indexMatrix[j] = N - pos - 1
					pow *= GaloisGen
					pow &= mask
				}

				polyRes := ring.NewPoly(params.N(), params.MaxLevel())
				for i := 0; int64(i) < int64(N); i++ {
					polyRes.Coeffs[0][indexMatrix[i]] = res[i]
				}
				params.RingT().INTT(polyRes, polyRes)
				if polyRes.Coeffs[0][0] != 0 { //Incorrect decryption
					//If the decryption is incorrect, the noises have the same sign. We have a new linear equation
					if len(e1) == 1 {
						//Bingo!
						string_true_noise = true_noise_to_string(noise, t)
						string_found_noise = found_noise_to_string(e1)
						if verbose {
							print_attack_progress("BFV", string_true_noise, string_found_noise, len(e1), true, false, false, max(ciphertexts_which_noise_has_been_found+1, number_of_sign_mismatch+1), int(params.N()))
						}

						ciphertexts_which_noise_has_been_found = ciphertexts_which_noise_has_been_found + 1
						number_of_fully_identified_noises = number_of_fully_identified_noises + 1
					}
					if len(e1) == 2 {
						if verbose {
							fmt.Printf("\033[36m> Trying 2 systems of linear equations  - 1st sign <\033[39m\n")
						}

						//Bingo!
						string_true_noise = true_noise_to_string(noise, t)
						string_found_noise = found_noise_to_string(e1)
						if verbose {
							print_attack_progress("BFV", string_true_noise, string_found_noise, len(e1), true, false, false, max(ciphertexts_which_noise_has_been_found+1, number_of_sign_mismatch+1), int(params.N()))
						}

						ciphertexts_which_noise_has_been_found = ciphertexts_which_noise_has_been_found + 1
						true_noises_same_sign = append(true_noises_same_sign, noise)
						found_noises_same_sign = append(found_noises_same_sign, e1)
					}
				} else {
					//If not, there is a sign mismatch and we continue with a new cipher.
					if len(e1) == 1 {
						//Sign mismatch!
						string_true_noise = true_noise_to_string(noise, t)
						string_found_noise = found_noise_to_string(e1)
						if verbose {
							print_attack_progress("BFV", string_true_noise, string_found_noise, len(e1), false, false, false, max(ciphertexts_which_noise_has_been_found, number_of_sign_mismatch), int(params.N()))
						}

						number_of_fully_identified_noises = number_of_fully_identified_noises + 1
						number_of_sign_mismatch = number_of_sign_mismatch + 1
					}

					if len(e1) == 2 {
						if verbose {
							fmt.Printf("\033[35m> Trying 2 systems of linear equations? - 2nd sign <\033[39m\n")
						}

						//Sign mismatch!
						string_true_noise = true_noise_to_string(noise, t)
						string_found_noise = found_noise_to_string(e1)
						if verbose {
							print_attack_progress("BFV", string_true_noise, string_found_noise, len(e1), false, false, false, max(ciphertexts_which_noise_has_been_found, number_of_sign_mismatch), int(params.N()))
						}

						number_of_sign_mismatch = number_of_sign_mismatch + 1

						true_noises_sign_mismatch = append(true_noises_sign_mismatch, noise)
						found_noises_sign_mismatch = append(found_noises_sign_mismatch, e1)
					}
				}
			}
		}
	}

	if ciphertexts_which_noise_has_been_found >= params.N() {
		if DEBUG {
			fmt.Printf("ciphertexts_which_noise_has_been_found = %d\n", ciphertexts_which_noise_has_been_found)
		}
		bool_correct_noise_left, count_correct_noise, count_incorrect_noise := check_left_noises(true_noises_same_sign, found_noises_same_sign, q)
		if DEBUG {
			fmt.Printf("\n")
			fmt.Printf("LEFT count_correct_noise = %d;\nLEFT count_incorrect_noise = %d\n", count_correct_noise, count_incorrect_noise)
		}
		if !bool_correct_noise_left {
			if DEBUG {
				fmt.Printf("Incorrect noise left -> positive noise?\n")
			}
			bool_correct_noise_right, count_correct_noise, count_incorrect_noise := check_right_noises(true_noises_same_sign, found_noises_same_sign, q)
			if bool_correct_noise_right {
				if DEBUG {
					fmt.Printf("Correct noise right -> positive noise.\n")
					fmt.Printf("RIGHT count_correct_noise = %d;\nRIGHT count_incorrect_noise = %d\n", count_correct_noise, count_incorrect_noise)
				}
			} else {
				if DEBUG {
					fmt.Printf("Incorrect noise right & Incorrect noise left...\n")
					fmt.Printf("RIGHT count_correct_noise = %d;\nRIGHT count_incorrect_noise = %d\n", count_correct_noise, count_incorrect_noise)
				}
			}
		} else {
			if DEBUG {
				fmt.Printf("Correct noise left -> negative noise.\n")
			}
		}
	}

	if number_of_sign_mismatch >= params.N() {
		if DEBUG {
			fmt.Printf("number_of_sign_mismatch = %d\n", number_of_sign_mismatch)
		}
		bool_correct_noise_left, count_correct_noise, count_incorrect_noise := check_left_noises(true_noises_sign_mismatch, found_noises_sign_mismatch, q)
		if DEBUG {
			fmt.Printf("\n")
			fmt.Printf("LEFT count_correct_noise = %d;\nLEFT count_incorrect_noise = %d\n", count_correct_noise, count_incorrect_noise)
		}
		if !bool_correct_noise_left {
			if DEBUG {
				fmt.Printf("Incorrect noise left -> positive noise?\n")
			}
			bool_correct_noise_right, count_correct_noise, count_incorrect_noise := check_right_noises(true_noises_sign_mismatch, found_noises_sign_mismatch, q)
			if bool_correct_noise_right {
				if DEBUG {
					fmt.Printf("Correct noise right -> positive noise.\n")
					fmt.Printf("RIGHT count_correct_noise = %d;\nRIGHT count_incorrect_noise = %d\n", count_correct_noise, count_incorrect_noise)
				}
			} else {
				if DEBUG {
					fmt.Printf("Incorrect noise right & Incorrect noise left...\n")
					fmt.Printf("RIGHT count_correct_noise = %d;\nRIGHT count_incorrect_noise = %d\n", count_correct_noise, count_incorrect_noise)
				}
			}
		} else {
			if DEBUG {
				fmt.Printf("Correct noise left -> negative noise.\n")
			}
		}
	}

	fmt.Printf("\033[7;33m> %d linear equations have been found! <\033[0m\n", ciphertexts_which_noise_has_been_found)
	fmt.Printf("\033[1;33m[Lattigo][BFV] number of ciphertexts generated: \033[0m%d\n", generated_ciphertexts)
	fmt.Printf("\033[1;33m[Lattigo][BFV] number of noiseless samples: \033[0m%d/%d\n", number_of_noiseless, generated_ciphertexts)
	fmt.Printf("\033[1;33m[Lattigo][BFV] number of ciphertexts which absolute noise fully determined: \033[0m%d/%d\n", number_of_fully_identified_noises, generated_ciphertexts)
	fmt.Printf("\033[1;33m[Lattigo][BFV] number of evaluations: \033[0m%d\n", number_of_evaluations)
	fmt.Printf("\033[1;33m[Lattigo][BFV] number of decryptions: \033[0m%d\n", number_of_evaluations)

}

/*
  Check if the found noise is the true noise of the original ciphertext
*/
func is_correct_noise(true_noise uint64, found_noise []uint64, modulus uint64, print bool) (correct_noise bool) {
	true_noise = true_noise % modulus
	if true_noise > (modulus >> 1) {
		true_noise = modulus - true_noise
	}
	if len(found_noise) != 1 {
		correct_noise = false
		return
	}
	if true_noise == found_noise[0] {
		if print {
			fmt.Printf("\033[32mNoise found correct! \n\033[39m")
		}
		correct_noise = true
		return
	}
	if print {
		fmt.Printf("\033[31mNoise found incorrect!\n")
		fmt.Printf("true noise: %d and found noise: %d\n", true_noise, found_noise[0])
	}
	correct_noise = false
	return
}

// For the strategy explained to deal with large parameters in the Lattigo paragraph (section 4.1) of the paper https://eprint.iacr.org/2024/116
/*
  Check if the left bounds of the interval found noises correspond to the true noises of the originals ciphertexts
*/
func check_left_noises(true_noises_same_sign []uint64, found_noises_same_sign [][]uint64, modulus uint64) (correct_noise bool, count_correct_noise int, count_incorrect_noise int) {
	//All noises are negatives noises
	correct_noise = true
	count_correct_noise = 0
	count_incorrect_noise = 0

	for i := 0; i < len(true_noises_same_sign); i = i + 1 {
		true_noises_same_sign[i] = true_noises_same_sign[i] % modulus
		if modulus-true_noises_same_sign[i] != found_noises_same_sign[i][0] {
			correct_noise = false
			count_incorrect_noise = count_incorrect_noise + 1
		} else {
			count_correct_noise = count_correct_noise + 1
		}
	}
	return
}

/*
  Check if the right bounds of the interval found noises correspond to the true noises of the originals ciphertexts
*/
func check_right_noises(true_noises_same_sign []uint64, found_noises_same_sign [][]uint64, modulus uint64) (correct_noise bool, count_correct_noise int, count_incorrect_noise int) {
	correct_noise = true
	count_correct_noise = 0
	count_incorrect_noise = 0
	for i := 0; i < len(true_noises_same_sign); i = i + 1 {
		true_noises_same_sign[i] = true_noises_same_sign[i] % modulus
		if true_noises_same_sign[i] != found_noises_same_sign[i][1] {
			correct_noise = false
			count_incorrect_noise = count_incorrect_noise + 1
		} else {
			count_correct_noise = count_correct_noise + 1
		}
	}
	return
}

// Get the secret/true noise of a BFV ciphertext
func bfv_get_secret_noise(params heint.Parameters, ciphertext *rlwe.Ciphertext, decryptor *rlwe.Decryptor, encoder *heint.Encoder) (noise uint64) {
	plaintext := heint.NewPlaintext(params, params.MaxLevel())
	decryptor.Decrypt(ciphertext, plaintext)

	ringT := params.RingT()
	bufT := ringT.NewPoly()
	bufQ := params.RingQ().NewPoly()
	params.RingQ().AtLevel(plaintext.Level()).INTT(plaintext.Value, bufQ)
	encoder.RingQ2T(plaintext.Level(), false, bufQ, bufT)

	noise = bufT.Coeffs[0][0]
	return
}

// Return the max of two int
func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// Print the (true) noise given in parameters
func print_noise(noise uint64, modulus uint64) {
	noise = noise % modulus
	if noise > (modulus >> 1) {
		fmt.Printf("**********************************************\nNoise of this ciphertext: -%d\n", modulus-noise)
	} else {
		fmt.Printf("**********************************************\nNoise of this ciphertext: %d\n", noise)
	}
	return
}

// Return a string of the (true) noise given in argument
func true_noise_to_string(noise uint64, modulus uint64) string {
	noise = noise % modulus
	if noise > (modulus >> 1) {
		noise = modulus - noise
		return "-" + strconv.FormatUint(noise, 10)
	}
	return "+" + strconv.FormatUint(noise, 10)
}

// Function to print the found absolute noise given in argument
func print_found_absolute_noise(name string, e0 []uint64) {
	fmt.Printf("%s = %v\n", name, e0)
}

// Convert a uint64 slice to a string
func uint64SliceToString(slice []uint64) string {
	strSlice := make([]string, len(slice))
	for i, num := range slice {
		strSlice[i] = strconv.FormatUint(num, 10)
	}
	return strings.Join(strSlice, " ")
}

// Return a string of the found absolute noise slice given in argument
func found_noise_to_string(e0 []uint64) string {
	return "[ " + uint64SliceToString(e0) + " ]"
}

// Print the progress of the attack: when an absolute noise is found, print the true noise of the ciphertext, the found absolute noise and if the attack found exactly one absolute noise, if the noise have the sign of the first noise found or if it is a sign mismatch.
func print_attack_progress(scheme, trueNoise, foundNoise string, foundNoiseSize int, sameSign, checkFoundNoise, isCorrectNoise bool, nbOfAbsoluteNoiseOfSameSignFound int, nbOfLinearEquationNeeded int) {
	lib := "Lattigo"

	fmt.Printf("[%s][%s] Ciphertext true noise:   %s\n", lib, scheme, trueNoise)
	fmt.Printf("[%s][%s] Found noise:            %s\n", lib, scheme, foundNoise)

	if foundNoiseSize == 1 {
		fmt.Printf("[%s][%s] Same sign or sign mismatch: ", lib, scheme)
		if sameSign {
			fmt.Print("\033[36mSame sign\033[39m")
		} else {
			fmt.Print("\033[35mSign mismatch\033[39m")
		}
		fmt.Println(".")

		if checkFoundNoise {
			fmt.Printf("[%s][%s] Is absolute noise found correct? ", lib, scheme)
			if isCorrectNoise {
				fmt.Print("\033[32mYes!\033[39m")
			} else {
				fmt.Print("\033[31mNo.\033[39m")
			}
			fmt.Println()
		}
	}
	fmt.Printf("Nb of absolute noise of same sign found:  %d/%d\n", nbOfAbsoluteNoiseOfSameSignFound, nbOfLinearEquationNeeded)

	fmt.Println()
}

// Estimate the absolute noise of a ciphertext using CPAD requests.
func noiseAbsEstim(params heint.Parameters, pk *rlwe.PublicKey, sk *rlwe.SecretKey, c0 *rlwe.Ciphertext, encoder *heint.Encoder, encryptor *rlwe.Encryptor, evaluator *heint.Evaluator, decryptor *rlwe.Decryptor) (noise_estim []uint64, a uint64, ca *rlwe.Ciphertext) {
	q := params.Q()
	p := params.P()
	modulus_q := big.NewInt(1)
	for i := 0; i < len(q); i = i + 1 {
		modulus_q = new(big.Int).Mul(modulus_q, big.NewInt(int64(q[i])))
	}
	modulus_p := big.NewInt(1)
	for i := 0; i < len(p); i = i + 1 {
		modulus_p = new(big.Int).Mul(modulus_p, big.NewInt(int64(p[i])))
	}
	//modulus_qp := new(big.Int).Mul(modulus_q, modulus_p)
	//modulus_q0 := params.Q()[0]

	var cladder []*rlwe.Ciphertext
	cladder = append(cladder, c0)

	k := 1
	var aBigInt, bBigInt, zBigInt, lBigInt, uBigInt, divisorL, divisorU *big.Int
	aBigInt = big.NewInt(0)
	bBigInt = big.NewInt(0)

	//var cb *rlwe.Ciphertext
	//var c *rlwe.Ciphertext

	var N, logN, pow, pos uint64 = uint64(params.N()), uint64(params.LogN()), 1, 0
	const GaloisGen uint64 = ring.GaloisGen
	mask := 2*N - 1
	indexMatrix := make([]uint64, N)
	for i, j := 0, int(N>>1); i < int(N>>1); i, j = i+1, j+1 {
		pos = utils.BitReverse64(pow>>1, int(logN))
		indexMatrix[i] = pos
		indexMatrix[j] = N - pos - 1
		pow *= GaloisGen
		pow &= mask
	}

	for true {
		c_k_minus_1 := cladder[k-1]
		c, err := evaluator.AddNew(c_k_minus_1, c_k_minus_1)
		if err != nil {
			panic(err)
		}
		number_of_evaluations = number_of_evaluations + 1
		cladder = append(cladder, c)

		res := make([]uint64, params.MaxSlots())
		if err := encoder.Decode(decryptor.DecryptNew(c), res); err != nil {
			panic(err)
		}

		polyRes := ring.NewPoly(params.N(), params.MaxLevel())
		for i := 0; int64(i) < int64(N); i++ {
			polyRes.Coeffs[0][indexMatrix[i]] = res[i]
		}
		params.RingT().INTT(polyRes, polyRes)
		if polyRes.Coeffs[0][0] != 0 { //Incorrect decryption
			aBigInt = new(big.Int).Lsh(big.NewInt(1), uint(k-1))
			ca = cladder[k-1]
			bBigInt = new(big.Int).Lsh(big.NewInt(1), uint(k))
			//cb = cladder[k]
			k = k - 1
			break
		}

		Two_pow_k := big.NewInt(0)
		Two_pow_k = new(big.Int).Lsh(big.NewInt(1), uint(k))
		if Two_pow_k.Cmp(modulus_q) == 1 { //2^k > q
			//fmt.Printf("\nk=%d, 2^k=%d, qp=%d\n", k, Two_pow_k, modulus_qp)
			noise_estim = append(noise_estim, 0)
			return
		}

		k = k + 1
	}

	//var cz *rlwe.Ciphertext
	for k > 0 {
		// z = a + (1<<(k-1));
		zBigInt = new(big.Int).Add(aBigInt, new(big.Int).Lsh(big.NewInt(1), uint(k-1)))
		c_k_minus_1 := cladder[k-1]

		cz, err := evaluator.AddNew(ca, c_k_minus_1)
		if err != nil {
			panic(err)
		}
		number_of_evaluations = number_of_evaluations + 1
		res := make([]uint64, params.MaxSlots())
		if err := encoder.Decode(decryptor.DecryptNew(cz), res); err != nil {
			panic(err)
		}

		polyRes := ring.NewPoly(params.N(), params.MaxLevel())
		for i := 0; int64(i) < int64(N); i++ {
			polyRes.Coeffs[0][indexMatrix[i]] = res[i]
		}
		params.RingT().INTT(polyRes, polyRes)
		if polyRes.Coeffs[0][0] != 0 { //Incorrect decryption
			bBigInt = zBigInt
			//cb = cz
		} else {
			aBigInt = zBigInt
			ca = cz
		}
		k = k - 1
	}

	two := big.NewInt(2)
	t := new(big.Int).SetUint64(params.PlaintextModulus())
	divisorL = new(big.Int).Mul(two, bBigInt)
	divisorL = new(big.Int).Mul(divisorL, t)
	lBigInt = new(big.Int).Div(modulus_q, divisorL)
	if new(big.Int).Mul(divisorL, lBigInt).Cmp(modulus_q) != 0 {
		lBigInt.Add(lBigInt, big.NewInt(1))
	}

	//l = ceil(q/(2tb))
	//u = floor(q/(2ta))

	divisorU = new(big.Int).Mul(two, aBigInt)
	divisorU = new(big.Int).Mul(divisorU, t)
	uBigInt = new(big.Int).Div(modulus_q, divisorU)

	l := lBigInt.Uint64()
	u := uBigInt.Uint64()

	a = aBigInt.Uint64()
	//b := bBigInt.Uint64()

	//fmt.Printf("l=%d; u=%d;\n\n", lBigInt, uBigInt)

	if l == u {
		noise_estim = append(noise_estim, l)
	} else {
		noise_estim = append(noise_estim, l)
		noise_estim = append(noise_estim, u)
	}
	return
}

func main() {
	// Define the --no-verbose flag
	noVerbose := flag.Bool("no-verbose", false, "Set to disable verbose mode")
	flag.Parse()

	// By default, verbose is true, unless --no-verbose is specified
	verbose := !*noVerbose

	strategy0(verbose)
	//strategy1(verbose)
	//strategy2(verbose)
}
