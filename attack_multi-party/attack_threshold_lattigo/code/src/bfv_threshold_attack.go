package main

import (
	"fmt"
	"log"
	"math/big"
	"os"
	"strconv"
	"strings"

	"github.com/tuneinsight/lattigo/v5/core/rlwe"
	"github.com/tuneinsight/lattigo/v5/he/heint"
	"github.com/tuneinsight/lattigo/v5/mhe"
	"github.com/tuneinsight/lattigo/v5/utils/sampling"

	"github.com/tuneinsight/lattigo/v5/ring"
	"github.com/tuneinsight/lattigo/v5/utils"
)

type party struct {
	sk         *rlwe.SecretKey
	rlkEphemSk *rlwe.SecretKey

	ckgShare         mhe.PublicKeyGenShare
	rkgShareOne      mhe.RelinearizationKeyGenShare
	rkgShareTwo      mhe.RelinearizationKeyGenShare
	gkgShare         mhe.GaloisKeyGenShare
	cksShare         mhe.KeySwitchShare
	cksShare_wonoise mhe.KeySwitchShare
}

var number_of_evaluations int64
var CHECK_FOUND_NOISE bool = true
var SIGMA_SMUDGING float64 = 0

//SIGMA_SMUDGING 1<<32 //= 4.294967296e+09 = 2^32
//SIGMA_SMUDGING 1<<30 //= 1.073741824e+09 = 2^30

// Find the noise of one coefficient of a ciphertext c0 to get an equation b = <a,s> + |e| of this LWE coefficient. Search n linear equations for the LWE coefficient of a ciphertext, where  b' = <a',s> + |e'| such that e and e' have the same sign.
func strategy0() {

	nb_parties := 5
	//nb_parties := 100

	l := log.New(os.Stderr, "", 0)
	var err error

	l.Println("> Parameters Setting")

	PN12QP101pq := heint.ParametersLiteral{ // LogQP = 101.00005709794536
		LogN:             12,
		Q:                []uint64{0x800004001, 0x800008001}, // 2*35
		P:                []uint64{0x80014001},               // 1*31
		PlaintextModulus: 65537,
	}
	params, err := heint.NewParametersFromLiteral(PN12QP101pq)
	if err != nil {
		panic(err)
	}

	// Common reference polynomial generator that uses the PRNG
	crs, err := sampling.NewKeyedPRNG([]byte{'l', 'a', 't', 't', 'i', 'g', 'o'})
	if err != nil {
		panic(err)
	}

	// Create each party, and allocate the memory for all the shares that the protocols will need
	P := genparties(params, nb_parties)

	// 1) Collective public key generation
	common_pk := ckgphase(params, crs, P)

	// 2) Collective RelinearizationKey generation
	RelinearizationKey := rkgphase(params, crs, P)

	// 3) Collective GaloisKeys generation
	galKeys := gkgphase(params, crs, P)

	q := params.Q()[0]
	t := params.PlaintextModulus()

	fmt.Println("BFV Parameters:")
	fmt.Printf("params: %v\n\n", params)
	fmt.Printf("N: %v\n", params.N())
	fmt.Printf("log_2(q) = %v\n", params.LogQ())
	fmt.Printf("log_2(p) = %v\n", params.LogP())
	fmt.Printf("log_2(qp) = %v\n", params.LogQP())
	fmt.Printf("Plainmodulus = %v\n\n", params.PlaintextModulus())
	fmt.Printf("\nSIGMA_SMUDGING = %v\n\n", SIGMA_SMUDGING)

	fmt.Printf("\nNumber of parties = %d\n\n", nb_parties)
	// Key Generation
	l.Println("> Key Generation")

	//kgen := heint.NewKeyGenerator(params)
	//tsk, tpk := kgen.GenKeyPair()
	tsk, tpk := P[0].sk, common_pk

	encoder := heint.NewEncoder(params)
	encryptor := heint.NewEncryptor(params, common_pk)
	decryptor := heint.NewDecryptor(params, tsk)

	// Instantiates EvaluationKeySet
	evk := rlwe.NewMemEvaluationKeySet(RelinearizationKey, galKeys...)
	evaluator := heint.NewEvaluator(params, evk)

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

	noise := bfv_get_secret_noise_threshold(params, c0, decryptor, encoder, tpk, P)
	e0, a0, ca0 := noiseAbsEstim(params, common_pk, c0, encoder, encryptor, evaluator, decryptor, tpk, P)

	for len(e0) > 1 || e0[0] == 0 {
		c0, err = encryptor.EncryptNew(pt)
		if err != nil {
			panic(err)
		}
		generated_ciphertexts = generated_ciphertexts + 1
		noise = bfv_get_secret_noise_threshold(params, c0, decryptor, encoder, tpk, P)
		e0, a0, ca0 = noiseAbsEstim(params, common_pk, c0, encoder, encryptor, evaluator, decryptor, tpk, P)
	}

	//Bingo!
	string_true_noise = true_noise_to_string(noise, t)
	string_found_noise = found_noise_to_string(e0)
	correct_noise = is_correct_noise(noise, e0, t, false)
	print_attack_progress("BFV ThHE", string_true_noise, string_found_noise, len(e0), true, CHECK_FOUND_NOISE, correct_noise, ciphertexts_which_noise_has_been_found, int(params.N()))

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
	count := 0

	for ciphertexts_which_noise_has_been_found < params.N() {
		count = count + 1
		//First, we try to determine the absolute value of the noise of c1.

		c1, err := encryptor.EncryptNew(pt)
		if err != nil {
			panic(err)
		}
		generated_ciphertexts = generated_ciphertexts + 1
		noise := bfv_get_secret_noise_threshold(params, c1, decryptor, encoder, tpk, P)
		e1, a1, ca1 := noiseAbsEstim(params, common_pk, c1, encoder, encryptor, evaluator, decryptor, tpk, P)

		for len(e1) > 1 {
			c1, err = encryptor.EncryptNew(pt)
			if err != nil {
				panic(err)
			}
			generated_ciphertexts = generated_ciphertexts + 1
			noise = bfv_get_secret_noise_threshold(params, c1, decryptor, encoder, tpk, P)
			e1, a1, ca1 = noiseAbsEstim(params, common_pk, c1, encoder, encryptor, evaluator, decryptor, tpk, P)
		}

		//If we succeed to determine the absolute noise of c1, we look to see if its noise the one of c0 have the same sign.

		if e1[0] == 0 {
			//Bingo!
			string_true_noise = true_noise_to_string(noise, t)
			string_found_noise = found_noise_to_string(e1)
			correct_noise = is_correct_noise(noise, e1, t, false)
			print_attack_progress("BFV ThHE", string_true_noise, string_found_noise, len(e1), true, CHECK_FOUND_NOISE, correct_noise, ciphertexts_which_noise_has_been_found, int(params.N()))

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
				// Collective Public Key Switch
				//cz_PCKS := pcksPhase(params, tpk, cz, P)
				cz_CKS := cksphase(params, P, cz)
				//res := encoder.DecodeUintNew(decryptor.DecryptNew(cz_CKS))
				ptres := heint.NewPlaintext(params, params.MaxLevel())
				decryptor.Decrypt(cz_CKS, ptres)
				res := make([]uint64, params.MaxSlots())
				if err := encoder.Decode(ptres, res); err != nil {
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
					print_attack_progress("BFV ThHE", string_true_noise, string_found_noise, len(e1), true, CHECK_FOUND_NOISE, correct_noise, ciphertexts_which_noise_has_been_found, int(params.N()))

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
					print_attack_progress("BFV ThHE", string_true_noise, string_found_noise, len(e1), false, CHECK_FOUND_NOISE, correct_noise, ciphertexts_which_noise_has_been_found, int(params.N()))

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
	fmt.Printf("\033[1;33m[Lattigo][BFV ThHE] number of ciphertexts generated: \033[0m%d\n", generated_ciphertexts)
	fmt.Printf("\033[1;33m[Lattigo][BFV ThHE] number of noiseless samples: \033[0m%d/%d\n", number_of_noiseless, generated_ciphertexts)
	fmt.Printf("\033[1;33m[Lattigo][BFV ThHE] number of ciphertexts which absolute noise fully determined: \033[0m%d/%d\n", number_of_fully_identified_noises, generated_ciphertexts)
	fmt.Printf("\033[1;33m[Lattigo][BFV ThHE] number of evaluations: \033[0m%d\n", number_of_evaluations)
	fmt.Printf("\033[1;33m[Lattigo][BFV ThHE] number of decryptions: \033[0m%d\n", number_of_evaluations)

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

// Get the secret/true noise of a BFV ciphertext
func bfv_get_secret_noise_threshold(params heint.Parameters, ciphertext *rlwe.Ciphertext, decryptor *rlwe.Decryptor, encoder *heint.Encoder, tpk *rlwe.PublicKey, P []*party) (noise uint64) {
	// Collective Public Key Switch
	//encOutPCKS := pcksPhase(params, tpk, ciphertext, P)
	encOutCKS := cksphase(params, P, ciphertext, true)

	// Decrypt the result with the target secret key
	plaintext := heint.NewPlaintext(params, params.MaxLevel())
	decryptor.Decrypt(encOutCKS, plaintext)

	ringT := params.RingT()
	bufT := ringT.NewPoly()
	bufQ := params.RingQ().NewPoly()
	params.RingQ().AtLevel(plaintext.Level()).INTT(plaintext.Value, bufQ)
	encoder.RingQ2T(plaintext.Level(), false, bufQ, bufT)

	//ringT.MulScalar(bufT, ring.ModExp(plaintext.Scale.Uint64(), ringT.SubRings[0].Modulus-2, ringT.SubRings[0].Modulus), bufT)
	//ringT.NTT(bufT, bufT)

	//res := make([]uint64, params.MaxSlots())
	//if err := encoder.Decode(plaintext, res); err != nil {
	//	panic(err)
	//}
	//fmt.Printf("res = %v\n", res[0:8])

	//noise = plaintext.Value.Coeffs[0][0]
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
	if noise > modulus/2 {
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
func noiseAbsEstim(params heint.Parameters, pk *rlwe.PublicKey, c0 *rlwe.Ciphertext, encoder *heint.Encoder, encryptor *rlwe.Encryptor, evaluator *heint.Evaluator, decryptor *rlwe.Decryptor, tpk *rlwe.PublicKey, P []*party) (noise_estim []uint64, a uint64, ca *rlwe.Ciphertext) {
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

		//c_PCKS := pcksPhase(params, tpk, c, P)
		c_CKS := cksphase(params, P, c)
		ptres := heint.NewPlaintext(params, params.MaxLevel())
		decryptor.Decrypt(c_CKS, ptres)
		res := make([]uint64, params.MaxSlots())
		if err := encoder.Decode(ptres, res); err != nil {
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
		if Two_pow_k.Cmp(modulus_q) == 1 { //2^k > qp
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
		//cz_PCKS := pcksPhase(params, tpk, cz, P)
		cz_CKS := cksphase(params, P, cz)
		ptres := heint.NewPlaintext(params, params.MaxLevel())
		decryptor.Decrypt(cz_CKS, ptres)
		res := make([]uint64, params.MaxSlots())
		if err := encoder.Decode(ptres, res); err != nil {
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

	//l = ceil(q/(2t b))
	//u = floor(q/(2t a))

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
	strategy0()
}

func genparties(params heint.Parameters, N int) []*party {
	P := make([]*party, N)
	kgen := rlwe.NewKeyGenerator(params)
	for i := range P {
		pi := &party{}
		pi.sk = kgen.GenSecretKeyNew()
		P[i] = pi
	}
	return P
}

// Collective Key Generation phase to create a Collective Public Key
func ckgphase(params heint.Parameters, crs sampling.PRNG, P []*party) *rlwe.PublicKey {
	ckg := mhe.NewPublicKeyGenProtocol(params) // Public key generation
	ckgCombined := ckg.AllocateShare()
	for _, pi := range P {
		pi.ckgShare = ckg.AllocateShare()
	}
	crp := ckg.SampleCRP(crs)
	for _, pi := range P {
		/* #nosec G601 -- Implicit memory aliasing in for loop acknowledged */
		ckg.GenShare(pi.sk, crp, &pi.ckgShare)
	}
	pk := rlwe.NewPublicKey(params)
	for _, pi := range P {
		ckg.AggregateShares(pi.ckgShare, ckgCombined, &ckgCombined)
	}
	ckg.GenPublicKey(ckgCombined, crp, pk)
	return pk
}

// Collective Key Switch phase to collectively switch/decrypt a ciphertext
func cksphase(params heint.Parameters, P []*party, result *rlwe.Ciphertext, options ...bool) *rlwe.Ciphertext {
	var cks mhe.KeySwitchProtocol
	without_eFresh := false
	if len(options) > 0 && options[0] {
		without_eFresh = true
	}
	//cks, err := mhe.NewKeySwitchProtocol(params, ring.DiscreteGaussian{Sigma: 0, Bound: 6 * (0)}, without_eFresh) // Collective public-key re-encryption
	cks, err := mhe.NewKeySwitchProtocol(params, ring.DiscreteGaussian{Sigma: SIGMA_SMUDGING, Bound: 6 * (SIGMA_SMUDGING)}, without_eFresh) // Collective public-key re-encryption
	if err != nil {
		panic(err)
	}
	for _, pi := range P {
		pi.cksShare = cks.AllocateShare(params.MaxLevel())
	}
	zero := rlwe.NewSecretKey(params)
	cksCombined := cks.AllocateShare(params.MaxLevel())
	for _, pi := range P[1:] {
		/* #nosec G601 -- Implicit memory aliasing in for loop acknowledged */
		cks.GenShare(pi.sk, zero, result, &pi.cksShare)
	}
	encOut := heint.NewCiphertext(params, 1, params.MaxLevel())
	for _, pi := range P {
		if err := cks.AggregateShares(pi.cksShare, cksCombined, &cksCombined); err != nil {
			panic(err)
		}
	}
	cks.KeySwitch(result, cksCombined, encOut)
	return encOut
}

// Relinearization Key Generation phase to create a Relinearization Public Key
func rkgphase(params heint.Parameters, crs sampling.PRNG, P []*party) *rlwe.RelinearizationKey {
	rkg := mhe.NewRelinearizationKeyGenProtocol(params) // Relinearization key generation
	_, rkgCombined1, rkgCombined2 := rkg.AllocateShare()
	for _, pi := range P {
		pi.rlkEphemSk, pi.rkgShareOne, pi.rkgShareTwo = rkg.AllocateShare()
	}
	crp := rkg.SampleCRP(crs)
	for _, pi := range P {
		/* #nosec G601 -- Implicit memory aliasing in for loop acknowledged */
		rkg.GenShareRoundOne(pi.sk, crp, pi.rlkEphemSk, &pi.rkgShareOne)
	}
	for _, pi := range P {
		/* #nosec G601 -- Implicit memory aliasing in for loop acknowledged */
		rkg.AggregateShares(pi.rkgShareOne, rkgCombined1, &rkgCombined1)
	}
	for _, pi := range P {
		/* #nosec G601 -- Implicit memory aliasing in for loop acknowledged */
		rkg.GenShareRoundTwo(pi.rlkEphemSk, pi.sk, rkgCombined1, &pi.rkgShareTwo)
	}
	rlk := rlwe.NewRelinearizationKey(params)
	for _, pi := range P {
		/* #nosec G601 -- Implicit memory aliasing in for loop acknowledged */
		rkg.AggregateShares(pi.rkgShareTwo, rkgCombined2, &rkgCombined2)
	}
	rkg.GenRelinearizationKey(rkgCombined1, rkgCombined2, rlk)
	return rlk
}

// Galois Key Generation phase to create a Galois Public Key
func gkgphase(params heint.Parameters, crs sampling.PRNG, P []*party) (galKeys []*rlwe.GaloisKey) {
	gkg := mhe.NewGaloisKeyGenProtocol(params) // Rotation keys generation
	for _, pi := range P {
		pi.gkgShare = gkg.AllocateShare()
	}
	galEls := append(params.GaloisElementsForInnerSum(1, params.N()>>1), params.GaloisElementForRowRotation())
	galKeys = make([]*rlwe.GaloisKey, len(galEls))
	gkgShareCombined := gkg.AllocateShare()
	for i, galEl := range galEls {
		gkgShareCombined.GaloisElement = galEl
		crp := gkg.SampleCRP(crs)
		for _, pi := range P {
			/* #nosec G601 -- Implicit memory aliasing in for loop acknowledged */
			if err := gkg.GenShare(pi.sk, galEl, crp, &pi.gkgShare); err != nil {
				panic(err)
			}
		}
		if err := gkg.AggregateShares(P[0].gkgShare, P[1].gkgShare, &gkgShareCombined); err != nil {
			panic(err)
		}
		for _, pi := range P[2:] {
			if err := gkg.AggregateShares(pi.gkgShare, gkgShareCombined, &gkgShareCombined); err != nil {
				panic(err)
			}
		}
		galKeys[i] = rlwe.NewGaloisKey(params)
		if err := gkg.GenGaloisKey(gkgShareCombined, crp, galKeys[i]); err != nil {
			panic(err)
		}
	}
	return
}
