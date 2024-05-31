# Practical CPAD attack on "exact" and threshold FHE schemes and libraries

Welcome to the Practical CPAD attack on "exact" and threshold FHE schemes and libraries! This repository contains the implementations of the attacks on Fully Homomorphic Encryption (FHE) libraries from the paper 

> M. Checri and R. Sirdey and A. Boudguiga and J.-P. Bultel, _On the practical CPAD security of "exact" and threshold FHE schemes_, CRYPTO'24.

for both single-party and multi-party scenarios.

## Table of Contents

- [Introduction](#introduction)
- [Dependencies](#dependencies)
- [Folder Structure](#folder-structure)
- [Getting Started](#getting-started)
- [Acknowledgment](#acknowledgment)

## Introduction

Fully Homomorphic Encryption (FHE) is a corpus of cool new school cryptographic techniques which allow to compute directly over encrypted data. In [https://eprint.iacr.org/2024/116](https://eprint.iacr.org/2024/116) (accepted for publication at CRYPTO'24) we have exhibited new passive key recovery attacks on most maintstream FHE cryptosystems (BFV, BGV, TFHE) and libraries (SEAL, OpenFHE, Lattigo, TFHELib). These attacks are very practical as we have been able to run them in less than hour on an average laptop PC. So is FHE broken? As expected… Not quite. In fact, our attacks are possible only because we perform them in the CPAD model which grants the adversary just a little bit more power than it has in the standard CPA model achieved by these FHE cryptosystems. Still, the very existence of these attacks contributes to a better understanding of FHE security in the “slightly beyond passive” adversary regime and have a number of far reaching consequences in terms of FHE practice.

<!-- Fully Homomorphic Encryption (FHE) is a powerful cryptographic technique that allows computations to be performed on encrypted data without the need for decryption. However, like any cryptographic system, FHE schemes are vulnerable to various attacks. -->

This repository provides the implementations which we created to obtain the experimental results in [https://eprint.iacr.org/2024/116](https://eprint.iacr.org/2024/116) against popular FHE libraries. The attacks themselves target the vulnerability of FHE schemes to decryption errors probing, ultimately allowing to recover the secret key used in these schemes.

<!-- The attack described in the paper aims to recover the secret key used in FHE schemes. In this repository, we provide implementations of these attacks, along with the number of linear equations required to recover the secret key. However, it's worth noting that while we provide the necessary equations, solving the linear system to retrieve the secret key still requires additional steps.-->

### CPAD Security Background

Since its inception more than ten years ago, Fully Homomorphic Encryption has been the subject of a lot of research towards more efficiency and better practicality. From a security perspective, however, FHE still raises a number of questions and challenges. In particular, all the FHE used in practice, mainly BFV, BGV, CKKS and TFHE, achieve only CPA-security, which is the technical term for security against passive adversaries. Furthermore, it is well known that the ciphertext malleability offered by FHE is contradictory with the golden standard for security against active adversaries (CCA2) although some hope exists that weaker levels (e.g. CCA1 or slightly above) may be practically achievable. Very active research is presently done on this within the FHE community.

In essence, for CPA security, the adversary has access only to an encryption oracle meaning that, in an attempt to break the cryptographic scheme at hand, he or she can choose many plaintexts and observe the associated outputs of the encryption function i.e., well-formed ciphertexts. This is the baseline security property for cryptosystems with provable security. For CCA security, the adversary additionally has access to a decryption oracle. As long as he or she feeds only well-formed ciphertexts to that later oracle, the adversary does not learn anything he or she does not already know, so everything is fine. But, and that’s the “active security” part of CCA security, the adversary does not have to play by the book and may feed arbitrary inputs to the decryption oracle. When a scheme is not CCA-secure, this is where the Pandora box opens up. Regarding FHE, the bottom line is that all the schemes we are using in practice are completely insecure (and trivially so) as soon as the adversary is granted access to a decryption oracle. This is well known and real-world FHE practitioners should be prepared to live with this by including additional countermeasures in their systems (although this is much easier said than done).

However, FHE can get into trouble even against adversaries much less poweful than full-blown CCA(1) ones. Indeed, in a seminal Eurocrypt'21 paper, Li and Micciancio were the first to study the security of FHE against a slight, seemingly benign extension of CPA security, where the adversary is granted access only to a highly constrained decryption oracle that accepts only genuine ciphertexts or ciphertexts derived from genuine ciphertexts by means of genuine homomorphic operations. This is called CPAD security. The intuition is that, given a FHE scheme, if the adversary knows m, f as well as c=enc(m), granting him or her access to the decryption of an homomorphic evaluation of f on c should not raise any issue. Indeed, he or she can compute f(m) by his or herself and, by definition of FHE, we should expect that the result of such an evaluation would decrypt to f(m). So, at first glance, it appears that this constrained oracle does not provide more information to the adversary than he or she can compute on his or herself and, as such, that this CPAD security is implied by or even equivalent to CPA security. Interestingly, Li and Micciancio demonstrated that these intuitions are not true for approximate FHE schemes such as CKKS, for which it turns out that decrypted FHE results leak the LWE noises in the ciphertexts, resulting in the ability for the adversary to easily and practically recover the secret decryption key of the scheme. They further demonstrated their attack practicality on most mainstream libraries implementing CKKS. 

Up our attacks, the current status quo in the state-of-the-art was that this line of attack does not apply to the other schemes such as BFV, BGV or TFHE which are “marketed” as non-approximate.

<!-- The CPAD (Chosen Plaintext Attack with a Decryption oracle) security context extends the traditional chosen-plaintext attack (CPA) model by allowing adversaries to interact with a decryption oracle. In this extended model, adversaries can submit ciphertexts of their choice to the oracle and receive the corresponding plaintexts. However, there are limitations on the types of ciphertexts that can be decrypted, because the decryption oracle give an answer only on well-formed ciphertexts.

This enhanced security context is particularly relevant in cryptographic scenarios where adversaries may have partial access to the decryption process. By querying the decryption oracle, adversaries can gain insights into the plaintexts corresponding to specific ciphertexts, which can aid in cryptanalysis and potentially compromise the security of the encryption scheme.

The CPAD model introduces additional challenges for designing secure cryptographic systems, as it requires defenses against adversaries with access to decryption capabilities. Understanding and mitigating the risks associated with CPAD attacks is crucial for ensuring the security of encryption schemes in practical applications.-->


### Learning With Errors (LWE) Problem

It turns out that the security of FHE is based on the Learning With Errors (LWE) problem. In a nutshell, the LWE problem consists in hiding a secret vector s in noised linear equations over Zq, i.e. in pairs of the form (a,b) with b=<a,s>+e, where a is a randomly chosen vector and where the noise term e follows a specific probability distribution.

In LWE-based cryptosystems, s is the secret key and messages are embedded into such kind of linear equations. So in essence, an adversary gets (polynomially) many such noised equations and one way of breaking the cryptosystem is to try to recover s from these. This is a called a key-recovery attack. Of course, when no noise is added, it is easy to recover s by means of standard linear algebra techniques. The same is true when the noise happens to be known by the adversary. When this is not the case, there are good reasons to believe that retrieving s is computationally intractable even for a hypothetical mighty quantum computer!

Trying to find the noise term is exactly the path we followed to build our attacks. We consider encryptions of 0, each giving one noised linear equation in the secret (key) vector s, and then recover the noise term e by means of a simple (yet clever) algorithm. The key point is that this algorithm requires the decryptions only of ciphertexts which are derived from our initial (well-formed) encryptions of 0 by means of valid homomorphic operations (in fact, only homomorphic additions). Therefore, our algorithm is a valid CPAD adversary.

When enough (denoised) linear equations are then obtained, s can be recovered easily. In fact, one can do so easily-enough that we can consider that the attack is successfully demonstrated without explicitly solving the final linear system over Zq.

<!-- The Learning With Errors (LWE) problem is a fundamental computational problem in the field of lattice-based cryptography. It involves finding a hidden linear relationship between random noise and linearly related observations.

In the context of FHE (Fully Homomorphic Encryption), many cryptographic schemes are based on the hardness of the LWE problem. Specifically, these schemes rely on the assumption that it is computationally difficult to recover the secret key from noisy linear equations derived from LWE instances.

The LWE problem can be formally stated as follows: given a matrix A and a vector b, where A is a random matrix and b is the result of multiplying A by a secret vector s modulo q, along with some noise e, the task is to recover the secret vector s from the noisy vector b.

Efficiently solving the LWE problem is believed to be computationally difficult, especially as the dimension of the problem instance increases. This hardness assumption forms the basis for the security of many lattice-based cryptographic schemes, including those used in FHE.

Understanding the properties and complexity of the LWE problem is essential for analyzing the security of FHE schemes and designing robust cryptographic protocols resistant to attacks.-->


## Dependencies

To build and run the artifacts in this repository, you will need the following dependencies:

- Docker: Ensure you have Docker installed to build and run the containerized environments.

Each subdirectory contains a `Dockerfile` to set up the required environment for the respective library.

## Folder Structure

- **attack_single-party**: Contains implementations of attacks targeting single-party FHE schemes.
  - **attack_regev**: stand-alone proof-of-concept (Python) implementations of the attack on Regev.
  - **attack_SEAL**: Implementations of the attack on BFV and BGV using the Microsoft SEAL library.
  - **attack_OpenFHE**: Implementations of the attack on BFV and BGV using the OpenFHE library.
  - **attack_lattigo**: Implementations of the attack on BFV using the Lattigo library.
  - **attack_tfheLib**: Implementations of the attack on TFHE using the TFHELib library.
- **attack_multi-party**: Contains implementations of attacks targeting multi-party (aka Threshold) FHE schemes.
  - **attack_threshold_lattigo**: Implementations of the attack on threshold BFV using the Lattigo library.
  - **attack_threshold_OpenFHE**: Implementations of the attack on threshold BFV using the OpenFHE library.
- **README.md**: This file you're currently reading.
- **view_tree.txt**: A text file containing the tree structure of the repository.

## Getting Started

To get started with using or contributing to this repository, please refer to the README files in each attack folder for specific instructions and requirements.

Each attack implementation in this repository is designed to target a specific FHE library. Therefore, each directory contains a Dockerfile for setting up the necessary dependencies and environment. Simply follow the instructions provided in the README.md of each directory to launch the attack on the respective library.

For example, to launch an attack on the OpenFHE library, navigate to the `attack_single-party/attack_OpenFHE` directory and follow the instructions in the README.md file.

### Reading the Outputs

All the attacks consistently give an output of the form:
```
[Library][Scheme] Ciphertext true noise: AAA
[Library][Scheme] Found noise:         [ BBB ]
[Library][Scheme] Same sign or sign mismatch: CCC
Nb of absolute noise of same sign found: DDD/EEE
```

The final output is always of the form:
```
> EEE linear equations have been found! <
[Library][Scheme] number of ciphertexts generated: FFF
[Library][Scheme] number of noiseless samples: GGG/FFF
[Library][Scheme] number of ciphertexts which absolute noise fully determined: HHH/FFF
[Library][Scheme] number of evaluations: III
[Library][Scheme] number of decryptions: JJJ
```


#### Explanation of Output Fields:

1. ``AAA``: The "true" noise value of the ciphertext (with its sign).
2. `BBB`: The absolute noise value that was found by the attack.
3. ``CCC``: Indicates whether the found noise has the same sign as the first found absolute noise or if it is a sign mismatch.
5. ``DDD``: Number of instances where the absolute noise with the same sign was found at this step of the attack.
6. ``EEE``: Indicates the number of linear equations needed for the attack.
7. ``FFF``: Total number of ciphertexts generated during the attack <=> number of calls to the encryption oracle.
8. ``GGG``: Number of ciphertexts that were noiseless.
9. ``HHH``: Number of ciphertexts for which the absolute noise was fully determined.
10. `III`: Total number of evaluations performed  <=> number of calls to the evaluation oracle.
11. ``JJJ``: Total number of decryptions performed  <=> number of calls to the decryption oracle.

And **[Library][Scheme]** are the library and scheme used to perform the attack. 

## Acknowledgment

We would like to express our gratitude to the following individuals and resources for their assistance to this project:

- **Antoine Choffrut**: We would like to thank our colleague Antoine Choffrut for providing key insights on HElib noise upper bound monitoring and blocked decryption mechanisms.
- **France 2030 ANR Program**: This work was supported by the France 2030 ANR Projects ANR-22-PECY-003 SecureCompute and ANR-23-PECL-0009 TRUSTINCloudS.
- **Horizon Europe Program**: This work was supported by the European Union’s Horizon Europe Research and Innovation Program ENCRYPT under Grant Agreement No. 101070670.
- **OpenAI's GPT-3 Language Model**: We extend our appreciation to the GPT-3 model developed by OpenAI for providing guidance and assistance in creating the README files and Dockerfile configurations for this repository.
