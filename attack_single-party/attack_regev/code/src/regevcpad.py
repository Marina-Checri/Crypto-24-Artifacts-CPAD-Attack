import sys
import math
import random
from fractions import Fraction

def randvec(a, b, n):
    return [random.randint(a, b) for _ in range(n)]

def dotprod(u, v):
    assert len(u) == len(v)
    return sum(u[i] * v[i] for i in range(len(u)))

#Implementation of the Regev cryptosystem
class Regev:
    def __init__(self, n, q, s):
        self.n = n
        self.q = q
        self.s = s
        self.sk = randvec(0, 1, n)

    def print(self):
        print(self.n, self.q, self.s)
        print(self.sk)

    def encrypt(self, m):
        a = randvec(0, self.q - 1, self.n)
        e = round(random.gauss(0, self.s))
        b = (dotprod(a, self.sk) + m * self.q // 2 + e) % self.q
        a.append(b)
        return a

    def add(self, c0, c1):
        return [(c0[i] + c1[i]) % self.q for i in range(len(c0))]

    def forbiddenGetNoiseOfEnc0(self, c):
        a = c[:]
        b = a.pop()
        e = (b - dotprod(a, self.sk)) % self.q
        if e > self.q / 2:
            e -= self.q
        a.append(b)
        return e

    def decrypt(self, c):
        a = c[:]
        b = a.pop()
        m = round(2 * (Fraction((b - dotprod(a, self.sk)) % self.q, self.q))) % 2
        a.append(b)
        return m

#noiseAbsEstim estimate the absolute noise in a ciphertext, using CPAD actions.
def noiseAbsEstim(c0, reg, aca):
    Cladder = [c0]
    k = 1
    a = 0
    b = 0
    ca = []
    cb = []
    while True:
        c = reg.add(Cladder[k - 1], Cladder[k - 1])
        Cladder.append(c)
        if reg.decrypt(c) == 1:
            a = 2 ** (k - 1)
            ca = Cladder[k - 1]
            b = 2 ** k
            cb = Cladder[k]
            k -= 1
            break
        if 2 ** k > reg.q:
            aca.clear()
            aca.append(a)
            aca.append(ca)
            return [0]
        k = k + 1

    while k > 0:
        z = a + 2 ** (k - 1)
        cz = reg.add(ca, Cladder[k - 1])
        if reg.decrypt(cz) == 1:
            b = z
            cb = cz
        else:
            a = z
            ca = cz
        k -= 1

    l = math.ceil(reg.q / (4 * b))
    u = math.floor(reg.q / (4 * a))
    aca.clear()
    aca.append(a)
    aca.append(ca)
    if l == u:
        return [l]
    else:
        return [l, u]

#Print the progress of the attack: when an absolute noise is found, print the true noise of the ciphertext, the found absolute noise and if the attack found exactly one absolute noise, if the noise have the sign of the first noise found or if it is a sign mismatch.
def print_attack_progress(lib, scheme, true_noise, found_noise, found_noise_size, same_sign, check_found_noise, is_correct_noise, nb_of_absolute_noise_of_same_sign_found, nb_of_linear_equation_needed):
    print(f"[{lib}][{scheme}] Ciphertext true noise:   {true_noise}")
    print(f"[{lib}][{scheme}] Found noise:            {found_noise}")
    print(f"[{lib}][{scheme}] Same sign or sign mismatch: ", end="")
    if same_sign:
        print("\033[36mSame sign.\033[39m")
    else:
        print("\033[35mSign mismatch.\033[39m")
    if check_found_noise:
        print(f"[{lib}][{scheme}] Is absolute noise found correct? ", end="")
        if is_correct_noise:
            print("\033[32mYes!\033[39m")
        else:
            print("\033[31mNo.\033[39m")
    print(f"Nb of absolute noise of same sign found:  {nb_of_absolute_noise_of_same_sign_found}/{nb_of_linear_equation_needed}")
    print()

# Find the noise of one coefficient of a ciphertext c0
# to get an equation b = <a,s> + |e| of this LWE coefficient.
# Search n linear equations for the LWE coefficient of a ciphertext,
# where  b' = <a',s> + |e'| such that e and e' have the same sign.
def strategy0(reg):
    N = 0
    M = 1
    c0 = reg.encrypt(0)
    aca0 = []
    e0 = noiseAbsEstim(c0, reg, aca0)

    while len(e0) > 1 or e0[0] == 0:
        c0 = reg.encrypt(0)
        e0 = noiseAbsEstim(c0, reg, aca0)
        M = M + 1

    a0 = aca0[0]
    ca0 = aca0[1]
    real_noise_0 = reg.forbiddenGetNoiseOfEnc0(c0)
    print_attack_progress('In-house lib', 'Regev', real_noise_0, str(e0), len(e0), True, False, False, N, reg.n)
    N = N + 1

    while N < reg.n:
        c1 = reg.encrypt(0)
        M = M + 1
        aca1 = []
        e1 = noiseAbsEstim(c1, reg, aca1)
        
        while len(e1) > 1:
            c1 = reg.encrypt(0)
            e1 = noiseAbsEstim(c1, reg, aca1)
            M = M + 1

        a1 = aca1[0]
        ca1 = aca1[1]
        if e1[0] == 0:
            real_noise_1 = reg.forbiddenGetNoiseOfEnc0(c1)
            print_attack_progress('In-house lib', 'Regev', real_noise_1, str(e1), len(e1), True, False, False, N, reg.n)
            N = N + 1
        elif e0[0] * a0 + e1[0] * a1 > reg.q / 4:
            cz = reg.add(ca0, ca1)
            if reg.decrypt(cz) == 1:
                real_noise_1 = reg.forbiddenGetNoiseOfEnc0(c1)
                print_attack_progress('In-house lib', 'Regev', real_noise_1, str(e1), len(e1), True, False, False, N, reg.n)
                N = N + 1
            else:
                real_noise_1 = reg.forbiddenGetNoiseOfEnc0(c1)
                print_attack_progress('In-house lib', 'Regev', real_noise_1, str(e1), len(e1), False, False, False, N, reg.n)

    print(f'\033[7;33m> {N} linear equations have been found! <\033[0m');
    print(f'\033[1;33m[In-house lib][Regev] number of ciphertexts generated: \033[0m {M}');


# Find n noiseless LWE coefficients of different ciphertexts
# to get n linear equations b = <a,s>.
def strategy1(reg):
    M = 0
    N = 0
    while N < reg.n:
        c1 = reg.encrypt(0)
        M = M + 1
        aca1 = []
        e1 = noiseAbsEstim(c1, reg, aca1)
        
        while len(e1) > 1 or e1[0] != 0:
            c1 = reg.encrypt(0)
            M = M + 1
            e1 = noiseAbsEstim(c1, reg, aca1)
            real_noise_1 = reg.forbiddenGetNoiseOfEnc0(c1)

        print_attack_progress('In-house lib', 'Regev', real_noise_1, str(e1), len(e1), True, False, False, N, reg.n)
        N = N + 1
    print(f'\033[7;33m> {N} linear equations have been found! <\033[0m');
    print(f'\033[1;33m[In-house lib][Regev] number of ciphertexts generated: \033[0m {M}');

if __name__ == '__main__':
    strategy=0
    #Toy params
    #reg=Regev(10,127,7)
    # Weak TFHE params
    #reg=Regev(636,2**32,2**17)
    # TFHE params
    #reg=Regev(1024,2**32,2**17)
    # OpenFHE's params
    reg=Regev(8192,2**240,3.19)
    #reg.print()

    for i in range(10):
        m = random.randint(0, 1)
        c = reg.encrypt(m)
        m2 = reg.decrypt(c)
        assert m == m2

    strategy = 0
    if strategy == 0:
        print("*********************************************")
        print("**************** STRATEGY 0 *****************")
        print("*********************************************\n")
        strategy0(reg)

    elif strategy == 1:
        print("*********************************************")
        print("**************** STRATEGY 1 *****************")
        print("*********************************************\n")
        strategy1(reg)
    else:
        print('No strategy chosen...')
