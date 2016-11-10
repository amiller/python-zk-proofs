##
# Examples of simple zero-knowledge proofs implemented in
#
# More specifically, these are non-interactive, zero-knowledge,
# proofs of knowledge. They can be analyzed and proven secure
# in the random oracle model (the random oracle here is instantiated
# with the SHA2 hash function).
#
# Lecture notes:
#   http://soc1024.web.engr.illinois.edu/teaching/ece598am/fall2016/zkproofs.pdf


import sys
sys.path += ['elliptic-curves-finite-fields']
from finitefield.finitefield import FiniteField
from elliptic import GeneralizedEllipticCurve, Point, Ideal
import elliptic
import os
import random

## 
## This is the definition of secp256k1, Bitcoin's elliptic curve.
## You can probably skip this, it's a bunch of well-known numbers
##

# First the finite field
q = 2**256 - 2**32 - 2**9 - 2**8 - 2**7 - 2**6 - 2**4 - 1
Fq = FiniteField(q,1) # elliptic curve over F_q

# Then the curve, always of the form y^2 = x^3 + {a6}
curve = GeneralizedEllipticCurve(a6=Fq(7)) # E: y2 = x3+7

# base point, a generator of the group
Gx = Fq(0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798)
Gy = Fq(0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)
G = Point(curve, Gx, Gy)

# This is the order (# of elements in) the curve
p = order = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
Fp = FiniteField(p,1)


##
## Convenience functions
##
def random_oracle_string_to_Zp(s):
    return sha2_to_long(s) % p

def sha2_to_long(seed):
    # BUG: we should replace this with return uint256_from_str(Hash(seed))
    from Crypto.Hash import SHA256
    return long(SHA256.new(seed).hexdigest(),16)

# This easy sqrt works for this curve, not necessarily all curves
# https://en.wikipedia.org/wiki/Quadratic_residue#Prime_or_prime_power_modulus
def sqrt(a):
    # p: modulus of the underlying finitefield
    return a ** ((q+1)/4)

def random_point(seed=None):
    import os
    if seed is None: seed = os.urandom(32)
    assert type(seed) == str and len(seed) == 32
    x = sha2_to_long(seed)
    while True:
        try:
            p = solve(Fq(x))
        except ValueError:
            if curve.testPoint(p.x, p.y): break
            seed = Hash('random_point:' + seed)
            x = sha2_to_long(seed)
            continue
        break
    return p

def solve(x):
    # Solve for y, given x
    # There are two possible points that satisfy the curve,
    # an even and an odd. We choose the odd one.
    y = sqrt(x**3 + 7)
    if y.n % 2 == 0: y = -y
    if not curve.testPoint(x, y): raise ValueError
    return Point(curve, x, y)

##
## Example ZK Proof
## 
##    This is a discrete log proof of ZKP{ (a): A = g^a }
##

def sigma_proof1(a, A):
    assert a*G == A
    # blinding factor
    k = random.randint(0,order)

    # commitment
    K = k*G

    # use a hash function instead of communicating w/ verifier
    c = random_oracle_string_to_Zp(str(K))

    # response
    s = Fp(k + c*a)

    return (K,s)


def verify_proof1(A, prf):
    (K,s) = prf
    assert type(A) is type(K) is elliptic.Point
    assert type(s) is Fp

    # Recompute c w/ the information given
    c = sha2_to_long(str(K))

    assert s.n *G == K + c*A
    return True

def test_proof1():
    # Randomly choose "a"
    a = random.randint(0,order)
    A = a*G

    prf = sigma_proof1(a, A)
    assert verify_proof1(A, prf)

##
## Example: a more complicated discrete log proof
##     Zk{ (a, b):  A=g^a, B=g^b,  C = g^(a(b+3)) }
##
##  First rewrite as:
##     Zk{ (a, b):  A=g^a, B=g^b,  C/A^3 = A^b) }

def sigma_proof2(a, b, A, B, C):
    assert a*G == A
    assert b*G == B
    assert (a*(b+3))*G == C
    # blinding factor
    kA = random.randint(0,order)
    kB = random.randint(0,order)

    # commitment
    KA = kA *G
    KB = kB *G
    KC = kB *A

    # use a hash function instead of communicating w/ verifier
    c = random_oracle_string_to_Zp(str(KA) + str(KB) + str(KC))

    # response
    s1 = Fp(kA + c * a)
    s2 = Fp(kB + c * b)

    return (KA,KB,KC,s1,s2)

def verify_proof2(A, B, C, prf):
    (KA,KB,KC,s1,s2) = prf
    assert type(KA) == type(KB) == type(KC) == elliptic.Point
    assert type(s1) == type(s2) == Fp

    # Recompute c w/ the information given
    c = random_oracle_string_to_Zp(str(KA) + str(KB) + str(KC))

    assert s1.n*G == KA + c*A
    assert s2.n*G == KB + c*B
    assert s2.n*A == KC + c*(C - 3*A)
    return True

def test_proof2():
    # Randomly choose "a" and "b"
    a = random.randint(0,order)
    b = random.randint(0,order)
    A = a*G
    B = b*G
    C = (a*(b+3)) * G

    prf = sigma_proof2(a, b, A, B, C)
    assert verify_proof2(A, B, C, prf)
