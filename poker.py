##
# Equality checking proof
#    https://link.springer.com/chapter/10.1007/978-3-540-40974-8_29
#
#   ZkPoK{ (a,b): X = g^a    and    Y = h^b    and    a = b }
#   =
#   ZkPoK{ (a): X = g^a    and    Y = h^a }
#
#   This is a sigma-phi protocol, where
#      phi(a) = (g^a, h^a)
# 


import sys
sys.path += ['elliptic-curves-finite-fields']
from finitefield.finitefield import FiniteField
import elliptic
import os
import random
from Crypto.Hash import SHA256

import secp256k1_openssl
def fast__mul__(self, n):
    if n < 0:
        return -self * -n
    if n == 0:
        return Ideal(self.curve)

    p = secp256k1_openssl.SPoint(self.x.n, self.y.n)
    x,y = p.mult(n)._coords()
    #slow = self._slow_mul(n)
    #assert slow.x == x
    #assert slow.y == y
    return Point(self.curve, Fq(x), Fq(y))
if '_slow_mul' not in dir(elliptic.Point):
    elliptic.Point._slow_mul = elliptic.Point.__mul__
elliptic.Point.__mul__ = fast__mul__

from elliptic import GeneralizedEllipticCurve, Point, Ideal

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

## Construct the second generator
H = random_point(seed=SHA256.new("nothingupmysleeve").digest())

def proof(X, Y, a):
    #assert X == a*G
    #assert Y == a*H

    # blinding factor
    k = random_oracle_string_to_Zp(str(X)+str(Y)+str(a))

    # commitment
    K = (k*G, k*H)

    # use a hash function instead of communicating w/ verifier
    c = sha2_to_long(uint256_to_str(K[1].x.n)[::-1] + uint256_to_str(K[0].x.n)[::-1])

    # response
    s = Fp(k + a*c)

    return (K,s)

def verify(X, Y, prf):
    ((KX,KY),s) = prf
    assert type(X)  is type(Y)  is elliptic.Point
    assert type(KX) is type(KY) is elliptic.Point
    assert type(s) is Fp

    # Recompute c w/ the information given
    c = sha2_to_long(uint256_to_str(KY.x.n)[::-1] + uint256_to_str(KX.x.n)[::-1])
    print c

    assert s.n *G == KX + c*X
    assert s.n *H == KY + c*Y
    return True

def test():
    global a, X, Y, prf
    a = sha2_to_long('hi1')
    X = a*G
    Y = a*H
    prf = (K, s) = proof(X,Y, a)
    verify(X,Y, (K, s))
    
import struct

def uint256_from_str(s):
    """Convert bytes to uint256"""
    r = 0
    t = struct.unpack(b"<IIIIIIII", s[:32])
    for i in range(8):
        r += t[i] << (i * 32)
    return r

def uint256_to_str(s):
    """Convert bytes to uint256"""
    assert 0 <= s < 2**256
    t = []
    for i in range(8):
        t.append((s >> (i * 32) & 0xffffffff))
    s = struct.pack(b"<IIIIIIII", *t)
    return s
