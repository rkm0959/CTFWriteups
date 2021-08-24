from Crypto.Cipher import AES, PKCS1_OAEP, PKCS1_v1_5
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad
from Crypto.Util.number import inverse, long_to_bytes, bytes_to_long, isPrime, getPrime, GCD
from tqdm import tqdm
from pwn import *
from sage.all import *
import gmpy2, pickle, itertools, sys, json, hashlib, os, math, time, base64, binascii, string, re, struct, datetime, subprocess
import numpy as np
import random as rand
import multiprocessing as mp
from base64 import b64encode, b64decode
from sage.modules.free_module_integer import IntegerLattice
from ecdsa import ecdsa
from sage.modules.free_module_integer import IntegerLattice
from collections import deque 

def gcd_pol(A, B):
    B = B.monic()
    if A % B == 0:
        return B
    return gcd_pol(B, A % B)
    
# 1. interpolate to find all coefficients
# 2. polynomial gcd

p = getPrime(256)
q = getPrime(256)

N = p * q
e = 11
flag = bytes_to_long(open("flag.txt", "rb").read())
print(flag.bit_length())
coeffs = deque([rand.randint(0, 128) for _ in range(16)])

POL = PolynomialRing(Zmod(N), 'x')
x = POL.gen()

poly1 = 0
for i in range(16):
    poly1 += (coeffs[i] * (x ** i))

pts = []

for i in range(180): # just wait for 16 cycle 
    msg = Zmod(N)(i + 1)
    enc = Zmod(N)(poly1(msg) ** e)
    pts.append((msg, enc))

# lagrange polynomial
# note : this works because coefficients of f ** 11 are very small
# therefore, we can factorize over ZZ instead of Zmod(N) (which is pretty much impossible)

poly1 = 0
for i in range(len(pts)):
    add = pts[i][1]
    for j in range(len(pts)):
        if i == j:
            continue
        add *= (x - pts[j][0]) / Zmod(N)(pts[i][0] - pts[j][0])
    poly1 += add

coef_powered = poly1.coefficients(sparse = False)

POL_Z = PolynomialRing(ZZ, 'y')
y = POL_Z.gen()

poly2 = 0
for i in range(len(coef_powered)):
    poly2 += int(coef_powered[i]) * (y ** i)

res = list(poly2.factor())

print(res)

coefs = res[0][0].coefficients(sparse = False)

coefs = deque(coefs)

poly3 = 0
val3 = 0
for i in range(16):
    poly3 += Zmod(N)(coefs[i]) * (x ** i)
    val3 += Zmod(N)(coefs[i]) * (Zmod(N)(flag) ** i) # can recover via choice = 2
poly3 -= val3

coefs.rotate(1)

poly4 = 0
val4 = 0
for i in range(16):
    poly4 += Zmod(N)(coefs[i]) * (x ** i)
    val4 += Zmod(N)(coefs[i]) * (Zmod(N)(flag) ** i) # can recover via choice = 2
poly4 -= val4

poly5 = gcd_pol(poly3, poly4)
print(poly5)

fin = N - int(poly5.coefficients(sparse=False)[0]) % N

print(long_to_bytes(fin))

# rarctf{fr4nkl1n_reiter_w0rks_0n_p0lynom14ls_t00_5851060b}