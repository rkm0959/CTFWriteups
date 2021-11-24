from Crypto.Cipher import AES, PKCS1_OAEP, PKCS1_v1_5
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad, unpad
from Crypto.Util import Counter
from Crypto.Util.number import inverse, long_to_bytes, bytes_to_long, isPrime, getPrime, getRandomRange, sieve_base
from tqdm import tqdm
from pwn import *
from sage.all import *
import gmpy2, pickle, itertools, sys, json, hashlib, os, math, time, base64, binascii, string, re, struct, datetime, subprocess
import numpy as np
import random as rand
import multiprocessing as mp
from base64 import b64encode, b64decode
from sage.modules.free_module_integer import IntegerLattice
from Crypto.Hash import SHA3_256, HMAC, BLAKE2s
from Crypto.Cipher import AES, ARC4, DES

def inthroot(a, n):
    return a.nth_root(n, truncate_mode=True)[0]

fr = open("output.txt", "r")
n = int(fr.readline()[4:])

tokens = [int(fr.readline().split(": ")[1]) for _ in range(920)]
xsq = [pow(x, 2, n) for x in tokens]

# obtained via LLL, thanks BarkingDog!
'''
SZ = 50

M = [[0]*SZ for _ in range(SZ+1)]

for i in range(SZ):
  M[0][i] = xsq[i]

for i in range(SZ):
  M[i+1][i] = n

M = matrix(ZZ, M)

T = M.LLL()

print(T[1])

for i in range(SZ):
    v = T[1][i]
    A = v * pow(xsq[i],-1,n) % n
    print(A)

csqinv = 52983076548811446642078416561526103296256117483454486324354864860934507167817419284299797979785979560318778718382121118437029467788929084290109421055494194638653398930615132561955251638059730256502250470596999508030459148548384745026728889238876530368915312995370308785841757845456662731412090368303339076885
csq = inverse(csqinv, n)

print(csq)
'''

csq = 45826812852445545573935979277992443457076371872089648644915475778319093098825670699151487782654163657210516482531915639455166133358119343973980849423144111072114848219032243215219360482938562035117641611780636775341778802057146053472950017702818869239750207365020007621660815809140827723451995480125236607450
csqinv = 52983076548811446642078416561526103296256117483454486324354864860934507167817419284299797979785979560318778718382121118437029467788929084290109421055494194638653398930615132561955251638059730256502250470596999508030459148548384745026728889238876530368915312995370308785841757845456662731412090368303339076885

X = [v * csqinv % n for v in xsq]
primes = []
for p in sieve_base:
    for x in X:
        if x % p == 0:
            primes.append(p)
            break

SZ = 920
mat = [[0] * SZ for _ in range(SZ)]
# mat[i][j] : number of factor primes[i] in X[j]

for i in range(920):
    v = X[i]
    for j in range(920):
        while v % primes[j] == 0:
            v //= primes[j]
            mat[j][i] += 1
    
M = Matrix(GF(2), mat)
basis_ = M.right_kernel().basis()

# Part 1 : find c
xmult = Integer(1)
Xmult = Integer(1)
cnt = 0
for i in range(920):
    cc = basis_[0][i]
    if int(cc) == 1:
        xmult = xmult * Integer(tokens[i])
        Xmult = Xmult * Integer(X[i])
        cnt += 1

print(cnt)
v = inthroot(Xmult, 2)
xmult = xmult % n 
c_cnt = (xmult * inverse(int(v % n), n)) % n 
c = (c_cnt * inverse(pow(csq, (cnt - 1) // 2, n), n)) % n 

# Part 2 : find some sqrt of 1
xmult = Integer(1)
Xmult = Integer(1)

cnt = 0
for i in range(920):
    cc = basis_[1][i]
    if int(cc) == 1:
        xmult = xmult * Integer(tokens[i])
        Xmult = Xmult * Integer(X[i])
        cnt += 1

print(cnt)
v = inthroot(Xmult, 2)
xmult = xmult % n 
c_cnt = (xmult * inverse(int(v % n), n)) % n 
sq1 = (c_cnt * inverse(pow(csq, cnt // 2, n), n)) % n 

print(n)
p = GCD(sq1+1, n)
q = GCD(sq1-1, n)
assert p != 1 and q != 1 and p * q == n

for u in [1, -1]:
    for v in [1, -1]:
        cc = crt(u, v, p, q)
        c_real = (c * cc) % n
        phi = (p - 1) * (q - 1)
        d = inverse(65537, phi)
        print(long_to_bytes(pow(c_real, d, n)))
