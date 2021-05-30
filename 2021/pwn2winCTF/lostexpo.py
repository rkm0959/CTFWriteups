from Crypto.Cipher import AES, PKCS1_OAEP, PKCS1_v1_5
from Crypto.PublicKey import RSA
from Crypto.Util.number import inverse, long_to_bytes, bytes_to_long, isPrime, getPrime
from tqdm import tqdm
from pwn import *
from sage.all import *
import itertools, sys, json, hashlib, os, math, time, base64, binascii, string, re, struct, datetime, subprocess
import numpy as np
import random as rand
import multiprocessing as mp

rand.seed(6174)
n = 7
order = list(itertools.product(range(n), repeat=2))
rand.shuffle(order)
order.sort(key=(lambda x: np.sign(np.diff(x))))

def getPrimemod(e):
    # 1 mod e
    while True:
        tt = rand.randint(1, 1 << 128)
        tt = e * tt + 1
        if isPrime(tt):
            return tt

class Mat:
    def __init__(self):
        self.n = n
        self.m = [[0]*n for _ in range(n)]

    def __iter__(self):
        for i in range(self.n):
            for j in range(self.n):
                yield self.m[i][j]

    def I(self):
        r = Matrix()
        for i in range(n):
            r[i, i] = 1
        return r

    def __setitem__(self, key, value):
        self.m[key[0]][key[1]] = value

    def __getitem__(self, key):
        return self.m[key[0]][key[1]]

    def __mul__(self, other):
        r = Matrix()
        for i in range(n):
            for j in range(n):
                r[i, j] = sum(self[i, k]*other[k, j] for k in range(n))
        return r

    def __pow__(self, power):
        r = self.I()
        for _ in range(power):
            r = r * self
        return r

    def __str__(self):
        return str(self.m)

f = open('enc', 'rb')
s = f.read()
L = len(s)
f.close()

print(order)
e = 341524 # by checking M[0, 0]

N = 7

each = (L) // (N * N)

p = getPrime(256)
cur = 0
res = [[0] * N for i in range(N)]
for i in range(N):
    for j in range(N):
        for idx in range(cur * each, cur * each + each):
            res[i][j] = (100 * res[i][j] + s[idx]) % p
        cur += 1

print("HI")
M = Matrix(GF(p), res)
TT = Matrix(GF(p), 7, 7)

# build (0, 0)
for i in range(256):
    TT[0, 0] = i
    cc = TT ** e
    if cc[0, 0] == M[0, 0]:
        print(i)
        break

# build (1, 0)
for i in range(256):
    TT[1, 0] = i
    cc = TT ** e
    if cc[1, 0] == M[1, 0]:
        print(i)
        break

# build (2, 0) | (2, 1)
found = False
for i in tqdm(range(256)):
    for j in range(256):
        TT[2, 0] = i
        TT[2, 1] = j
        cc = TT ** e
        if cc[2, 0] == M[2, 0]:
            print(i, j)
            found = True
            break
    if found:
        break

# build diagonals
for i in range(3, 7):
    for j in range(256):
        TT[i, i] = j
        cc = TT ** e
        if cc[i, i] == M[i, i]:
            print(i, j)
            break

# build the rest
for i in range(1, 7):
    for j in range(max(3, i), 7):
        # TT[j, j - i]
        for k in range(256):
            TT[j, j-i] = k
            cc = TT ** e
            if cc[j, j-i] == M[j, j-i]:
                print(j, i, k)
                break

ans = ''
for i in range(49):
    u, v = order[i]
    cc = chr(int(TT[u, v]))
    ans += cc

print(ans)
    

print(TT ** e - M)
