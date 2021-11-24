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


token = '1d85d235d08dfa0f0593b1cfd41d3c98f2a542b2bf7a614c5d22ea787e326b4fd37cd6f68634d9bdf5f618605308d4bb16cb9b9190c0cb526e9b09533f19698b9be89b2e88ba00e80e44d6039d3c15555d780a6a2dbd14d8e57f1252334f16daef316ca692c02485684faee279d7bd926501c0872d01e62bc4d8baf55789b541358dfaa06d11528748534103a80c699a983c385e494a8612f4f124bd0b2747277182cec061c68197c5b105a22d9354be9e436c8393e3d2825e94f986a18bd6df9ab134168297c2e79eee5dc6ef15386b96b408b319f53b66c6e55b3b7d1a2a2930e9d34287b74799a59ab3f56a31ae3e9ffa73362e28f5751f79'
token = bytes.fromhex(token)

# (p(x) + 1 - h)(p(x) + 20 - h)(p(x) + 113 - h)(p(x) + 149 - h)(p(x) + 219 - h)
# p(x) p(x)^2 p(x)^3 p(x)^4 p(x)^5

p = 251
e = [1, 20, 113, 149, 219]
POL = PolynomialRing(GF(p), 'x')
x = POL.gen()

M = [[0] * 245 for _ in range(250)]
target = []

for i in range(0, p-1):
    t = i + 1
    v = int(token[i])
    f = (x + 1 - v) * (x + 20 - v) * (x + 113 - v) * (x + 149 - v) * (x + 219 - v)
    arr = f.coefficients(sparse=False)
    target.append(p - arr[0])
    for j in range(0, 16 + 1):
        M[i][j] = (arr[1] * (t ** j)) % p
    for j in range(17, 17 + 32 + 1):
        M[i][j] = (arr[2] * (t ** (j - 17))) % p 
    for j in range(17 + 33, 17 + 33 + 48 + 1):
        M[i][j] = (arr[3] * (t ** (j - 17 - 33))) % p
    for j in range(17 + 33 + 49, 17 + 33 + 49 + 64 + 1):
        M[i][j] = (arr[4] * (t ** (j - 17 - 33 - 49))) % p
    for j in range(17 + 33 + 49 + 65, 17 + 33 + 49 + 65 + 80 + 1):
        M[i][j] = (arr[5] * (t ** (j - 17 - 33 - 49 - 65))) % p

M = Matrix(GF(p), M)
target = vector(GF(p), target)

v = M.solve_right(target)
print(M.right_kernel().basis())
flag = 'n1ctf{'

for i in range(1, 17):
    flag += bytes([v[i]]).hex()

flag += "}"

print(flag)
    

