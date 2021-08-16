from Crypto.Cipher import AES, PKCS1_OAEP, PKCS1_v1_5
from Crypto.PublicKey import RSA
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

p = int(gmpy2.next_prime(2**64))

f = open("enc.pickle", "rb")
res = pickle.load(f)
f.close()

cip = bytes.fromhex(res["cip"])
iv = bytes.fromhex(res["iv"])
leak = res["leak"]

M = Matrix(GF(p), 64, 64)
vec = [0] * 64

for i in range(64):
	idx1 = (i ^ 0)
	idx2 = (i ^ 1)
	k = 1 if i % 2 else 2

	M[i, idx1] = k 
	M[i, idx2] = -1
	vec[i] = int(leak[16 * i : 16 * i + 16], 16)

vec = vector(GF(p), vec)
seeds = M.solve_right(vec)

pad = 0xDEADC0DE

for i in range(32):
	u = int(seeds[i])
	v = int(seeds[i + 32])
	ret2 = pad ^ ((v * inverse(u, p)) % p) 
	ret1 = pad ^ ((u * inverse(ret2, p)) % p)
	seeds[i] = ret1
	seeds[i + 32] = ret2

out1 = ''
for i in range(64):
	a, b = seeds[i^0], seeds[i^1]
	k = 1 if i % 2 else 2
	ret = (k * a - b + p) % p
	out1 += format(int(ret), '016x')

key = bytes.fromhex(out1)
key = hashlib.sha256(key).digest()[:16]

flag = AES.new(key, AES.MODE_CBC, iv).decrypt(cip)

print(flag)