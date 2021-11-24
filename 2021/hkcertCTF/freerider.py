from Crypto.Cipher import AES, PKCS1_OAEP, PKCS1_v1_5
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad, unpad
from Crypto.Util import Counter
from Crypto.Util.number import inverse, long_to_bytes, bytes_to_long, isPrime, getPrime, getRandomRange
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

def bytexor(a, b):
	assert len(a) == len(b)
	return bytes(x ^ y for x, y in zip(a, b))

st = bytes.fromhex("6ccb80c46c19243a37633d316a66871ca70ec8a44f48a80134f31d8d27f920c6bd5d810831833221d0f282130d2c222de38c2080ef995b2ad10dc5af8518")
st = bytes_to_long(st)
res = []
for i in range(256):
    cipher = AES.new(key = bytes([i]) + b"\x00" * 15, mode = AES.MODE_CTR, counter = Counter.new(128, initial_value=0))
    xored = cipher.encrypt(b"\x00" * 62)
    res.append(bytes_to_long(xored))
fin = bytes_to_long(b"Congratulations! hkcert21{" + b"\x00" * 35 + b"}")
df = fin ^ st

# [0, 26 * 8), [26 * 8, 27 * 8, 60 * 8], [61 * 8, 62 * 8)

M = Matrix(GF(2), 26 * 8 + 35 + 8, 256)
dif = [0] * (26 * 8 + 35 + 8)

for i in range(256):
    for j in range(0, 26 * 8):
        M[j, i] = ((res[i] >> (62 * 8 - j - 1)) & 1)
        dif[j] = ((df >> (62 * 8 - j - 1)) & 1)
    for j in range(0, 35):
        M[j + 26 * 8, i] = ((res[i] >> (62 * 8 - (j + 26) * 8 - 1)) & 1)
        dif[j + 26 * 8] = ((df >> (62 * 8 - (j + 26) * 8 - 1)) & 1)
    for j in range(0, 8):
        M[j + 26 * 8 + 35, i] = ((res[i] >> (8 - j - 1)) & 1)
        dif[j + 26 * 8 + 35] = ((df >> (8 - j - 1)) & 1)

dif = vector(GF(2), dif)

v = M.solve_right(dif)
kern_base = M.right_kernel().basis()

for i in range(1 << len(kern_base)):
    sol = v
    for j in range(len(kern_base)):
        if ((i >> j) & 1) == 1:
            sol += kern_base[j]
    weight = 0
    for k in range(256):
        weight += int(sol[k])
    if weight <= 16:
        print(sol)
        print(weight)
        ciphertext = bytes.fromhex("6ccb80c46c19243a37633d316a66871ca70ec8a44f48a80134f31d8d27f920c6bd5d810831833221d0f282130d2c222de38c2080ef995b2ad10dc5af8518")
        for t in range(256):
            if int(sol[t]) == 1:
                cipher = AES.new(key = bytes([t]) + b"\x00" * 15, mode = AES.MODE_CTR,  counter=Counter.new(128, initial_value=0))
                ciphertext = cipher.decrypt(ciphertext)
        print(ciphertext)







