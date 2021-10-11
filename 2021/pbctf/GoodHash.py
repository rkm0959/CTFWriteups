from Crypto.Cipher import AES, PKCS1_OAEP, PKCS1_v1_5
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad, unpad
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
from ecdsa import ecdsa
from Crypto.Hash import SHA3_256, HMAC, BLAKE2s
from Crypto.Cipher import AES, ARC4, DES

class GoodHash:
    def __init__(self, v=b""):
        self.key = b"goodhashGOODHASH"
        self.buf = v

    def update(self, v):
        self.buf += v

    def digest(self):
        cipher = AES.new(self.key, AES.MODE_GCM, nonce=self.buf)
        enc, tag = cipher.encrypt_and_digest(b"\0" * 32)
        return enc + tag

    def hexdigest(self):
        return self.digest().hex()

POL = PolynomialRing(GF(2), 'a')
a = POL.gen()
F = GF(2 ** 128, name = 'a', modulus = a ** 128 + a ** 7 + a ** 2 + a + 1)

def aes_enc(p, k):
    cipher = AES.new(key = k, mode = AES.MODE_ECB)
    return cipher.encrypt(p)

def int_to_finite(v):
    bin_block = bin(v)[2:].zfill(128)
    res = 0
    for i in range(128):
        res += (a ** i) * int(bin_block[i])
    return F(res)

def bytes_to_finite(v):
    v = bytes_to_long(v)
    return int_to_finite(v)

def finite_to_int(v):
    v = POL(v)
    res = v.coefficients(sparse = False)
    ret = 0
    for i in range(len(res)):
        ret += int(res[i]) * (1 << (127 - i))
    return ret

def finite_to_bytes(v):
    cc = finite_to_int(v)
    return long_to_bytes(cc, blocksize = 16)

def hasher(v):
    H = aes_enc(b"\x00" * 16, b"goodhashGOODHASH")
    H_f = bytes_to_finite(H)
    ret = F(0)
    res = bytes_to_long(v)
    bin_block = bin(res)[2:].zfill(512)
    bas = []
    for i in range(512):
        cc = F(a ** int(i % 128)) * F(H_f ** (3 - i // 128)) 
        bas.append(finite_to_int(cc))
        ret += F(a ** int(i % 128)) * F(H_f ** (3 - i // 128)) * int(bin_block[i])
    return bas, finite_to_int(ret)

ACCEPTABLE = string.ascii_letters + string.digits + string.punctuation + " "
print(ACCEPTABLE)

conn = remote('good-hash.chal.perfect.blue', 1337)
body = conn.recvline()[6:-1]
print(body)
print(len(body))
print(conn.recvline())

bases, target = hasher(body + b"\x00\x00\x00")

starter = b'{"admin": true, "a": "'
finisher = b'"}\x00\x00\x00'
print(len(starter) + len(finisher))

print("[+] Building Matrix")

SZ = 128 + 37 * 3 + 27 * 8
M = Matrix(GF(2), SZ, 512)
vv = []

for i in range(128):
    for j in range(512):
        M[i, j] = (bases[j] >> i) & 1
    vv.append((target >> i) & 1)

for i in range(37):
    M[3 * i + 128, 8 * (22 + i)] = 1
    vv.append(0) # 128
    M[3 * i + 128 + 1, 8 * (22 + i) + 1] = 1
    vv.append(1) # 64
    M[3 * i + 128 + 2, 8 * (22 + i) + 2] = 1
    vv.append(0) # 32

for i in range(22):
    for j in range(8):
        M[8 * i + j + 37 * 3 + 128, 8 * i + j] = 1
        vv.append((int(starter[i]) >> (7 - j)) & 1)
for i in range(5):
    for j in range(8):
        M[8 * i + j + 37 * 3 + 22 * 8 + 128, 8 * (59 + i) + j] = 1
        vv.append((int(finisher[i]) >> (7 - j)) & 1)

vv = vector(GF(2), vv)
val = M.solve_right(vv)
kernels = M.right_kernel().basis()

print("[+] Finished Solving Matrix, Finding Collision Now...")

attempts = 0

while True:
    attempts += 1
    print(attempts)
    cur = val 
    for i in range(len(kernels)):
        cur += (kernels[i] * GF(2)(rand.randint(0, 1)))
    fins = 0
    for i in range(512):
        fins = 2 * fins + int(cur[i])
    fins = long_to_bytes(fins)
    print(fins)
    fins = fins[:61]
    print(fins, len(fins))
    try:
        if len(fins) == 61 and (any(v not in ACCEPTABLE for v in fins.decode()) == False):
            token = json.loads(fins)
            bases2, finresult = hasher(fins + b"\x00\x00\x00")
            print(GoodHash(body + b"\x00\x00\x00").hexdigest())
            print(GoodHash(fins + b"\x00\x00\x00").hexdigest())
            print(target)
            print(finresult)
            print(token)
            if token["admin"] == True:
                conn.sendline(fins)
                print(conn.recvline())
                print(conn.recvline())
                break
    except:
        pass