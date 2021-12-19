from Crypto.Cipher import AES, PKCS1_OAEP, PKCS1_v1_5
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad, unpad
from Crypto.Util.number import inverse, long_to_bytes, bytes_to_long, isPrime, getPrime
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
from sage.modules.free_module_integer import IntegerLattice
from Crypto.Cipher import AES, ARC4, DES
from Crypto.Hash import SHA512

# data25
sig = [1, 1, -1, -1, 1, 0, 1, -1, -1, -1, 1, 1, 1, -1, 1, -1, -1, -1, 1, -1, 1, -1, -1, -1, -1, -1, 1, 1, -1]
enc = bytes.fromhex('7592b8ab22c5f2beb2310403599f516ae6fa02a6c5290fb264da786ce212661a89f734b31dd7')

def find_sol(args):
    RANGE = args
    for i in range(RANGE[0], RANGE[1]):
        cc = [1 + ((i >> j) & 1) for j in range(28)]
        priv = [sig[j] * cc[j] for j in range(5)] + [0] + [sig[j] * cc[j-1] for j in range(6, 29)]
        secret = ','.join(f'{e:+}' for e in priv)
        stream = SHA512.new(secret.encode()).digest()
        flag = bytes(x^y for x,y in zip(enc, stream))
        if b"hxp{" in flag:
            print(flag)
    return None 

def PoW(NUM):
    batch = 1000000
    pool = mp.Pool(NUM)
    nonce = 0
    for nonce in tqdm(range(0, 1 << 28, batch * NUM)):
        nonce_range = [(nonce + i * batch, nonce + i * batch + batch) for i in range(NUM)]
        params = [(RANGE) for RANGE in nonce_range]
        solutions = pool.map(find_sol, params)
        solutions = list(filter(None, solutions))
        if len(solutions) != 0:
            return solutions[0]

NUM = 12
start = time.time()

v = PoW(NUM)

end = time.time()

print(end - start)