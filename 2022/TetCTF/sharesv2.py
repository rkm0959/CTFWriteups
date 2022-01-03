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
from mt19937predictor import MT19937Predictor
from Crypto.Hash import SHA256

conn = remote("139.162.61.222", 13372)
# conn.interactive()
ALLOWED_CHARS = string.ascii_lowercase + string.digits + "_"
P = len(ALLOWED_CHARS)
INT_TO_CHAR = {}
CHAR_TO_INT = {}
for _i, _c in enumerate(ALLOWED_CHARS):
    INT_TO_CHAR[_i] = _c
    CHAR_TO_INT[_c] = _i

# 0 ~ 31
IDX = [[0] * 32 for _ in range(32)]
cur = 32
for i in range(32):
    for j in range(i, 32):
        IDX[i][j] = cur 
        cur += 1

def get_idx(i, j):
    if i > j:
        i, j = j, i 
    return IDX[i][j]

SZ = IDX[31][31] + 1

dat = []
vec = []


for idx in tqdm(range(100)):
    conn.sendline(b"a")
    ret = eval(conn.recvline())
    
    mat = []
    password_part = []
    res_part = []

    # (pass - res)(pass - res - 19) = 0

    for i in range(32):
        password_vec = [CHAR_TO_INT[ret[i][x]] for x in range(32)]
        res = CHAR_TO_INT[ret[i][32]]

        expanded = [0] * SZ 
        result = (- (res * (res + 19))) % P

        for j in range(32):
            for k in range(32):
                expanded[get_idx(j, k)] += password_vec[j] * password_vec[k]
        for j in range(32):
            expanded[j] = ((-1) * (2 * res + 19) * password_vec[j]) % P
        
        dat.append(expanded)
        vec.append(result)

dat = Matrix(GF(37), dat)
vec = vector(GF(37), vec)
fin = dat.solve_right(vec)

password = ""
for i in range(32):
    password += INT_TO_CHAR[int(fin[i])]

conn.sendline(password)
print(conn.recvline())







        