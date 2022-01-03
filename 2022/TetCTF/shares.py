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

ALLOWED_CHARS = string.ascii_lowercase + string.digits + "_"
P = len(ALLOWED_CHARS)
INT_TO_CHAR = {}
CHAR_TO_INT = {}
for _i, _c in enumerate(ALLOWED_CHARS):
    INT_TO_CHAR[_i] = _c
    CHAR_TO_INT[_c] = _i

'''
password (16) || random (16)

-> 16 linear combinations
-> if the random part is linearly dependent -> info on password
-> combine
'''

conn = remote("139.162.61.222", 13371)

dat = []
vec = []

for _ in tqdm(range(2021)):
    conn.sendline("a")
    ret = eval(conn.recvline())
    
    mat = []
    password_part = []
    random_part = []
    res_part = []

    for i in range(16):
        password_vec = [CHAR_TO_INT[ret[i][x]] for x in range(16)]
        random_vec = [CHAR_TO_INT[ret[i][x]] for x in range(16, 32)]
        res = CHAR_TO_INT[ret[i][32]]
        password_part.append(password_vec)
        random_part.append(random_vec)
        res_part.append(res)
    
    password_part = Matrix(GF(37), password_part)
    random_part = Matrix(GF(37), random_part).transpose()

    ker = random_part.right_kernel().basis()
    for i in range(len(ker)):
        ker_vec = ker[i]
        password_vec = [0] * 16
        password_result = 0
        
        for k in range(16):
            for j in range(16):    
                password_vec[j] += password_part[k, j] * ker_vec[k]
            password_result += res_part[k] * ker_vec[k]
        
        dat.append(password_vec)
        vec.append(password_result)
    

dat = Matrix(GF(37), dat)
vec = vector(GF(37), vec)
fin = dat.solve_right(vec)

password = ""
for i in range(16):
    password += INT_TO_CHAR[int(fin[i])]

conn.sendline(password)
print(conn.recvline())







        


