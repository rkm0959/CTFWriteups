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
from Crypto.Hash import SHA3_256, HMAC, BLAKE2s
from Crypto.Cipher import AES, ARC4, DES

def inthroot(a, n):
    return a.nth_root(n, truncate_mode=True)[0]

f = open("transcript.log", "r")
f.readline()
enc_flag = bytes.fromhex(f.readline().strip())

ENC2 = Integer(2) ** 65537
ENC3 = Integer(3) ** 65537

res = []
mod = []

for i in tqdm(range(16384)):
    line1 = f.readline().strip()
    assert line1 == "[cmd] pkey"
    line2 = f.readline().strip()
    assert line2 == "[cmd] send 2"
    enc2 = Integer(int(f.readline().strip()[2:], 16))
    line4 = f.readline().strip()
    assert line4 == "[cmd] send 3"
    enc3 = Integer(int(f.readline().strip()[2:], 16))
    line6 = f.readline().strip()
    assert line6 == "[cmd] backup"
    enc_secret = Integer(int(f.readline().strip()[2:], 16))

    N = GCD(ENC2 - enc2, ENC3 - enc3)
    for j in range(2, 1 << 16):
        while N % j == 0:
            N = N // j
    
    assert 1022 <= int(N).bit_length() <= 1024
    res.append(enc_secret)
    mod.append(N)

while len(res) != 1:
    print(len(res))
    nxtres = []
    nxtmod = []
    for i in tqdm(range(0, len(res), 2)):
        cc = crt(res[i], res[i+1], mod[i], mod[i+1])
        md = mod[i] * mod[i+1] // GCD(mod[i], mod[i+1])
        nxtres.append(cc)
        nxtmod.append(md)
    res = nxtres
    mod = nxtmod

res = res[0]
master_secret = inthroot(Integer(res), 65537)
assert master_secret ** 65537 == res

print(master_secret)
secret = long_to_bytes(int(master_secret), 8)
cipher = AES.new(secret, AES.MODE_CBC, b'\x00' * 16)
print(cipher.decrypt(enc_flag))