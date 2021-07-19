from Crypto.Cipher import AES, PKCS1_OAEP, PKCS1_v1_5
from Crypto.PublicKey import RSA
from Crypto.Util.number import inverse, long_to_bytes, bytes_to_long, isPrime, getPrime, GCD
from tqdm import tqdm
from pwn import *
from sage.all import *
import itertools, sys, json, hashlib, os, math, time, base64, binascii, string, re, struct, datetime, subprocess
import numpy as np
import random as rand
import multiprocessing as mp
from base64 import b64encode, b64decode
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

############################ Basic Initializations #############################
REMOTE = True
cur_idx = 0

r = remote('pythia.2021.ctfcompetition.com', 1337)
passwords = [bytes(''.join(rand.choice(string.ascii_lowercase) for _ in range(3)), 'UTF-8') for _ in range(3)]

pass_to_key = {}
key_to_pass = {}
passes = []
keys = []
ans = [b'', b'', b'']

for c1 in string.ascii_lowercase:
    for c2 in string.ascii_lowercase:
        for c3 in string.ascii_lowercase:
            val = bytes(''.join([c1, c2, c3]), 'UTF-8')
            kdf = Scrypt(salt=b'', length=16, n=2**4, r=8, p=1, backend=default_backend())
            key = kdf.derive(val)
            pass_to_key[val] = key
            key_to_pass[key] = val
            passes.append(val)
            keys.append(key)

############################# Query Functions ###################################

def menu(whi):
    print("INMENU")
    for _ in range(5):
        print(r.recvline())
    r.sendline(str(whi))

def select_key(idx):
    global r, cur_idx
    if REMOTE:
        menu(1)
        print("SELECTKEY", idx)
        print(r.recvline())
        r.sendline(str(idx))
        print(r.recvline())
        r.recvline()
    else:
        cur_idx = idx

def check(res):
    global r, passwords
    if REMOTE:
        menu(2)
        print(r.recvline())
        r.sendline(res)
        for _ in range(4):
            print(r.recvline())
    else:
        print(passwords[0] + passwords[1] + passwords[2])
        print(res)

def query(ctxt):
    global r, passwords
    if REMOTE:
        menu(3)
        print("Query")
        print(r.recvline())
        r.sendline(ctxt)
        print(r.recvline())
        s = r.recvline()
        print("s:", s)
        if b"ERROR" in s:
            return 0
        print(r.recvline())
        r.recvline()
        return 1
    else:
        nonce, ciphertext = ctxt.split(b",")
        nonce = b64decode(nonce)
        ciphertext = b64decode(ciphertext)
        kdf = Scrypt(salt=b'', length=16, n=2**4, r=8, p=1, backend=default_backend())
        key = kdf.derive(passwords[cur_idx])
        try:
            cipher = AESGCM(key)
            plaintext = cipher.decrypt(nonce, ciphertext, associated_data=None)
            return 1
        except:
            return 0

####################### ATTACK #########################

# define appropriate GF(2^128) structure
POL = PolynomialRing(GF(2), 'a')
a = POL.gen()
F = GF(2 ** 128, name = 'a', modulus = a ** 128 + a ** 7 + a ** 2 + a + 1)
R = PolynomialRing(F, 'X')
X = R.gen()

def aes_enc(p, k):
    cipher = AES.new(k, AES.MODE_ECB)
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

# thanks, barkingdog!
def lagrange(LEFT, RIGHT):
    points = []
    points.append((a+1,1))
    points.append((a**26+a**2+a,a**3+a))
    L = bytes.fromhex(hex((RIGHT-LEFT)*128)[2:].zfill(32))
    target = bytes_to_finite(L)
    f2 = 1
    for key in keys[LEFT:RIGHT]:
        x = aes_enc(bytes(16),key)
        y = aes_enc(bytes(15)+bytes([1]),key)
        points.append((bytes_to_finite(x), bytes_to_finite(y)))
        f2 = f2 * (X - (bytes_to_finite(x)))
    f1 = R.lagrange_polynomial(points)
    deg1val = f2.coefficients()[1]
    cur = f1.coefficients()[1]
    diff = cur - target
    factor = deg1val ** (-1) * diff
    f = f1 - factor * f2
    return f

ON = True
CACHE = {}

def CHECKER(LE, RI):

    if (LE, RI) in CACHE.keys():
        asker = CACHE[(LE, RI)]
        fin = query(asker)
        if fin == 1:
            return True
        return False

    # thanks, barkingdog!
    f = lagrange(LE, RI)
    t = f.coefficients(sparse = False)
    t.reverse() 
    C = b''
    for i in range(0, len(t)):
        if i == len(t)-2: continue
        C += long_to_bytes(finite_to_int(t[i]), blocksize = 16)

    nonce = b64encode(b"\x00" * 12)
    ctxt = b64encode(C)

    asker = nonce + b"," + ctxt
    fin = query(asker)
    CACHE[(LE, RI)] = asker 
    
    if fin == 1:
        return True
    
    return False

for _ in range(3):
    r.recvline()

for i in range(3):
    select_key(i)
    LE, RI = None, None
    for j in tqdm(range(40)):
        LV = (len(keys) * j) // 40
        RV = (len(keys) * (j + 1)) // 40
        if CHECKER(LV, RV):
            LE, RI = LV, RV
            break
    print(LE, RI)
    while LE + 1 < RI:
        print(LE, RI)
        MM = (LE + RI) // 2
        if CHECKER(LE, MM):
            RI = MM
        else:
            LE = MM
    loc = (LE + RI) // 2
    ans[i] = key_to_pass[keys[loc]]
    print(ans[i])

check(ans[0] + ans[1] + ans[2])