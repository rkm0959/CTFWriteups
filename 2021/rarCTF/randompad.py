from Crypto.Cipher import AES, PKCS1_OAEP, PKCS1_v1_5
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad
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
from sage.modules.free_module_integer import IntegerLattice
from collections import deque 
from mt19937predictor import MT19937Predictor

def inthroot(a, n):
    return a.nth_root(n, truncate_mode=True)[0]

def keygen(): # normal rsa key generation
    primes = []
    e = 3
    for _ in range(2):
        while True:
            p = getPrime(1024)
            if (p - 1) % 3:
                break
        primes.append(p)
    return e, primes[0] * primes[1]

def pad(m, n, pri = False): # pkcs#1 v1.5
    ms = long_to_bytes(m)
    ns = long_to_bytes(n)
    if len(ms) >= len(ns) - 11:
        return -1
    padlength = len(ns) - len(ms) - 3
    if pri:
        print(padlength)
    ps = long_to_bytes(getrandbits(padlength * 8)).rjust(padlength, b"\x00")
    return int.from_bytes(b"\x00\x02" + ps + b"\x00" + ms, "big")

def encrypt(m, e, n, pri = False): # standard rsa
    res = pad(m, n, pri)
    assert res != -1
    return pow(res, e, n)

flag = open("flag.txt", "rb").read()

e, n = keygen()

rng_predict = MT19937Predictor()

m = bytes_to_long(b"\x01" + b"\x00" * 220)

for i in range(624 // 8):
    ret = encrypt(m, 3, n)
    # ret = padded^3 = ("\x00\x02" + pads + "\x00" + "\x01" + "\x00" * 220)^3
    extra = inverse(256 ** (220 * 3), n)
    ret = (ret * extra) % n
    # ret = (\x00\x02 + pads + "\x00\x01")^3
    assert long_to_bytes(ret)[-2:] == b"\x00\x01"
    ans = int(inthroot(Integer(ret), 3)) >> 16
    # print(long_to_bytes(ans))
    ans = ans & ((1 << 256) - 1)
    # print(long_to_bytes(ans))
    rng_predict.setrandbits(ans, 256)

# if we know flag length = 50 -> in reality, need bruteforce - simple enough, so skipped
ret = encrypt(bytes_to_long(flag), 3, n, True)
pads = rng_predict.getrandbits(int(203 * 8))
added = b"\x00\x02" + long_to_bytes(pads) + b"\x00" + b"\x00" * 50
added = bytes_to_long(added)
POL = PolynomialRing(Zmod(n), 'x')
x = POL.gen()
f = (added + x) ** 3 - ret
flag = f.small_roots(X = (1 << 400), beta = 1, epsilon = 0.05)[0]
print(long_to_bytes(flag))