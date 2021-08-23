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

r = remote('crypto.be.ax', 6001)


def readlines(num):
    for _ in range(num):
        s = r.recvline()

def getSig(msg):
    readlines(5)
    r.sendline("1")
    msg = hex(msg)[2:]
    r.sendline(msg)
    sig = int(r.recvline().split()[-1], 16)
    r.sendline(b"00")
    r.recvline()
    return sig

def guesspriv(coef):
    readlines(5)
    r.sendline("3")
    payload = ""
    for i in range(32):
        payload += str(coef[i])
        if i != 31:
            payload += " "
    r.sendline(payload)
    for _ in range(3):
        print(r.recvline())

readlines(4)
p = int(r.recvline().split()[-1])
r.recvline()

print(p)
POL = PolynomialRing(GF(p), 'x')
x = POL.gen()


pts = []
for i in tqdm(range(2, 140)):
    sig = getSig(i)
    pts.append((GF(p)(i), GF(p)(sig)))

f = POL.lagrange_polynomial(pts)

facs = list(f.factor())

print("factored!")

g = f.coefficients(sparse=False)[-1]

cc = (x ** 4) - g

idx = rand.randint(0, 3)
val = cc.roots()[idx][0]

print("4th root found!")

h = 1

for (pol, ex) in facs:
    assert ex == 4 
    h *= pol

hh = h.coefficients(sparse = False)

for i in range(32):
    hh[i] = (hh[i] * val) % p

pol = 0

for i in range(32):
    pol += GF(p)(hh[i]) * (x ** i)

assert (pol ** 4) == f

guesspriv(hh) 




    