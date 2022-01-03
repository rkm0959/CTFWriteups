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

p = 50824208494214622675210983238467313009841434758617398532295301998201478298245257311594403096942992643947506323356996857413985105233960391416730079425326309
C = 803799120267736039902689148809657862377959420031713529926996228010552678684828445053154435325462622566051992510975853540073683867248578880146673607388918

INFINITY = "INF"

def op(x1, x2):
    if x2 == INFINITY:
        x1, x2 = x2, x1
    if x1 == INFINITY:
        if x2 == INFINITY:
            return (-2 * C) % p
        elif x2 == 0:
            return INFINITY
        else:
            return -(1 + 2 * C * x2) * pow(x2, -1, p) % p
    if x1 * x2 == 1:
        return INFINITY
    return (x1 + x2 + 2 * C * x1 * x2) * pow(1 - x1 * x2, -1, p) % p

def repeated_op(x, k):
    s = 0
    while k > 0:
        if k & 1:
            s = op(s, x)
        k = k >> 1
        x = op(x, x)
    return s

'''
(x1 + x2 + 2 * C * x1 * x2) / (1 - x1 * x2)

homomorphism of the form (u1x + v1) / (u2x + v2)

(u1x1 + v1)(u1x2 + v1)
(u2x1 + v2)(u2x2 + v2)

u1 (x1 + x2 + 2Cx1x2) + v1 (1 - x1x2)
u2 (x1 + x2 + 2Cx1x2) + v2 (1 - x1x2)

(u1x1 + v1)(u1x2 + v1) = u1(x1 + x2 + 2Cx1x2) + v1(1 - x1x2)

u1^2 = u1 * 2C - v1
u1v1 = u1
v1^2 = v1

-> v1 = 1
-> u1^2 = 2Cu1 - 1
-> u1^2 - 2Cu1 + 1

'''



x = C - GF(p)(C * C - 1).nth_root(2)
x = GF(p)(x)
y = GF(p)(x) ** (-1)

def f(t):
    u = GF(p)(x * t + 1)
    v = GF(p)(y * t + 1)
    return int(u * (v ** -1))



conn = remote("139.162.61.222", 13374)
a = int(conn.recvline())
b = int(conn.recvline())
c = int(conn.recvline())

conn.sendline(str(f(a)))
conn.sendline(str(f(b)))
conn.sendline(str(f(c)))

print(conn.recvline())

