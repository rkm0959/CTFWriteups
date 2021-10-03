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
from sage.modules.free_module_integer import IntegerLattice
from Crypto.Cipher import AES, ARC4, DES
from Crypto.PublicKey import DSA
from Crypto.Signature import DSS
from Crypto.Hash import SHA256
from Crypto.Math.Primality import test_probable_prime


r = remote('34.146.212.53', 61234)

s = r.recvline()
q = int(s.split()[-1])

p = q ** 8
while p.bit_length() < 2048:
    p = 2 * p 

h = 1 + 16 * q ** 7
r.sendline(str(p))
r.sendline(str(h))

g = int(r.recvline().split()[-1])
y = int(r.recvline().split()[-1])

print(2 <= g < p)
print(pow(g, q, p) == 1)

gs = ((g - 1) // (q ** 7)) % q
ys = ((y - 1) // (q ** 7)) % q

x = (ys * inverse(gs, q)) % q 

res = bytes_to_long(hashlib.sha256(b'flag').digest())

k = 1
rr = g % q
ss = (res + x * rr) % q

print(r.recvline())


res = long_to_bytes(rr, 32) + long_to_bytes(ss, 32)

r.sendline(b64encode(res))

print(r.recvline())
print(r.recvline())