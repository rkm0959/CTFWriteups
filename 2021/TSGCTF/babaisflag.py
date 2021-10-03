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


r = remote('34.146.212.53', 65434)

p = (1 << 256) - (1 << 32) - (1 << 9) - (1 << 8) - (1 << 7) - (1 << 6) - (1 << 4) - 1

E = EllipticCurve(GF(p), [0, 7])
Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8

G = E(Gx, Gy)
n = E.order()
print(isPrime(n))

h1 = bytes_to_long(hashlib.sha256(b'Baba').digest())
h2 = bytes_to_long(hashlib.sha256(b'Flag').digest())

for i in range(3):
	r.recvline()
r.sendline(b"1")
r.recvline()
X1 = int(r.recvline().split()[-1])
S1 = int(r.recvline().split()[-1])

print(X1)
print(S1)


target1 = S1 * E.lift_x(GF(p)(X1))

target2 = target1 + (h2 - h1) * G
for i in range(3):
	r.recvline()
r.sendline(b"2")
r.sendline("Flag")
r.sendline(str(int(target2.xy()[0])))
r.sendline(b"1")
print(r.recvline())
print(r.recvline())