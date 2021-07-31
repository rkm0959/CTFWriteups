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
from sage.modules.free_module_integer import IntegerLattice
from ecdsa import ecdsa

def nextPrime(n):
    while True:
        n += (n % 2) + 1
        if isPrime(n):
            return n

# 65859
# 67395

'''
for i in range(240, 300):
    a = nextPrime(i)
    b = nextPrime(a)
    c = nextPrime(i >> 2)
    print(i, i * a + c, i * b + c)
'''


f = open("g.enc", "rb")
G = bytes_to_long(f.read())
f.close()

f = open("h.enc", "rb")
H = bytes_to_long(f.read())
f.close()

g = []
h = []

while G > 0:
    g.append(G % 5)
    G //= 5
g = g[::-1]

while H > 0:
    h.append(H % 5)
    H //= 5
h = h[::-1]

print(len(g))
print(len(h))

L = 256
a = nextPrime(L)
b = nextPrime(a)
c = nextPrime(L >> 2)

for i in range(len(g) - c - 1, -1, -1):
    g[i] -= g[i + c]

for i in range(len(h) - c - 1, -1, -1):
    h[i] -= h[i + c]

g = g[c:]
h = h[c:]

con = g[:256]

for i in range(len(con)-2, -1, -1):
    con[i] -= con[i+1]

res = 0
for i in range(len(con)):
    res = 2 * res + con[i]

print(long_to_bytes(res))
