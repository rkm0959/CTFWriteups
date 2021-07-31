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

r = remote('01.cr.yp.toc.tf', 29010)


def read_lines(num = 5):
    for _ in range(num):
        r.recvline()

def getpoint():
    s = r.recvline().split()[-1]
    s = s.split(b',')
    x = int(s[0][1:])
    y = int(s[1][:-1])
    return x, y

p = 170141183460469231731687303715884111953
q = 2 * p + 1

assert isPrime(p) and isPrime(q)

read_lines()

read_lines()
r.sendline("A")
print(r.recvline())
r.sendline(str(p*q) + "," + str(p*q))

read_lines()
r.sendline("C")
print(r.recvline())
r.sendline(str(p))

read_lines()
r.sendline("S")
r.recvline()
r.recvline()
r.recvline()

x1, y1 = getpoint()
x2, y2 = getpoint()
x3, y3 = getpoint()
x4, y4 = getpoint()

print(r.recvline())

c1 = (GF(p)(x2) / GF(p)(y2)) / (GF(p)(x1) / GF(p)(y1))
c2 = (GF(q)(x4) / GF(q)(y4)) / (GF(q)(x3) / GF(q)(y3))

c1 = int(c1)
c2 = int(c2)

r.sendline(str(c1) + "," + str(c2))

print(r.recvline())
print(r.recvline())
print(r.recvline())