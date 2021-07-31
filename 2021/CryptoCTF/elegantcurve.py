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


r = remote('07.cr.yp.toc.tf', 10010)

def read_lines(num):
    for _ in range(num):
        r.recvline()

def getpoint():
    s = r.recvline().split()
    x = int(s[-2][2:-1])
    y = int(s[-1][:-2])
    return x, y

# y^2 = (x+t)^2(x-2t)
# y^2 = x^2 (x-3t)

# -3t must be QR
p = 730750818665451459101842416358141509827966291053
q = 730750818665451459101842416358141509827966291771

pr = [p, q]
ts = [1, 2]



read_lines(8)
r.sendline("S")
r.recvline()
r.sendline(str(p-3) + "," + str(p-2) + "," + str(p))
r.recvline()
r.recvline()
r.sendline(str(q-12) + "," + str(q-16) + "," + str(q))

x1, y1 = getpoint()
x2, y2 = getpoint()
x3, y3 = getpoint()
x4, y4 = getpoint()

print(r.recvline())

# alpha = -1, beta = 2
# alpha = -2, beta = 4
alp_1 = GF(p)(-3).nth_root(2)
alp_2 = GF(q)(-6).nth_root(2)

D1 = GF(p)(y1 + alp_1 * (x1 + 1)) / GF(p)(y1 - alp_1 * (x1 + 1))
D3 = GF(p)(y3 + alp_1 * (x3 + 1)) / GF(p)(y3 - alp_1 * (x3 + 1))

D2 = GF(q)(y2 + alp_2 * (x2 + 2)) / GF(q)(y2 - alp_2 * (x2 + 2))
D4 = GF(q)(y4 + alp_2 * (x4 + 2)) / GF(q)(y4 - alp_2 * (x4 + 2))


rr = int(D3.log(D1))

print("Done 1")

ss = int(D4.log(D2))

print("Done 2")

r.sendline(str(rr) + "," + str(ss))

print(r.recvline())
print(r.recvline())
print(r.recvline())
print(r.recvline())