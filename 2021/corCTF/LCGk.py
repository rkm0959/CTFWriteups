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


### r = (k * G).x

# ks = H(m) + dr

# x_1 s_1 = H(m_1) + d r_1
# (ax_1 + b) s_2 = H(m_2) + d r_2
# (a(ax_1+b)+b) s_3 = H(m_3) + dr_3


fun = remote('crypto.be.ax', 6002)

p = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF 
a = p - 3
b = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B

Gx = 0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296 
Gy = 0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5

E = EllipticCurve(GF(p), [a, b])
G = E(Gx, Gy)

N = E.order()

PR = PolynomialRing(GF(N), ['X', 'A', 'B', 'D']) 
X, A, B, D = PR.gens()

class RNG:
	def __init__(self, seed, A, b, p):
		self.seed = seed
		self.A = A
		self.b = b
		self.p = p

	def gen(self):
		out = self.seed
		while True:
			out = (self.A*out + self.b) % self.p
			yield out

def H(m):
	h = hashlib.sha256()
	h.update(m)
	return bytes_to_long(h.digest())

def sign(m, d):
	k = 1
	r = int((k*G).xy()[0]) % N
	s = ((H(m) + d*r)*inverse(k, N)) % N
	return r, s


f = []
g = X


print(fun.recvline())
print(fun.recvline())
print(fun.recvline())

for i in range(1, 5):
    fun.sendline("00" * i)
    r = int(fun.recvline().split()[-1])
    s = int(fun.recvline().split()[-1])
    f.append(X * s - H(b"\x00" * i) - D * r)
    X = A * X + B

I = Ideal(f).groebner_basis()

print(I)

for pol in I:
    try:
        print(pol.factor())
    except:
        pass

d = (N+int(input())) % N

finr, fins = sign(b'i wish to know the ways of the world', d)

fun.recvline()
fun.sendline(str(finr))
fun.sendline(str(fins))

print(fun.recvline())
print(fun.recvline())