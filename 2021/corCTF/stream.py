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


def bsum(state, taps, l):
	ret = 0
	for i in taps:
		ret ^= (state >> (l - i))
	return ret & 1

class Gen:
	def __init__(self, key, slength):
		self.state = key
		self.slength = slength
		self.TAPS = [2, 4, 5, 7, 10, 12, 13, 17, 19, 24, 25, 27, 30, 32, 
		33, 34, 35, 45, 47, 49, 50, 52, 54, 56, 57, 58, 59, 60, 61, 64]

	def clock(self):
		out = bsum(self.state, self.TAPS, self.slength)
		self.state = (out << (self.slength - 1)) + (self.state >> 1)
		return out

def gf256_multiply(a, b):
	p = 0
	for _ in range(8):
		if b % 2:
			p ^= a
		check = a & 0x80
		a <<= 1
		if check == 0x80:
			a ^= 0x1b
		b >>= 1
	return p % 256

def gf256_inverse(x):
	ret = 1
	d = 254
	while d > 0:
		if d % 2 == 1:
			ret = gf256_multiply(ret, x)
		d //= 2
		x = gf256_multiply(x, x)
	return ret

lookup = [0] * 256
for i in range(1, 256):
	lookup[i] = gf256_inverse(i)
	assert gf256_multiply(lookup[i], i) == 1

val = []
for i in range(256):
	val.append([0] * 256)
for i in range(256):
	for j in range(256):
		val[i][j] = gf256_multiply(i, j)

def encrypt(fn, outf, key):
	cipher = Gen(key, 64)
	pt = b''
	with open(fn, 'rb') as f:
		pt = f.read()
	ct = b''
	for byte in pt:
		genbyte = 0
		for i in range(8):
			genbyte = genbyte << 1
			genbyte += cipher.clock()
		ct += long_to_bytes(gf256_multiply(genbyte, byte))
	with open(outf, 'wb') as f:
		f.write(ct)

def decrypt(fn, key):
	global lookup, val
	cipher = Gen(key, 64)
	ct = b''
	with open(fn, 'rb') as f:
		ct = f.read()
	pt = b''
	for byte in ct:
		genbyte = 0
		for i in range(8):
			genbyte = genbyte << 1
			genbyte += cipher.clock()
		pt += long_to_bytes(val[lookup[genbyte]][byte])
	l = len(pt)
	cnt = 0
	for byte in pt:
		if byte < 128:
			cnt += 1
	print(key, cnt / l)
	if cnt / l >= 0.6 or b"ctf{" in pt: # high ascii? ctf{ ?
		print(pt)

TAPS = [2, 4, 5, 7, 10, 12, 13, 17, 19, 24, 25, 27, 30, 32, 
		33, 34, 35, 45, 47, 49, 50, 52, 54, 56, 57, 58, 59, 60, 61, 64]

R = PolynomialRing(GF(2), 'x')
x = R.gen()

f = (x ** 64)

for t in TAPS:
	f += (x ** (64 - t))

poly = f


M = [poly.list()[1:]]
for i in range(63):
	M.append([1 if j == i else 0 for j in range(64)])

ex = 255

M = Matrix(GF(2), M)
A = M ** ex 
g = (x ** ex) - 1
g = g % f 
print(f.gcd(g))


E, S = A.eigenspaces_right(format='galois')[0]
assert E == 1

basis = S.basis()

for i in tqdm(range(1, 1 << len(basis))):
	vec = vector(GF(2), [0] * 64)
	for j in range(len(basis)):
		if ((i >> j) & 1) == 1:
			vec += basis[j]
	assert A * vec == vec
	tt = list(vec)[::-1]
	for j in range(64):
		tt[j] = int(tt[j])
	key = int(''.join([str(d) for d in tt]), 2)
	decrypt("ct", key)
