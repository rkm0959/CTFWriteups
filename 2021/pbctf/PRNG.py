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
from Crypto.Cipher import AES, ARC4, DES

def urand(b):
	return int.from_bytes(os.urandom(b), byteorder='big')

class PRNGFinisher:
	def __init__(self, X, Y, Z):
		self.m1 = 2 ** 32 - 107
		self.m2 = 2 ** 32 - 5
		self.m3 = 2 ** 32 - 209
		self.M = 2 ** 64 - 59

		rnd = rand.Random(b'rbtree')

		self.a1 = [rnd.getrandbits(20) for _ in range(3)]
		self.a2 = [rnd.getrandbits(20) for _ in range(3)]
		self.a3 = [rnd.getrandbits(20) for _ in range(3)]

		self.x = X
		self.y = Y
		self.z = Z

	def out(self):
		o = (2 * self.m1 * self.x[0] - self.m3 * self.y[0] - self.m2 * self.z[0]) % self.M

		self.x = self.x[1:] + [sum(x * y for x, y in zip(self.x, self.a1)) % self.m1]
		self.y = self.y[1:] + [sum(x * y for x, y in zip(self.y, self.a2)) % self.m2]
		self.z = self.z[1:] + [sum(x * y for x, y in zip(self.z, self.a3)) % self.m3]

		return o.to_bytes(8, byteorder='big')

class PRNG:
	def __init__(self):
		self.m1 = 2 ** 32 - 107
		self.m2 = 2 ** 32 - 5
		self.m3 = 2 ** 32 - 209
		self.M = 2 ** 64 - 59

		rnd = rand.Random(b'rbtree')

		self.a1 = [rnd.getrandbits(20) for _ in range(3)]
		self.a2 = [rnd.getrandbits(20) for _ in range(3)]
		self.a3 = [rnd.getrandbits(20) for _ in range(3)]

		self.x = [urand(4) for _ in range(3)]
		self.y = [urand(4) for _ in range(3)]
		self.z = [urand(4) for _ in range(3)]

	def out(self):
		ret = b''
		xs = []
		ys = []
		zs = []
		for _ in range(12):
			xs.append(self.x[0])
			ys.append(self.y[0])
			zs.append(self.z[0])
			o = (2 * self.m1 * self.x[0] - self.m3 * self.y[0] - self.m2 * self.z[0]) % self.M
			self.x = self.x[1:] + [sum(x * y for x, y in zip(self.x, self.a1)) % self.m1]
			self.y = self.y[1:] + [sum(x * y for x, y in zip(self.y, self.a2)) % self.m2]
			self.z = self.z[1:] + [sum(x * y for x, y in zip(self.z, self.a3)) % self.m3]
			ret += o.to_bytes(8, byteorder='big')
		return ret, xs, ys, zs


# Directly taken from rbtree's LLL repository
# From https://oddcoder.com/LOL-34c3/, https://hackmd.io/@hakatashi/B1OM7HFVI
def Babai_CVP(mat, target):
	M = mat.BKZ(block_size = 35)
	G = M.gram_schmidt()[0]
	diff = target
	for i in reversed(range(G.nrows())):
		diff -=  M[i] * ((diff * G[i]) / (G[i] * G[i])).round()
	return target - diff

def solve(mat, lb, ub, weight = None):
	num_var  = mat.nrows()
	num_ineq = mat.ncols()

	max_element = 0 
	for i in range(num_var):
		for j in range(num_ineq):
			max_element = max(max_element, abs(mat[i, j]))

	if weight == None:
		weight = num_ineq * max_element

	# sanity checker
	if len(lb) != num_ineq:
		print("Fail: len(lb) != num_ineq")
		return

	if len(ub) != num_ineq:
		print("Fail: len(ub) != num_ineq")
		return

	for i in range(num_ineq):
		if lb[i] > ub[i]:
			print("Fail: lb[i] > ub[i] at index", i)
			return

	# heuristic for number of solutions
	DET = 0

	if num_var == num_ineq:
		DET = abs(mat.det())
		num_sol = 1
		for i in range(num_ineq):
			num_sol *= (ub[i] - lb[i])
		if DET == 0:
			print("Zero Determinant")
		else:
			num_sol //= DET
			# + 1 added in for the sake of not making it zero...
			print("Expected Number of Solutions : ", num_sol + 1)

	# scaling process begins
	max_diff = max([ub[i] - lb[i] for i in range(num_ineq)])
	applied_weights = []

	for i in range(num_ineq):
		ineq_weight = weight if lb[i] == ub[i] else max_diff // (ub[i] - lb[i])
		applied_weights.append(ineq_weight)
		for j in range(num_var):
			mat[j, i] *= ineq_weight
		lb[i] *= ineq_weight
		ub[i] *= ineq_weight

	# Solve CVP
	target = vector([(lb[i] + ub[i]) // 2 for i in range(num_ineq)])
	result = Babai_CVP(mat, target)

	for i in range(num_ineq):
		if (lb[i] <= result[i] <= ub[i]) == False:
			print("Fail : inequality does not hold after solving")
	
	# recover x
	fin = None

	if DET != 0:
		mat = mat.transpose()
		fin = mat.solve_right(result)
	
	## recover your result
	return result, applied_weights, fin

def get_idx(name, v):
	if name == 'x':
		return v - 1
	if name == 'y':
		return v + 11
	if name == 'z':
		return v + 23

test = False

if test:
	prng = PRNG()
	hint, ERRX, ERRZ, XS, YS, ZS = prng.out()
	print("XS", XS)
	print("YS", YS)
	print("ZS", ZS)

	vec_sol = []
	for i in range(12):
		vec_sol.append(XS[i])
	for i in range(12):
		vec_sol.append(YS[i])
	for i in range(12):
		vec_sol.append(ZS[i])
else:
	prng = PRNG()
	hint = '67f19d3da8af1480f39ac04f7e9134b2dc4ad094475b696224389c9ef29b8a2aff8933bd3fefa6e0d03827ab2816ba0fd9c0e2d73e01aa6f184acd9c58122616f9621fb8313a62efb27fb3d3aa385b89435630d0704f0dceec00fef703d54fca'
	output = '153ed807c00d585860b843a03871b11f60baf11fe72d2619283ec5b4d931435ac378e21abe67c47f7923fcde101f4f0c65b5ee48950820f9b26e33acf57868d5f0cbc2377a39a81918f8c20f61c71047c8e82b1c965fa01b58ad0569ce7521c7'
	hint = bytes.fromhex(hint)
	output = bytes.fromhex(output)

print(len(hint))
M = Matrix(ZZ, 75, 75)

cnt = 0
tot_base = 36

lb = []
ub = []

# x
for i in range(9):
	M[get_idx('x', i + 4), cnt] = 1
	M[get_idx('x', i + 1), cnt] = -prng.a1[0]
	M[get_idx('x', i + 2), cnt] = -prng.a1[1]
	M[get_idx('x', i + 3), cnt] = -prng.a1[2]
	M[tot_base, cnt] = prng.m1
	cnt += 1
	tot_base += 1
	lb.append(0)
	ub.append(0)

# y 
for i in range(9):
	M[get_idx('y', i + 4), cnt] = 1
	M[get_idx('y', i + 1), cnt] = -prng.a2[0]
	M[get_idx('y', i + 2), cnt] = -prng.a2[1]
	M[get_idx('y', i + 3), cnt] = -prng.a2[2]
	M[tot_base, cnt] = prng.m2
	cnt += 1
	tot_base += 1
	lb.append(0)
	ub.append(0)

# z
for i in range(9):
	M[get_idx('z', i + 4), cnt] = 1
	M[get_idx('z', i + 1), cnt] = -prng.a3[0]
	M[get_idx('z', i + 2), cnt] = -prng.a3[1]
	M[get_idx('z', i + 3), cnt] = -prng.a3[2]
	M[tot_base, cnt] = prng.m3
	cnt += 1
	tot_base += 1
	lb.append(0)
	ub.append(0)

for i in range(12):
	M[get_idx('x', i + 1), cnt] = 1
	cnt += 1
	lb.append(0)
	ub.append(1 << 32)

for i in range(12):
	M[get_idx('y', i + 1), cnt] = 1
	cnt += 1
	lb.append(0)
	ub.append(1 << 32)

for i in range(12):
	M[get_idx('z', i + 1), cnt] = 1
	cnt += 1
	lb.append(0)
	ub.append(1 << 32)

for i in range(12):
	M[get_idx('x', i + 1), cnt] = (2 * prng.m1)
	M[get_idx('y', i + 1), cnt] = -prng.m3
	M[get_idx('z', i + 1), cnt] = -prng.m2
	M[tot_base, cnt] = prng.M
	cnt += 1
	tot_base += 1
	val = bytes_to_long(hint[8 * i : 8 * i + 8])
	lb.append(val)
	ub.append(val)

print(cnt)
print(tot_base)

result, applied_weights, fin = solve(M, lb, ub)

INIT_X = [int(fin[get_idx('x', i + 1)]) for i in range(3)]
INIT_Y = [int(fin[get_idx('y', i + 1)]) for i in range(3)]
INIT_Z = [int(fin[get_idx('z', i + 1)]) for i in range(3)]

print(fin)
print(INIT_X)
print(INIT_Y)
print(INIT_Z)

actual_prng = PRNGFinisher(INIT_X, INIT_Y, INIT_Z)

hint_check = b''
for i in range(12):
	hint_check += actual_prng.out()

sdaf = [hint_check[i] == hint[i] for i in range(96)]
print(sdaf)

if test == False:
	flag = b''
	for i in range(len(output) // 8):
		res = bytes_to_long(actual_prng.out())
		res = res ^ bytes_to_long(output[8 * i : 8 * i + 8])
		flag += long_to_bytes(res)
	print(flag)