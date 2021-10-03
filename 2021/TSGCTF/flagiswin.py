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

	print(result[num_ineq - 1] - target[num_ineq-1])

	for i in range(num_ineq):
		if (lb[i] <= result[i] <= ub[i]) == False:
			print("Fail : inequality does not hold after solving")
			break
    
    	# recover x
	fin = None

	if DET != 0:
		mat = mat.transpose()
		fin = mat.solve_right(result)
	
	## recover your result
	return result, applied_weights, fin




r = remote('34.146.212.53', 35719)

p = (1 << 256) - (1 << 32) - (1 << 9) - (1 << 8) - (1 << 7) - (1 << 6) - (1 << 4) - 1

E = EllipticCurve(GF(p), [0, 7])
Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8

G = E(Gx, Gy)
n = E.order()
print(isPrime(n))

h1 = bytes_to_long(hashlib.sha256(b'Baba').digest())
h2 = bytes_to_long(hashlib.sha256(b'Flag').digest())

X = []
S = []
for _ in range(4):
	for i in range(3):
		r.recvline()
	r.sendline(b"1")
	r.recvline()
	X.append(int(r.recvline().split()[-1]))
	S.append(int(r.recvline().split()[-1]))

NUM_EQ = 4
test = False

D = 26

supp = []
if test:
	d = rand.randint(1, n)
	for i in range(NUM_EQ):
		cc = []
		k = 0
		for j in range(2 * D):
			if j % 2 == 0:
				u = rand.randint(0, 9)
				supp.append(u)
				k += u * (16 ** j)
				cc.append(u)
			else:
				k += 3 * (16 ** j)
		x = int((k * G).xy()[0])
		s = ((h1 + x * d) * inverse(k, n)) % n 
		X[i] = x
		S[i] = s 
	supp.append(d)

print(supp)
M = Matrix(ZZ, 2 * D + 1, 2 * D + 1)
lb = [0] * (2 * D + 1)
ub = [0] * (2 * D + 1) 

base_k = 0
for i in range(D):
	base_k += 3 * 16 * (256 ** i)

for i in range(2 * D):
	M[i, i] = 1
	lb[i] = 0
	ub[i] = 16 

for i in range(D):
	M[i, 2 * D] = int(((256 ** i) * (S[0] * X[1])) % n)
	M[i + D, 2 * D] = int(n - ((256 ** i) * (S[1] * X[0])) % n) 
	M[2 * D, 2 * D] = int(n)
	lb[2 * D] = int((h1 * (X[1] - X[0]) - base_k * S[0] * X[1] + base_k * S[1] * X[0]) % n)
	ub[2 * D] = int((h1 * (X[1] - X[0]) - base_k * S[0] * X[1] + base_k * S[1] * X[0]) % n)


result, applied_weights, fin = solve(M, lb, ub)
print(fin)

k0 = base_k 
for i in range(26):
	k0 += (256 ** i) * int(fin[i]) 

d = (inverse(X[0], n) * (k0 * S[0] - h1)) % n 

x = Gx 
s = (h2 + x * d) % n 

for i in range(3):
	print(r.recvline())
r.sendline(b"2")
r.sendline(b"Flag")
r.sendline(str(x))
r.sendline(str(s))
print(r.recvline())
print(r.recvline())
print(r.recvline())

