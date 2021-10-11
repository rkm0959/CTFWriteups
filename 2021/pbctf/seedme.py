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
	M = IntegerLattice(mat, lll_reduce=True).reduced_basis
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
			break
    
    	# recover x
	fin = None

	if DET != 0:
		mat = mat.transpose()
		fin = mat.solve_right(result)
	
	## recover your result
	return result, applied_weights, fin

# conn = remote('seedme.chal.perfect.blue', 1337)
# conn.interactive()

def getv(seed):
	seed = (seed * 0x5DEECE66D + 0xB) & ((1 << 48) - 1)
	return seed, (seed >> 24) / (1 << 24)

curm = [1]
curb = [0]

M = Matrix(ZZ, 17, 17)
lb = [0] * 17
ub = [0] * 17

for i in range(16 * 2048):
	curm.append((0x5DEECE66D * curm[i]) % (1 << 48))
	curb.append((0x5DEECE66D * curb[i] + 0xB) % (1 << 48))

for i in range(0, 16):
	m, b = curm[2048 * i + 2048], curb[2048 * i + 2048]
	M[0, i] = m
	M[i + 1, i] = 1 << 48
	lb[i] = int(0.9803 * (1 << 48)) - b 
	ub[i] = int((1 << 48)) - 1 - b

# post-fix manually
lb[0] = int(0.985 * (1 << 48)) - curb[2048]
ub[15] = int(0.995 * (1 << 48)) - curb[2048 * 16]

M[0, 16] = 1
lb[16] = 0
ub[16] = 1 << 48

result, applied_weights, fin = solve(M, lb, ub)

res = (int(fin[0]) + (1 << 48)) % (1 << 48)

init_seed = 0x5DEECE66D ^ res 

print(init_seed)

seeds = init_seed
seeds = (seeds ^ 0x5DEECE66D) & ((1 << 48) - 1)

curm = [1]
curb = [0]

for i in range(16 * 2048):
	curm.append((0x5DEECE66D * curm[i]) % (1 << 48))
	curb.append((0x5DEECE66D * curb[i] + 0xB) % (1 << 48))

for i in range(0, 16):
	m, b = curm[2048 * i + 2048], curb[2048 * i + 2048]
	res = (seeds * m + b) % (1 << 48)
	print(res / (1 << 48) >= 0.7331 * 1.337)