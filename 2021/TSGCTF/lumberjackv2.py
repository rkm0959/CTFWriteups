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

def ceil(n, m): # returns ceil(n/m)
	return (n + m - 1) // m

def is_inside(L, R, M, val): # is L <= val <= R in mod M context?
	if L <= R:
		return L <= val <= R
	else:
		R += M
		if L <= val <= R:
			return True
		if L <= val + M <= R:
			return True 
		return False

## some notes : it's good idea to check for gcd(A, M) = 1
## in CTF context, if gcd(A, M) != 1, we can factorize M and sometimes we can solve the challenge
## in competitive programming context, we need to check gcd(A, M) = 1 and decide whether solution even exists..
def optf(A, M, L, R): # minimum nonnegative x s.t. L <= Ax mod M <= R
	if L == 0:
		return 0
	if 2 * A > M:
		L, R = R, L
		A, L, R = M - A, M - L, M - R
	cc_1 = ceil(L, A)
	if A * cc_1 <= R:
		return cc_1
	cc_2 = optf(A - M % A, A, L % A, R % A)
	return ceil(L + M * cc_2, A)

# check if L <= Ax (mod M) <= R has a solution
def sol_ex(A, M, L, R):
	if L == 0 or L > R:
		return True
	g = GCD(A, M)
	if (L - 1) // g == R // g:
		return False
	return True

## find all solutions for L <= Ax mod M <= R, S <= x <= E:
def solve(A, M, L, R, S, E):
	# this is for estimate only : if very large, might be a bad idea to run this
	# print("Expected Number of Solutions : ", ((E - S + 1) * (R - L + 1)) // M + 1)
	if sol_ex(A, M, L, R) == False:
		return []
	cur = S - 1
	ans = []
	num_sol = 0
	while cur <= E:
		NL = (L - A * (cur + 1)) % M
		NR = (R - A * (cur + 1)) % M
		if NL > NR:
			cur += 1
		else:
			val = optf(A, M, NL, NR)
			cur += 1 + val
		if cur <= E:
			ans.append(cur)
			# remove assert for performance if needed
			assert is_inside(L, R, M, (A * cur) % M)
			num_sol += 1
	print("Actual Number of Solutions : ", num_sol)
	return ans

R = RealField(10000)
s, e = 1, 13371337
res = R(0)

for i in tqdm(range(1, 14000000)):
	# s / i* 2^(e-i)
	if i <= e:
		cc = int(  (s * int(pow(2, e - i, i)) ) % i )
		res += R(cc) / R(i)
	elif i <= e + 600:
		cc = s % (i * pow(2, i-e))
		res += R(cc) / R(i * (R(2) ** (i - e)))
	else:
		res += R(s) / R(i * (R(2) ** (i - e)))
	if res >= R(1):
		res -= R(1)

v = int(res * R(2 ** 5000))
print(v)

sys.setrecursionlimit(10 ** 6)

# precomputed value for v if we want to run faster
# v = 104467719097681022057300648159092766739461820759527788803431374429749202996598539378458182436837681345543925962306891591833461612502515045981445926684682358323308261304290373054925612226182733107796857626976493704119272755515918737555569752899651208944094037846879634304455864163093308215843400987528709056202607615741661048357391118227786345180154208036978340562466304585408474133903329418830168845350382065437912818670354536370592643276209990022352468513247105364866496635369670789720747700649759990355890200751012936662143561049001301249528010291771761950361452815258340869891084006477266374594006616353577318049159753438048226906578830586885303742385812811980671604779855709970433220838908955178688103887057381189868736971917478791863222159108503041341127526278506417196248697197556016664197565112768842768202516445787527018959899837975690485431230655281878513063189418403851078733109615830807076747920972948291859087346662306827774924514073854523174295841676152577125804719203730924000152764239173508745969462217783210008405744313807064502904124419556467728734901163402045262617247557826707141500370639533350600868367440350224548254262243646719957836133362916060574889531746989612145901750068206496214840464856508514364038366349275783596869857224531822138102707600832995684295680096350514375154337769610478058827222795657082330192108305758247420243158539345558518997843832260211831484592731800899720540704391473357713953835834406266097918490563059947547462195243149279631721444764029089223803466310598

while True:
	r = remote('34.146.212.53', 53928)
	s = r.recvline()
	print(s)
	s = s[-76:-2]
	print(s)

	cc = bytes_to_long(s)
	res = R(cc).log() / R(2).log()
	res = int(res * R(2 ** 5000))

	# enc * v - integer * 2^5000 = ln_2(val) * 2^5000
	# enc * v - integer * 2^5000 = res 
	fin = solve(v, 1 << 5000, (res - (1 << 4409)) % (1 << 5000), (res + (1 << 4409)) % (1 << 5000), 0, 1 << 600)
	dec = R(v) / R(2 ** 5000)

	finished = False
	for cand in fin:
		if finished:
			break
		val = dec * R(cand)
		val = val - val.floor()
		val = R(2) ** val
		for i in range(70 * 8, 80 * 8):
			flag = int(val * R(2 ** i))
			flag = flag.to_bytes((flag.bit_length() + 7) // 8, 'big')
			if s == flag[:74]:
				print(s)
				print(cand.bit_length())
				print(flag)
				print(cand)
				r.sendline(str(cand))
				ff = r.recvline()
				if b"? :P" in ff:
					finished = True
					break
				else:
					print(ff)
	r.close()