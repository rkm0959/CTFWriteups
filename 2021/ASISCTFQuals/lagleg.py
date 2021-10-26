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
from Crypto.Hash import SHA3_256, HMAC, BLAKE2s
from Crypto.Cipher import AES, ARC4, DES

def inthroot(a, n):
	return a.nth_root(n, truncate_mode=True)[0]

a = 192948041792305023195893277034532781336
n = 772559547290160010920412621051392165317498598296084946084386444091060134053985973087541256301003639549317798291916637210182966424107689011211268907278162096553174971554689109947325734336069313105789282878112740205249104820920364881
y = 754843853942922590978288450377461057162899072980081889481597335367906588582097339709346991452615504422434823707721197330881973700388055679080814559570248350531810374624494389646277873934234170885190847719684200687267925979436889772
U, V = (9083709539234699681499154559006541145975405183323215645582033885264296926186620280958201308661746194284022873377667665062501349047202357817146222033735539058147945671541486202387767382626733526030628929826676457655813734637020574, 625771268848498566477216756364333384750869252753726246816617776940622341574266652518894117167008714362418009723919180248010211052475114496172513936468417590330695688907796560242492250071433491517329459840410014214097477377322316145)

print(n.bit_length())

# r : 128 bit
# s : 32 bit
# n = (r^5 + s)(r + s) = r^6 + sr^5 + sr + s^2
# r^6 <= n <= r^6 + 2^32 r^5 + 2^32 r + 2^64

'''
r = int(inthroot(Integer(n), 6))

lef = 0
rig = 1 << 129 
best = 0

while lef <= rig:
	mid = (lef + rig) // 2
	if (mid ** 5 + (1 << 32)) * (mid + (1 << 32)) >= n:
		best = mid
		rig = mid - 1
	else:
		lef = mid + 1

def find_sol(args):
	target, RANGE = args
	target = Integer(target)
	for i in range(RANGE[0], RANGE[1]):
		# (i^5 + s)(i + s) = target
		b = Integer(i) ** 5 + Integer(i)
		c = Integer(i) ** 6 - target
		det = b * b - 4 * c 
		if det < 0:
			continue
		v = inthroot(det, 2)
		if v * v == det:
			s = (-int(b) + int(v)) // 2
			if (i ** 5 + s) * (i + s) == int(target):
				return i
	return None 

def solve(target, l, r):
	batch = 3000000
	NUM = 12
	pool = mp.Pool(NUM)
	nonce = 0
	while True:
		nonce_range = [(nonce + l + i * batch, nonce + l + i * batch + batch) for i in range(NUM)]
		params = [(target, RANGE) for RANGE in nonce_range]
		solutions = pool.map(find_sol, params)
		solutions = list(filter(None, solutions))
		print("Checked", nonce + batch * NUM)
		if len(solutions) != 0:
			return solutions[0]
		nonce += batch * NUM

sols = solve(n, best, r)
print(sols)
'''

r = 302915847001663746574137782281707162419
s = 3417321932

p = r ** 5 + s 
q = r + s 

D = a * a - 4

def lag(k, a, n):
	s, t = 2, a
	if k == 0:
		return 2
	r = 0
	while k % 2 == 0:
		r += 1
		k //= 2
	B = bin(k)[2:]
	for b in B:
		if b == '0':
			t = (s * t - a) % n
			s = (s **2 - 2) % n
		else:
			s = (s * t - a) % n
			t = (t** 2 - 2) % n
	for _ in range(r):
		s = (s ** 2 - 2) % n
	return s

e = 65537
d = inverse(e, (p * p - 1) * (q * q - 1))
x = pow(d, e, n)

ryn = lag(x, U, n)
emn = (V - ryn + n) % n


def solve_p(target, p, e):
	POL = PolynomialRing(GF(p), 'x')
	x = POL.gen()
	K = GF(p ** 2, name = 'a', modulus = x * x - target * x + 1)
	res = K(x)
	d = inverse(e, p * p - 1)
	res = res ** d 
	tt = res + res ** -1
	return GF(p)(tt)


def solve_q(target, q, e):
	POL = PolynomialRing(GF(q), 'x')
	x = POL.gen()
	# ?^e + ?^-e == emn
	# ? + ?^-1 = m
	f = x * x - target * x + 1
	root = f.roots()[0][0]
	d = inverse(e, q - 1)
	val = pow(int(root), d, q)
	mq = (val + inverse(val, q)) % q
	return mq


res1 = solve_p(emn, p, e)
res2 = solve_q(emn, q, e)
flag = int(crt(int(res1), int(res2), p, q))
print(long_to_bytes(flag))
