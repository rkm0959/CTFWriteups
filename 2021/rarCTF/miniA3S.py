from Crypto.Cipher import AES, PKCS1_OAEP, PKCS1_v1_5
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad
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
from DATA import *

T_SIZE  = 3             # Fixed trits in a tryte
W_SIZE  = 3             # Fixed trytes in a word (determines size of matrix)

# Secure enough ig
SBOX    = (9, 10, 11, 1, 2, 0, 20, 18, 19, 3, 4, 5, 22, 23, 21, 14, 12, 26, 24, 25, 13, 16, 17, 15, 8, 6, 7)

KEYLEN = 8

# plaintext 27 GF(3) values
# round key 216 GF(3) values
# constant 1 GF(3) value
# -> 216 + 27 + 1 = 244


def init_ptxt_vec(idx, val):
	arr = [0] * idx + [val] + [0] * (243 - idx)
	return vector(GF(3), arr)

def init_roundkey_vec(idx, val):
	arr = [0] * (idx + 27) + [val] + [0] * (243 - 27 - idx)
	return vector(GF(3), arr)

def init_constant_vec(val):
	arr = [0] * 243 + [val]
	return vector(GF(3), arr)

ZERO = init_constant_vec(0)
ONE = init_constant_vec(1)
TWO = init_constant_vec(2)

POLY    = (TWO, ZERO, ONE, ONE)  # Len = T_SIZE + 1

POLY2   = ((TWO, ZERO, ONE), (ONE, TWO, ZERO), (ZERO, TWO, ONE), (TWO, ZERO, ONE))  # Len = W_SIZE + 1
CONS    = ((ONE, TWO, ZERO), (TWO, ZERO, ONE), (ONE, ONE, ONE))     # Len = W_SIZE 
I_CONS  = ((ZERO, ZERO, TWO), (TWO, TWO, ONE), (TWO, TWO, TWO))     # Inverse of CONS (mod POLY2)

def sbox_approx(input):
	output = []
	output.append(input[0] + input[1])
	output.append(input[2])
	output.append(ONE + 2 * input[1] + 2 * input[2])
	return tuple(output)

def assert_const(a):
	for i in range(243):
		assert a[i] == GF(3)(0)

def print_const_list(a):
	for x in a:
		print(x[243], end = " ")
	print("\n")
def mult(a, b): # a should be const
	assert_const(a)
	return GF(3)(a[243]) * b

def up(array, size, filler):    # If only there was APL in python :pensiv:
	''' Groups up things in a tuple based on size '''
	l = len(array)
	array += (filler,) * (-l % size)
	return tuple([array[i:i + size] for i in range(0, l, size)])

def down(array): 
	''' Ungroups objects in tuple '''
	return sum(array, ())

def clean(array):
	while len(array) > 1:
		if array[-1] != ZERO:
			break
		array = array[:-1]
	return tuple(array)

def int_to_tri(num): # positive only
	out = []
	while num:
		num, trit = divmod(num, 3)
		out.append(init_constant_vec(trit))
	return tuple(out) if out else (ZERO,)

def int_to_tri_fixed(num):
	out = []
	for _ in range(3):
		num, trit = divmod(num, 3)
		out.append(init_constant_vec(trit))
	return tuple(out)

def tri_to_int(tri): # assumes constant
	out = 0
	for i in tri[::-1]:
		out *= 3
		out += int(i[243])
	return out


def sbox_rev(tri):
	val = int(tri[0]) + 3 * int(tri[1]) + 9 * int(tri[2])
	val = SBOX.index(val)
	return (GF(3)(val % 3), GF(3)((val // 3) % 3), GF(3)(val // 9))

tri_to_tyt  = lambda tri: up(tri, T_SIZE, ZERO)
tyt_to_tri  = lambda tyt: down(tyt)

int_to_tyt  = lambda num: tri_to_tyt(int_to_tri(num))
tyt_to_int  = lambda tyt: tri_to_int(down(tyt))

tyt_to_wrd  = lambda tyt: up(tyt, W_SIZE, (ZERO,) * T_SIZE)
wrd_to_tyt  = lambda wrd: down(wrd)

def apply(func):    # scale up operations (same len only)
	def wrapper(a, b):
		return tuple(func(i, j) for i, j in zip(a, b))
	return wrapper

xor     = lambda a, b: (a + b)
uxor    = lambda a, b: (a - b)
t_xor   = apply(xor)
t_uxor  = apply(uxor)
T_xor   = apply(t_xor)
T_uxor  = apply(t_uxor)
W_xor   = apply(T_xor)
W_uxor  = apply(T_uxor)


def tri_mul(A, B):
	c = [ZERO] * len(B)
	for a in A[::-1]:
		c = [ZERO] + c
		x = tuple(mult(b, a) for b in B)
		c[:len(x)] = t_xor(c, x) # wtf slice assignment exists??? 
	return clean(c)

def tri_divmod(A, B): # both are const
	B = clean(B)
	A2  = list(A)
	c   = [ZERO]
	for idx in A2:
		assert_const(idx)
	for idx in B:
		assert_const(idx)
	while len(A2) >= len(B):
		c = [ZERO] + c
		while A2[-1] != ZERO:
			A2[-len(B):] = t_uxor(A2[-len(B):], B)
			c[0] = xor(c[0], init_constant_vec(1))
		A2.pop()
	if len(A2) == 0:
		A2 = [ZERO]
	return clean(c), clean(A2)

def tri_mulmod(A, B, mod=POLY): # A, mod is const
	c = [ZERO] * (len(mod) - 1)
	for a in A[::-1]:
		c = [ZERO] + c
		x = tuple(mult(a, b) for b in B)
		c[:len(x)] = t_xor(c, x) # wtf slice assignment exists??? 
		mul = mult(mod[-1], c[-1])
		mul = mult(TWO, mul)
		for idx in range(len(c)):
			c[idx] = c[idx] + mult(mod[idx], mul)
		assert c[-1] == ZERO
		c.pop()
	return tuple(c)

def egcd(a, b): # both are const
	x0, x1, y0, y1 = (ZERO,), (ONE,), b, a
	while len(y0) > 1:
		q, _ = tri_divmod(y0, y1)
		u, v = tri_mul(q, y1), tri_mul(q, x1)
		x0, y0 = x0 + (ZERO,) * len(u), y0 + (ZERO,) * len(v)
		y0, y1 = y1, clean(t_uxor(y0, u) + y0[len(u):])
		x0, x1 = x1, clean(t_uxor(x0, v) + x0[len(v):])
	return x0, y0

def modinv(a, m=POLY): # both are const
	_, a = tri_divmod(a, m)
	x, y = egcd(a, m)
	if len(y) > 1:
		raise Exception('modular inverse does not exist')
	return tri_divmod(x, y)[0]

def tyt_mulmod(A, B, mod=POLY2, mod2=POLY): # B is const
	fil = [(ZERO,) * T_SIZE]
	C = fil * (len(mod) - 1)
	for a in A[::-1]:
		C = fil + C
		x = tuple(tri_mulmod(b, a, mod2) for b in B) # b is const
		C[:len(x)] = T_xor(C, x)
		
		num = modinv(mod[-1], mod2)
		num2 = tri_mulmod(num, C[-1], mod2) # num is const
		x = tuple(tri_mulmod(m, num2, mod2) for m in mod) # m is const
		C[:len(x)] = T_uxor(C, x)

		C.pop()
	return C

'''
AES functions
'''

int_to_byt = lambda x: x.to_bytes((x.bit_length() + 7) // 8, "big")
byt_to_int = lambda x: int.from_bytes(x, byteorder="big")

def gen_row(size = W_SIZE):
	out = () 
	for i in range(size):
		row = tuple(list(range(i * size, (i + 1) * size)))
		out += row[i:] + row[:i]
	return out

SHIFT_ROWS = gen_row()
UN_SHIFT_ROWS = tuple([SHIFT_ROWS.index(i) for i in range(len(SHIFT_ROWS))])

def rot_wrd(tyt): # only 1 word so treat as tyt array
	return tyt[1:] + tyt[:1]
	
def sub_wrd(tyt):
	return tuple(sbox_approx(tri) for tri in tyt)


def unsub_wrd(tyt):
	return tuple(sbox_rev(tri) for tri in tyt)

def rcon(num):  # num gives number of constants given
	out = int_to_tyt(1)
	for _ in range(num - 1):
		j = (ZERO,) + out[-1]
		while j[-1] != ZERO:   # xor until back in finite field
			j = t_xor(j, POLY)
		out += (j[:T_SIZE],)
	return out

def expand(tyt):
	words   = tyt_to_wrd(tyt) 
	size    = len(words)
	rnum    = size + 3
	rcons   = rcon(rnum * 3 // size)

	for i in range(size, rnum * 3):
		k   = words[i - size]
		l   = words[i - 1]
		if i % size == 0:
			s = sub_wrd(rot_wrd(l))
			k = T_xor(k, s)
			k = (t_xor(k[0], rcons[i // size - 1]),) + k[1:]
		else:
			k = T_xor(k, l)
		words = words + (k,)

	return up(down(words[:rnum * 3]), W_SIZE ** 2, int_to_tyt(0)[0])

def transform_msg(m):
	m = up(int_to_tyt(m), W_SIZE ** 2, int_to_tyt(0)[0])[-1]
	return m

def transform_ctxt(c):
	c = byt_to_int(c)
	c = up(int_to_tyt(c), W_SIZE ** 2, int_to_tyt(0)[0])[-1]
	return c 

def mix_columns(tyt, cons=CONS):
	tyt = list(tyt)
	for i in range(W_SIZE):
		tyt[i::W_SIZE] = tyt_mulmod(tyt[i::W_SIZE], cons)
	return tuple(tyt)

def a3s_symbolic_partial():
	m = []
	for i in range(0, 27, 3):
		m.append((init_ptxt_vec(i, 1), init_ptxt_vec(i+1, 1), init_ptxt_vec(i+2, 1)))
	m = tuple(m)

	keys = []
	cc = 0
	for i in range(0, 8):
		subkey = []
		for _ in range(0, 27, 3):
			subkey.append((init_roundkey_vec(cc, 1), init_roundkey_vec(cc+1, 1), init_roundkey_vec(cc+2, 1)))
			cc += 3
		subkey = tuple(subkey)
		keys.append(subkey)
	keys = tuple(keys)

	assert len(keys) == KEYLEN

	print("prepared plaintexts and subkeys")

	ctt = T_xor(m, keys[0])
	for r in tqdm(range(1, len(keys) - 1)):
		ctt = sub_wrd(ctt)                          # SUB...
		ctt = tuple([ctt[i] for i in SHIFT_ROWS])   # SHIFT...
		ctt = mix_columns(ctt)                      # MIX...
		ctt = T_xor(ctt, keys[r])                   # ADD!
	return ctt


def a3s_symbolic():
	st = time.time()
	m = []
	for i in range(0, 27, 3):
		m.append((init_ptxt_vec(i, 1), init_ptxt_vec(i+1, 1), init_ptxt_vec(i+2, 1)))
	m = tuple(m)

	keys = []
	cc = 0
	for i in range(0, 8):
		subkey = []
		for j in range(0, 27, 3):
			subkey.append((init_roundkey_vec(cc, 1), init_roundkey_vec(cc+1, 1), init_roundkey_vec(cc+2, 1)))
			cc += 3
		subkey = tuple(subkey)
		keys.append(subkey)
	keys = tuple(keys)

	assert len(keys) == KEYLEN

	print("prepared plaintexts and subkeys")

	ctt = T_xor(m, keys[0])
	for r in tqdm(range(1, len(keys) - 1)):
		ctt = sub_wrd(ctt)                          # SUB...
		ctt = tuple([ctt[i] for i in SHIFT_ROWS])   # SHIFT...
		ctt = mix_columns(ctt)                      # MIX...
		ctt = T_xor(ctt, keys[r])                   # ADD!

	print("finish")
	ctt  = sub_wrd(ctt)
	ctt  = tuple([ctt[i] for i in SHIFT_ROWS])
	ctt  = T_xor(ctt, keys[-1])                     # last key

	en = time.time()

	print(en - st)
	return ctt


ret = a3s_symbolic()

keys = []
cc = 0
for i in range(0, 8):
	subkey = []
	for j in range(0, 27, 3):
		subkey.append((init_roundkey_vec(cc, 1), init_roundkey_vec(cc+1, 1), init_roundkey_vec(cc+2, 1)))
		cc += 3
	subkey = tuple(subkey)
	keys.append(subkey)
keys = tuple(keys)

key_expansion_type_1_equations = []

# Part 1 : Key Expansion Case 1 -> 135

# each word : 9 GF(3) values
cnt_type1 = 0
for i in range(5, 24):
	if i % 5 != 0:
		# -> i =  i-1 xor i-5
		a = i
		b = i-1 
		c = i-5
		for j in range(9):
			cnt_type1 += 1
			res = [0] * 216
			res[9*a+j] = 1
			res[9*b+j] = 2
			res[9*c+j] = 2
			key_expansion_type_1_equations.append((res, 0))
assert cnt_type1 == 135

def get_wrd(idx):
	ret = []
	for i in range(0, 9, 3):
		ret.append((init_roundkey_vec(9 * idx + i, 1), init_roundkey_vec(9 * idx + i + 1, 1), init_roundkey_vec(9 * idx + i + 2, 1)))
	ret = tuple(ret)
	return ret


# Part 2 : Key Expansion Case 2 -> 27 ~ 36


key_expansion_type_2_equations = []
cnt_type2 = 0
rcons = rcon(4)

for i in range(5, 25, 5): # 5, 10, 15, 20
	K = get_wrd(i-5)
	L = get_wrd(i-1)
	T = get_wrd(i)
	S = sub_wrd(rot_wrd(L))
	K = T_xor(K, S)
	K = (t_xor(K[0], rcons[i // 5 - 1]),) + K[1:]
	# this is keys[i]
	for j in range(3):
		batch = []
		for k in range(3):
			resv = T[j][k] - K[j][k]
			vec = [0] * 216
			targ = -resv[243]
			# [0, 27) is trash since they don't need ptxt values
			for idx in range(216):
				vec[idx] = int(resv[27+idx])
			batch.append((vec, targ))
		key_expansion_type_2_equations.append(batch)
# 12 batches x 3 equations per batch => 36 equations 

# Part 3 : Direct Correlation


mmm = [transform_msg(i) for i in tqdm(range(3 ** 9))]
ccc = [transform_ctxt(ENC_DATA[i]) for i in tqdm(range(3 ** 9))]
cccc = []
for i in tqdm(range(3 ** 9)):
	res = ccc[i]
	app = []
	for j in range(9):
		app.append((res[j][0][243], res[j][1][243], res[j][2][243]))
	app = tuple(app)
	cccc.append(app)


direct_correlation_equations = []

diff_val = []
for i in range(27):
	diff_val.append([0] * 3)

key_part = []
for _ in range(9):
	key_part.append([0] * 3)

for i in range(9):
	for j in range(3):
		vec = [0] * 216
		for k in range(216):
			vec[k] = int(ret[i][j][27+k])
		key_part[i][j] = vec


for i in tqdm(range(3 ** 9)):
	m = transform_msg(i)
	c = transform_ctxt(ENC_DATA[i])
	for j in range(9):
		for k in range(3):
			vec = ret[j][k] # symbolic result 
			result = c[j][k][243] # end result 
			for l in range(27): # subtract ptxt part
				result -= int(m[l//3][l%3][243]) * int(vec[l])
			result -= int(vec[243]) # subtract const part
			result = result % 3 # now all that remains is the key part
			diff_val[3*j+k][result] += 1

for i in range(27):
	mx, idx = 0, 0
	for j in range(3):
		if mx < diff_val[i][j]:
			mx = diff_val[i][j]
			idx = j
	direct_correlation_equations.append((key_part[i // 3][i % 3], idx))

# Part 4 : Correlation with Reversing One Step

partial_reverse_equations = []

ret_partial = a3s_symbolic_partial()


for i in tqdm(range(9)):
	print("key", i)
	score = [0] * 27
	for j in tqdm(range(27)):
		diff_val = []
		for _ in range(9):
			diff_val.append([0] * 27)
		true_key = [(GF(3)(0), GF(3)(0), GF(3)(0))] * i + [(GF(3)(j % 3), GF(3)((j // 3) % 3), GF(3)(j // 9))] + [(GF(3)(0), GF(3)(0), GF(3)(0))] * (8 - i)
		true_key = tuple(true_key)
		for k in range(3 ** 9):
			m = mmm[k]
			c = cccc[k]
			c_post_xor = T_uxor(c, true_key)
			c_post_tuple = tuple([c_post_xor[x] for x in UN_SHIFT_ROWS])
			c_final = unsub_wrd(c_post_tuple)
			
			for u in [UN_SHIFT_ROWS.index(i)]:
				CC = 0
				for v in range(3):
					result = int(c_final[u][v])
					for l in range(27):
						result -= int(m[l//3][l%3][243]) * int(ret_partial[u][v][l])
					result -= int(ret_partial[u][v][243])
					result = result % 3
					CC = CC + (int(result) * (3 ** v))
				diff_val[u][CC] += 1
		cur_score = 0
		for k in range(9):
			cur_score += max(diff_val[k])
		score[j] = cur_score
	mx = 0
	idx = 0
	print(score)
	for j in range(27):
		if mx < score[j]:
			mx = score[j]
			idx = j
	fin_key = int_to_tri_fixed(idx)
	for j in range(3):
		my_idx = 27 * 7 + 3 * i + j
		partial_reverse_equations.append(([0] * my_idx + [1] + [0] * (215 - my_idx), fin_key[j][243]))

# GG : find the key

def byte_xor(a, b):
	return bytes([i ^ j for i, j in zip(a, b)])

for i in tqdm(range(12)):
	M = []
	vec_target = []
	for u, v in key_expansion_type_1_equations:
		M.append(list(u))
		vec_target.append(v)
	for j in range(12):
		if i == j:
			continue
		for u, v in key_expansion_type_2_equations[j]:
			M.append(list(u))
			vec_target.append(v)
	for u, v in direct_correlation_equations:
		M.append(list(u))
		vec_target.append(v)
	for u, v in partial_reverse_equations:
		M.append(list(u))
		vec_target.append(v)
	M = Matrix(GF(3), M)
	vec_target = vector(GF(3), vec_target)
	try:
		key = M.solve_right(vec_target)
		print(len(M.right_kernel().basis()))
		fin_ans = 0
		for j in range(45):
			fin_ans += int(key[j]) * (3 ** j)
		hsh = hashlib.sha512(long_to_bytes(fin_ans)).digest()
		flag = byte_xor(hsh, FLAG)
		print(flag)
	except:
		pass