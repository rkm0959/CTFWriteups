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
from sage.modules.free_module_integer import IntegerLattice

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

p =  148982911401264734500617017580518449923542719532318121475997727602675813514863
g =  2
y =  99943368625476277151400768907519717344447758596311103260066302523387843692499

# ignoring two sig/msg is the hardest part

sig = [(82164720827627951718117576622367372918842412631288684063666489980382312886875, 20555462814568596793812771425415543791560033744700837082533238767135)
,(121728190859093179709167853051428045020048650314914045286511335302789797110644, 18832686601255134631820635660734300367214611070497673143677605724980)
# ,(146082371876690961814167471199278995325899717136850705507399907858041424152875, 17280327447912166881602972638784747375738574870164428834607749483679)
,(70503066417308377066271947367911829721247208157460892633371511382189117698027, 18679076989831101699209257375687089051054511859966345809079812661627)
,(129356717302185231616252962266443899346987025366769583013987552032290057284641, 2084781842220461075274126508657531826108703724816608320266110772897)
# ,(12183293984655719933097345580162258768878646698567137931824149359927592074910, 15768525934046641405375930988120401106067516205761039338919748323087)
]

ct =  'e426c232b20fc298fb4499a2fff2e248615a379c5bc1a7447531f8a66b13fb57e2cf334247a0589be816fc52d80c064b61fa60261e925beb34684655278955e0206709f95173ad292f5c60526363766061e37dd810ee69d1266cbe5124ae18978214e8b39089b31cad5fd91b9a99e344830b76d456bbf92b5585eebeaf85c990'
iv =  '563391612e7c7d3e6bd03e1eaf76a0ba'

messages = [
  b"Never gonna give you up",
  b"Never gonna let you down",
#  b"Never gonna run around and desert you",
  b"Never gonna make you cry",
  b"Never gonna say goodbye",
 # b"Never gonna tell a lie and hurt you"
]

for message in messages:
    print(len(message))
    print(pad(message, 32)[::-1])


q = (p - 1) // 2

coefs = []
consts = []

for i in range(1, 4):
    delta_e = sig[0][1] - sig[i][1]
    delta_s = sig[0][0] - sig[i][0]
    delta_e = (delta_e * inverse(1 << 96, q)) % q 
    delta_s = (delta_s * inverse(1 << 96, q)) % q

    coefs.append(delta_e)
    consts.append(delta_s)

# coefs[i] * x + consts[i] == small mod q

lb = [0] * 4
ub = [0] * 4
M = Matrix(ZZ, 4, 4)
for i in range(3):
    M[0, i] = coefs[i]
    M[i+1, i] = q
    lb[i] = - consts[i]
    ub[i] = (1 << 160) - consts[i]
M[0, 3] = 1
lb[3] = 0
ub[3] = q

result, applied_weights, fin = solve(M, lb, ub)
x = fin[0] % q 

key = hashlib.sha224(long_to_bytes(x)).digest()[:16]
cipher = AES.new(key, AES.MODE_CBC, bytes.fromhex(iv))
print(cipher.decrypt(bytes.fromhex(ct)))

x += q
key = hashlib.sha224(long_to_bytes(x)).digest()[:16]
cipher = AES.new(key, AES.MODE_CBC, bytes.fromhex(iv))
print(cipher.decrypt(bytes.fromhex(ct)))

# rarctf{zZZzZZZZzzZZZzzZZZZZZzZzzzZzzZZzZzzZZzzzZZZZzZZz_s0rry_1_w4s_t00_t1r3d_t0_c0me-up_w1th_4n_4ctual-fl4g_7686f36b65}
