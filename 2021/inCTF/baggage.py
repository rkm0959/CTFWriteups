from Crypto.Cipher import AES, PKCS1_OAEP, PKCS1_v1_5
from Crypto.PublicKey import RSA
from Crypto.Util.number import inverse, long_to_bytes, bytes_to_long, isPrime, getPrime, GCD
from tqdm import tqdm
from pwn import *
from sage.all import *
import gmpy2, pickle, itertools, sys, json, hashlib, os, math, time, base64, binascii, string, re, struct, datetime, subprocess
import numpy as np
# import random as rand
from random import getrandbits as rand
import multiprocessing as mp
from base64 import b64encode, b64decode
from sage.modules.free_module_integer import IntegerLattice
from ecdsa import ecdsa

def decrypt(ct, pv):
	b, r, q = pv
	ct = (inverse(r, q)*ct)%q
	msg = ''
	for i in b[::-1]:
		if ct >= i:
			msg += '1'
			ct -= i
		else:
			msg += '0'
	return bytes.fromhex(hex(int(msg, 2))[2:])

BUF = 16

f = open("enc.pickle", "rb")
res = pickle.load(f)
f.close()

cip = res["cip"]
pubkey = res["pbkey"]

mx = max(pubkey)

print(mx.bit_length())

dif = []
for i in range(len(pubkey) - 1):
    dif.append(pubkey[i+1] - 2 * pubkey[i])

res = dif[0]
for i in range(len(dif)):
    res = GCD(res, dif[i])
print(res)

b = []

for i in range(len(pubkey)):
    b.append(pubkey[i] // res)

q = int(b[-1])
while q.bit_length() < 320:
    q = int(next_prime(q << 1))

fin = decrypt(cip, (b, res, q))
print(fin)