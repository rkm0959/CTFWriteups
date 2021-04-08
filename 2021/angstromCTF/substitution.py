from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad, unpad
import string
from Crypto.Util.number import inverse, long_to_bytes, bytes_to_long, isPrime, getPrime
from tqdm import tqdm
from pwn import *
from z3 import *
from sage.all import *
import sys, json, hashlib, os
import math, time, base64
import random as rd # avoid confusion with sage
import multiprocessing as mp
import base64
import binascii

r = remote('crypto.2021.chall.actf.co', '21601')
p = 691
M = Matrix(GF(p), 50, 50)
b = []
r.recvline()

for i in tqdm(range(0, 50)):
	r.sendline(str(i+1))
	s = int(r.recvline().split()[-1])
	b.append(s)

b = vector(b)

for i in range(0, 50):
	for j in range(0, 50):
		M[i, j] = ((i+1) ** j)

v = M.solve_right(b)
cc = ''
for i in range(49, -1, -1):
	vv = (int)(v[i])
	if 32 <= vv < 128:
		cc += chr(vv)

print(cc)