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

## 16 byte

r = remote('crypto.2021.chall.actf.co', '21602')

def get_int(x):
	r.sendline(b"1")
	cc = int.to_bytes(x, 16, 'big')
	r.sendline(cc.hex())
	s = r.recvline()
	return int(s.split()[-1], 16)

tot = get_int(0)
non = get_int((1 << 128) - 1)

ff = []
for i in tqdm(range(0, 128)):
	ff.append(get_int(1 << i))

def get_query():
	s = r.recvline()
	u = s.split()[-1]
	u.decode()
	c = binascii.unhexlify(u)
	if len(c) % 16 != 0:
		c = c + bytes([0]) * (16 - len(c) % 16)
	return c

def get_enc(x):
	ret = tot
	for i in range(0, 128):
		if ((x >> i) & 1) == 1:
			ret -= (tot - ff[i])
	return ret 

r.sendline(b"2")

for i in range(10):
	ret = ''
	c = get_query()
	for j in range(0, len(c), 16):
		vv = get_enc(bytes_to_long(c[j : j+16]))
		ret += hex(vv)[2:].rjust(32, "0")
	r.sendline(ret)
print(r.recvline())
print(r.recvline())

