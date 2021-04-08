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

r = remote('crypto.2021.chall.actf.co', '21600')


def nxt(x):
	digits = 8
	val = int(str(x * x).rjust(16, "0")[4 : 12])
	return val

def get_int():
	r.sendline('r')
	s = r.recvline()
	v = s.split()[-1]
	return int(v)

n = get_int()
m = get_int()
L = divisors(n)
p = 0
q = 0

for x in L:
	if 10 ** 7 <= x < 10 ** 8:
		if nxt(x) * nxt(n // x) == m:
			p = nxt(x)
			q = nxt(n // x)


np = nxt(p)
nq = nxt(q)

nnp = nxt(np)
nnq = nxt(nq)

r.sendline('g')
r.sendline(str(np * nq))
r.sendline(str(nnp * nnq))

for i in range(0, 10):
	print(r.recvline())