from Crypto.Cipher import AES, PKCS1_OAEP, PKCS1_v1_5
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad
from Crypto.Util.number import inverse, long_to_bytes, bytes_to_long, isPrime, getPrime
from sympy.matrices.matrices import num_mat_mul
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

r = remote('167.99.77.49', 52171)
# r.interactive()

def read_menu(x):
	for _ in range(x):
		r.recvline()

read_menu(5)

read_menu(3)
r.sendline(b"1")
r.send(b"\n")
r.recvline()
token = r.recvline()
token = b64decode(token)
print(token)
print(len(token))

true_ptxt = [0] * 80

for i in range(64, 16, -16):
	for j in range(0, 16):
		for k in tqdm(range(0, 256)):
			if i == 64 and j == 0 and k == 0:
				continue
			query_token = token[:i-j-17]
			query_token += bytes([token[i-j-17] ^ k])
			for u in range(j):
				query_token += bytes([token[i-j-16+u] ^ true_ptxt[i-j+16+u] ^ (j+1)])
			query_token += token[i-16:i+16]
			read_menu(3)
			r.sendline(b"2")
			r.sendline(b"abc")
			r.sendline(b64encode(query_token))
			res = r.recvline()
			if b"Check your token again" not in res:
				true_ptxt[i+15-j] = k ^ (j+1)
				break
		print(bytes(true_ptxt))

print(bytes(true_ptxt))