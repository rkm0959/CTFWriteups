from Crypto.Cipher import AES, PKCS1_OAEP, PKCS1_v1_5
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad, unpad
from Crypto.Util.number import inverse, long_to_bytes, bytes_to_long, isPrime, getPrime
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
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import rsa

def H(params, msg, u):
	K, m = params
	r, z = K.characteristic(), K.gens()[0]
	h = 0
	while msg > 0:
		h *= z
		h += msg % r
		msg //= r
	h += z*u
	for _ in range(m):
		h = h ** r
	assert len(list(h)) != 0
	return int(h[0])

conn = remote('pwn-2021.duc.tf', 31912)
conn.recvline()

N = int(conn.recvline().split()[1])

r = next_prime(N)
F = PolynomialRing(GF(r), 'x')
K = F.quo(F.irreducible_element(15))
params = (K, 3)
pubkey = N

conn.sendline(hex(pubkey ** 6)[2:].encode())
conn.recvline()
conn.recvline()

target = int(conn.recvline().split()[2][2:].decode(), 16)

val_1 = H(params, target, 0)
val_2 = H(params, 0, 1)

u = ((1 + r - val_1) * inverse(val_2, r)) % r

conn.sendline(str(1).encode())
conn.sendline(str(u).encode())

print(conn.recvline())