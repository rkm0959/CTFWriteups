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
import zlib

def bytexor(a, b):
	assert len(a) == len(b)
	return bytes(x ^ y for x, y in zip(a, b))

f = open('enc', 'rb')
ctxt = f.read()

for i in tqdm(range(0, 1 << 16)):
	t = long_to_bytes(i)
	t = b'\x00' * (2 - len(t)) + t
	while len(t) <= 150:
		t += zlib.crc32(t).to_bytes(4, 'big')
	t = t[1:145]
	cc = bytexor(ctxt, t)
	if b"actf{" in cc:
		print(cc)