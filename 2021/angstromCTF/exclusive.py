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

def bytexor(a, b):
	assert len(a) == len(b)
	return bytes(x ^ y for x, y in zip(a, b))

def stxor(a, b):
	assert len(a) == len(b)
	ret = ''
	for i in range(0, len(a)):
		if a[i] == b[i]:
			ret += '0'
		else:
			ret += '1'
	return ret 

def is_ascii(s):
	return all(32 <= c < 128 for c in s)

h = '0ae27eb3a148c3cf031079921ea3315cd27eb7d02882bf724169921eb3a469920e07d0b883bf63c018869a5090e8868e331078a68ec2e468c2bf13b1d9a20ea0208882de12e398c2df60211852deb021f823dda35079b2dda25099f35ab7d218227e17d0a982bee7d098368f13503cd27f135039f68e62f1f9d3cea7'
h += h
h = bin(int(h, 16))[2:]
cc = bin(bytes_to_long(b"actf{"))[2:].rjust(40, '0')


for i in range(0, len(h)):
	A = h[i:]
	if len(A) < 40:
		break
	CYC = stxor(A[:40], cc)
	key = CYC * 50
	key = key[:len(A)]
	ff = stxor(A, key)
	L = 40
	ans = long_to_bytes(int(ff[:L*8], 2))
	if is_ascii(ans):
		print(ans)
	