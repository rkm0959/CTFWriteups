from Crypto.Cipher import AES, PKCS1_OAEP, PKCS1_v1_5
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad, unpad
from Crypto.Util.number import inverse, long_to_bytes, bytes_to_long, isPrime, getPrime, getRandomRange
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

def inthroot(a, nn):
    return a.nth_root(nn, truncate_mode=True)[0]

n, e = (1108103848370322618250236235096737547381026108763302516499816051432801216813681568375319595638932562835292256776016949573972732881586209527824393027428125964599378845347154409633878436868422905300799413838645686430352484534761305185938956589612889463246508935994301443576781452904666072122465831585156151, 65537)
c = 254705401581808316199469430068831357413481187288921393400711004895837418302514065107811330660948313420965140464021505716810909691650540609799307500282957438243553742714371028405100267860418626513481187170770328765524251710154676478766892336610743824131087888798846367363259860051983889314134196889300426

for i in tqdm(range(1, 5000)):
	for j in range(1, 5000 // i + 5):
		aa = i * j 
		bb = i + j 
		cc = 1 - n 
		try:
			tt = (-bb + inthroot(Integer(bb * bb - 4 * aa * cc), 2)) // (2 * aa)
			p = i * tt + 1
			q = j * tt + 1 
			if p * q == n:
				print("HEY")
				print(p, q)
				phi = LCM(p - 1, q - 1)
				d = inverse(e, phi)
				print(d)
				print(long_to_bytes(pow(c, d, n)))
				exit()
		except:
			pass

