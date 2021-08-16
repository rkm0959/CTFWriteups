from Crypto.Cipher import AES, PKCS1_OAEP, PKCS1_v1_5
from Crypto.PublicKey import RSA
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

def is_ascii(s):
	return all(c < 128 for c in s)

f = open("enc.pickle", "rb")
data = pickle.load(f)
f.close()

cip = bytes.fromhex(data["cip"])
iv = bytes.fromhex(data["iv"])

p = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
a = p - 3
b = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B

E = EllipticCurve(GF(p), [a, b])
G = E(38764697308493389993546589472262590866107682806682771450105924429005322578970, 112597290425349970187225006888153254041358622497584092630146848080355182942680)

pt = G
for i in tqdm(range(1, 1 << 20)):
    pt += G
    cur = int(pt.xy()[0])
    key = hashlib.sha256(str(cur).encode()).digest()[:16]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    flag = cipher.decrypt(cip)
    if is_ascii(flag):
        print(flag)


