from Crypto.Cipher import AES, PKCS1_OAEP, PKCS1_v1_5
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad, unpad
from Crypto.Util.number import inverse, long_to_bytes, bytes_to_long, isPrime, getPrime, getRandomRange
from tqdm import tqdm
# from pwn import *
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

R = RealField(10000)
s, e = 1644076701048410800736598044521957621165075009220047353598695908154798545574669213628822983013478131645136107829991107147966592023064802684205984935604556580976432082255148549763, 13371337
print(s.bit_length())

res = R(0)

for i in tqdm(range(1, 14000000)):
    # s / i* 2^(e-i)
    if i <= e:
        cc = int(  (s * int(pow(2, e - i, i)) ) % i )
        res += R(cc) / R(i)
    elif i <= e + 600:
        cc = s % (i * pow(2, i-e))
        res += R(cc) / R(i * (R(2) ** (i - e)))
    else:
        res += R(s) / R(i * (R(2) ** (i - e)))
    if res >= R(1):
        res -= R(1)
    
print(res)
res = R(2) ** res

for i in range(70 * 8, 80 * 8):
    cc = int(res * R(2 ** i))
    print(cc.to_bytes((cc.bit_length() + 7) // 8, 'big'))
