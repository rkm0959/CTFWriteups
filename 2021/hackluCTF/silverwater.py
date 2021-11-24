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
from Crypto.Hash import SHA3_256, HMAC, BLAKE2s
from Crypto.Cipher import AES, ARC4, DES


r = remote('flu.xxx', 20060)

N = int(r.recvline().rstrip())
fac = list(factor(N))

p = fac[0][0]
q = fac[1][0]
ret = b''

for i in range(20):
    s = r.recvline()
    cc = s[1:-2].decode().split()
    b = 0
    for j in range(8):
        cur = int(cc[j])
        u = pow(cur, (p - 1) // 2, p)
        v = pow(cur, (q - 1) // 2, q)
        if u == 1 and v == 1:
            b = 2 * b
        else:
            b = 2 * b + 1
    ret += bytes([b])

print(ret)
r.sendline(ret)
print(r.recvline())

    
