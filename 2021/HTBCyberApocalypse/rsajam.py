from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad, unpad
from Crypto.Util.number import inverse, long_to_bytes, bytes_to_long, isPrime, getPrime
from tqdm import tqdm
from pwn import *
from sage.all import *
import sys, json, hashlib, os, math, time, base64, binascii, string, re, struct, datetime
import random as rand
from os import urandom
import multiprocessing as mp

r = remote('46.101.77.180', 31366)

print(r.recvline())
t = r.recvline().strip().replace(b'\'', b'\"')
res = json.loads(t)

e = res['e']
d = res['d']
N = res['N']

for g in range(3, 100):
    tt = e * d - 1
    while tt % 2 == 0:
        tt //= 2
    val = pow(g, tt, N)
    for i in range(0, 10):
        u = GCD(val-1, N)
        if 1 < u < N:
            p = u
            q = N // u
            phi = (p - 1) * (q - 1)
            dd = (d + phi // 2) % phi
            r.sendline(str(dd))
            print(r.recvline())
            print(r.recvline())
            exit()
        val = (val * val) % N
