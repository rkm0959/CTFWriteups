from Crypto.Cipher import AES, PKCS1_OAEP, PKCS1_v1_5
from Crypto.PublicKey import RSA
from Crypto.Util.number import inverse, long_to_bytes, bytes_to_long, isPrime, getPrime, GCD
from tqdm import tqdm
from pwn import *
from sage.all import *
import itertools, sys, json, hashlib, os, math, time, base64, binascii, string, re, struct, datetime, subprocess
import numpy as np
import random as rand
import multiprocessing as mp
from base64 import b64encode, b64decode
from sage.modules.free_module_integer import IntegerLattice
from ecdsa import ecdsa

r = remote('07.cr.yp.toc.tf', 18010)

# ed - 1 == 0 mod phi1, phi2, phi3
# (p-1)(q-1)(r-1)

# p-1 = 2(q-1) = 4(r-1)
# r, 2r-1, 4r-3

def read_lines(num):
    for _ in range(num):
        r.recvline()

p = 2923003274661805836407369665432566039311865114301
q = 2 * p - 1
rr = 4 * p - 3

pr = [p, q, rr]

# ed == 1 mod 8(p-1)^2

e, d = None, None 
while True:
    e = rand.randint(0, 1<<300)
    if GCD(e, 8 * (p-1) *(p-1)) != 1:
        continue
    try:
        d = inverse(e, 8 * (p-1) * (p-1))
        if d < (p-1) * (p-1):
            break
    except:
        pass    

print(e)
print(d)

print((e * d) % (8 * (p-1) * (p-1)))

'''
cur = (1 << 161)

for i in tqdm(range(8000000)):
    p = cur + i 
    if isPrime(p) and isPrime(2 * p - 1) and isPrime(4 * p - 3):
        print(p)
exit()
'''

read_lines(7)
r.sendline("S")
print(r.recvline())
r.sendline(str(pr[0]) + "," + str(pr[1]))
print(r.recvline())
r.sendline(str(pr[1]) + "," + str(pr[2]))
print(r.recvline())
r.sendline(str(pr[2]) + "," + str(pr[0]))
print(r.recvline())
r.sendline(str(e) + "," + str(d))
print(r.recvline())
print(r.recvline())
print(r.recvline())