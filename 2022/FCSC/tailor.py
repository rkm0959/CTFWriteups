from Crypto.Cipher import AES, PKCS1_OAEP, PKCS1_v1_5
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad, unpad
from Crypto.Util import Counter
from Crypto.Util.number import getStrongPrime, inverse, long_to_bytes, bytes_to_long, isPrime, getPrime, getRandomRange, sieve_base
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
from mt19937predictor import MT19937Predictor
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes

conn = remote("challenges.france-cybersecurity-challenge.fr", 2100)
target = conn.recvline()[-11:-3]

print(target)

cnt = 0

for T in tqdm(range(256, 1024)):
    a = 0
    pos = True
    cands = [[] for idx in range(8)]
    for idx in range(8):
        # (a + c) * idx + T -> should match target[idx]
        if ord('A') <= target[idx] <= ord('Z') and target[idx] % 2 == 0:
            cidx = (target[idx] - ord('A') - a * idx - T) % 26
            if cidx % GCD(idx, 26) != 0:
                pos = False
            for j in range(32, 128):
                if (j * idx) % 26 == cidx:
                    cands[idx].append(j)            
        if ord('A') <= target[idx] <= ord('Z') and target[idx] % 2 == 1:
            cidx = (target[idx] - ord('A') - a * idx - T + 10) % 16
            if cidx % GCD(idx, 16) != 0:
                pos = False
            for j in range(32, 128):
                if (j * idx) % 16 == cidx:
                    cands[idx].append(j) 
        if ord('0') <= target[idx] <= ord('9'):
            cidx = (target[idx] - ord('0') - a * idx - T) % 16
            if cidx % GCD(idx, 16) != 0:
                pos = False
            for j in range(32, 128):
                if (j * idx) % 16 == cidx:
                    cands[idx].append(j) 
        a = target[idx]
    if pos == False:
        continue
    for tup in itertools.product(*cands):
        tot = sum(tup)
        if tot == T:
            ans = ''
            for idx in range(8):
                ans += chr(tup[idx])
            print(ans)
            conn.sendline(ans.encode())
            cnt += 1
            if cnt == 8:
                print(conn.recvline())
                print(conn.recvline())

        




