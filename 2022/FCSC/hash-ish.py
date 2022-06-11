# from Crypto.Cipher import AES, PKCS1_OAEP, PKCS1_v1_5
# from Crypto.PublicKey import RSA
# from Crypto.Util.Padding import pad, unpad
# from Crypto.Util import Counter
from Crypto.Util.number import getStrongPrime, inverse, long_to_bytes, bytes_to_long, isPrime, getPrime, getRandomRange, sieve_base
# from tqdm import tqdm
from pwn import *
# from sage.all import *
# import gmpy2, pickle, itertools, sys, json, hashlib, os, math, time, base64, binascii, string, re, struct, datetime, subprocess
# import numpy as np
# import random as rand
# import multiprocessing as mp
# from base64 import b64encode, b64decode
# from sage.modules.free_module_integer import IntegerLattice
# from Crypto.Hash import SHA3_256, HMAC, BLAKE2s
# from Crypto.Cipher import AES, ARC4, DES
# from mt19937predictor import MT19937Predictor
# from Crypto.Hash import SHA256
# from Crypto.Random import get_random_bytes

conn = remote("challenges.france-cybersecurity-challenge.fr", 2103)

s = conn.recvline()
print(s)

target = int(s.split()[-1])
print(target)

if target < 0:
    target = target + (1 << 64)

P1 = 11400714785074694791
P2 = 14029467366897019727
P5 = 2870177450012600261

for i in range(0, 200):
    lane = i
    acc = P5 
    acc = (acc + hash(lane) * P2) % (1 << 64)
    acc = ((acc << 31) | (acc >> 33)) % (1 << 64)
    acc = (acc * P1) % (1 << 64)

    goal = target
    goal = (goal - (2 ^ P5 ^ 3527539)) % (1 << 64)
    goal = (goal * inverse(P1, 1 << 64)) % (1 << 64)
    goal = ((goal << 33) | (goal >> 31)) % (1 << 64)

    lane = ((goal - acc) * inverse(P2, 1 << 64)) % (1 << 64)

    if lane == hash(lane):
        print(hash((i, lane)))
        conn.sendline(str(i).encode())
        conn.sendline(str(lane).encode())
        fin = bytes(eval(conn.recvline()[8:-1]))
        print(fin)
        exit()








