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

conn = remote('168.119.108.148', 13010)

for i in range(4):
    conn.recvline()

while True:
    inputs = []
    for i in range(7):
        s = conn.recvline()
        print(s)
        inputs.append(s)
    p = int(inputs[2].split()[-1])
    n = int(inputs[5].split()[-1])
    deg = int(inputs[6].split()[-1][:-1])
    a = p + 1 - n 
    val = [2, a]
    for i in range(2, deg + 1):
        val.append(a * val[i-1] - p * val[i-2])
    ans = (p ** deg) + 1 - val[deg]
    conn.sendline(str(ans))
    print(conn.recvline())

