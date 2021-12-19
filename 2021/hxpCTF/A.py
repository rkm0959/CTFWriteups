from Crypto.Cipher import AES, PKCS1_OAEP, PKCS1_v1_5
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad, unpad
from Crypto.Util import Counter
from Crypto.Util.number import inverse, long_to_bytes, bytes_to_long, isPrime, getPrime, getRandomRange, sieve_base
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

queries = # precomputed queries
for cnt in range(0, 40):
    conn = remote("65.108.176.239", 3153)
    tt = conn.recvline().decode()
    print(tt)
    u = tt.index('"')
    
    PoW = tt[u+1 : u+17]
    print(PoW)
    res = subprocess.run(["./pow-solver", "28", PoW], capture_output=True)
    ans = res.stdout
    print(ans)
    conn.sendline(ans.strip())

    f = open("data" + str(cnt) + ".txt", "w")

    f.write(conn.recvline().decode() + "\n")

    dat = []

    for i in tqdm(range(500)):
        conn.sendline(queries[i][2].encode())
        dat.append(conn.recvline().decode().strip())

    f.write(str(dat))
    f.close()
    conn.close()

