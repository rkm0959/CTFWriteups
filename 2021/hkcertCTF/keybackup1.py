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

def inthroot(a, n):
    return a.nth_root(n, truncate_mode=True)[0]

conn = remote('chalp.hkcert21.pwnable.hk', 28157)

res = []
mods = []


conn.sendline("pkey")

for i in range(5):
    conn.sendline(b"backup")
    
    input = conn.recvline().split()[-1].strip().decode()
    print(input)
    secret_result = int(input, 16)

    st = hex(1 << 61)[2:].encode()
    cc = conn.sendline(b"send " + st)

    input = conn.recvline().split()[-1].strip().decode()
    print(input)
    enc_result = int(input, 16)

    mult_n = (1 << (61 * 17)) - enc_result
    for j in range(2, 1 << 15):
        while mult_n % j == 0:
            mult_n = mult_n // j
    
    res.append(secret_result)
    mods.append(mult_n)

    conn.sendline(b"pkey")

conn.sendline(b"flag")
input = conn.recvline().split()[-1].strip().decode()
encflag = bytes.fromhex(input)

fin = crt(res, mods)
fin = Integer(fin)
secret = inthroot(fin, 17)

secret = long_to_bytes(int(secret), 8)

cipher = AES.new(secret, AES.MODE_CBC, b"\x00" * 16)

print(cipher.decrypt(encflag))