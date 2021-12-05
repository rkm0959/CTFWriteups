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

cnt_outside = 0
cnt = 0

REMOTE = True
while True:
    cnt_outside += 1
    print("outside trial", cnt_outside)
    if REMOTE:
        conn = remote('35.72.139.70', 31338)
        magic = conn.recvline().split()[-1].decode()
        conn.recvline()
    else:
        magic = os.urandom(17).hex()
    magic = bytes.fromhex(magic)
    magic = bytes_to_long(magic)

    N = (magic << 248) + 1
    
    if isPrime(N) == False:
        if REMOTE:
            conn.close()
        continue

    K = list(factor(magic))
    if K[-1][0] > (2 ** 120):
        if REMOTE:
            conn.close()
        continue

    print(K)
    
    while True:
        dat = os.urandom(48)
        data_num = bytes_to_long(dat)
        data2 = hashlib.sha384(dat).digest()
        data2_num = bytes_to_long(data2)

        if data2_num >= N:
            continue

        cnt += 1
        print("trial: ", cnt)
        print(dat, data2)

        e = None 
        try:
            e = GF(N)(data2_num).log(GF(N)(data_num))
        except:
            pass
        if e != None and pow(data_num, e, N) == data2_num:
            print(N)
            print(e)
            print(dat)
            conn.sendline(str(N))
            conn.sendline(str(e))
            conn.sendline(binascii.hexlify(dat))
            print(conn.recvline())
            exit()
