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
while True:
    cnt_outside += 1
    print("outside trial", cnt_outside)
    conn = remote('35.72.139.70', 31337)

    magic = conn.recvline().split()[-1].decode()
    conn.recvline()
    magic = bytes.fromhex(magic)
    magic = bytes_to_long(magic)

    N = magic << 248
    
    if magic % 2 == 0:
        conn.close()
        continue 
    K = list(factor(magic))
    if len(K) != 2:
        conn.close()
        continue 
    if K[0][1] != 1 or K[1][1] != 1:
        conn.close()
        continue
    p = K[0][0]
    q = K[1][0]
    if p < (1 << 16) or q < (1 << 16) or p % 4 == 1 or q % 4 == 1 or GCD(p - 1, q - 1) > 2:
        conn.close()
        continue
    print(factor(N))
    sleep(5)
    while True:
        dat = os.urandom(48)
        data_num = bytes_to_long(dat)
        data2 = hashlib.sha384(dat).digest()
        data2_num = bytes_to_long(data2)

        if data_num % 4 != 3 or data2_num % 2 == 0:
            continue

        cnt += 1
        print("trial: ", cnt)
        print(dat, data2)

        e = None 
        try:
            e1 = discrete_log(Zmod(1 << 384)(data2_num), Zmod(1 << 384)(data_num), operation = '*')
            e2 = GF(p)(data2_num).log(GF(p)(data_num))
            e3 = GF(q)(data2_num).log(GF(q)(data_num))
            e = crt([e1, e2, e3], [1 << 384, p - 1, q - 1])
        except:
            pass
        if e != None:
            print(N)
            print(e)
            print(dat)
            conn.sendline(str(N))
            conn.sendline(str(e))
            conn.sendline(binascii.hexlify(dat))
            print(conn.recvline())
            exit()

