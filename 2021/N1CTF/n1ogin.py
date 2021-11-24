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

from Crypto.PublicKey.RSA import import_key
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, hmac
from pwn import *



admin_data = {"rsa_data": "391b06a1740b8c9cf1c8d2bb66ba5b191caa8534b4be18c22ce81069658dd2cd3ca3a8d1a3fc8dfab4b68a6b076bf89be807404e0a98dd1bf9daaf8ba34e0556131d3e56cae61c0302d24a177481209e82de7ecf91c2fe66aa39162d7af9c2fdabaf0c444badfc6b82b071fda8e3b26d4d3e57dba25c36298601ae0153c73b7469c472ac4702531c38849772e7c6e24313e6eb7def64a7bec1c21150c1fded52b3ca716d4444b4d75836dff8c92a371f6256ee7a48034f6d5ea949d982f9f05c04d3d7cce10bd11b806cc02088b42fa0cb069390700fb586287ba224ea0b210ebd0479a4f1d2ef5f914bcc861125b7d8d714cf0feecb515c1b1ef869e91ca179", "aes_data": "1709bf9489f6df6dc31491cee4711f7a2a3e050f1ed3e9772442e8a8483e341313713383dd31fbf0133d55e977b8edf54ba832002ee4ee52da32c260b083a35b01626201c36dad6fca7b2be2aa03d90bf5c9a601a24149f55cdcd39f0bf6a032bfabeebee5259a21e188f5c5f8776cd9d7c072054781169174bddbc390e6da21bd7b85f76c93f48914fb1958ac89e464511d9a17fb2174aab825cb13eb3f0dfa"}


conn = remote("43.155.59.224", 7777)
conn.readline()


PUB_KEY = import_key(open("n1ogin.pub", "r").read())

def send_data(data):
    envelope = json.dumps(data)
    st = time.time()
    conn.sendlineafter(b"> ", envelope.encode())
    res = conn.recvline().decode()
    en = time.time()
    return en - st

aesdata = bytes.fromhex(admin_data["aes_data"])
iv, cipher, mac = aesdata[:16], aesdata[16:-16], aesdata[-16:]
res = iv + cipher 


conn.sendline(b"asdf")
conn.recvline()

true_ptxt = [0] * (len(res))

for i in range(len(res), 16, -16):
    for j in range(0, 16):
        tt = []
        sol = -1
        record = 0
        for k in tqdm(range(256)):
            if i == len(res) and j == 0 and k == 0:
                continue
            if (k ^ (j + 1)) > 128:
                continue
            query_token = res[:i-j-17]
            query_token += bytes([res[i-j-17] ^ k])
            for u in range(j):
                query_token += bytes([res[i-j-16+u] ^ true_ptxt[i-j+u] ^ (j+1)])
            query_token += res[i-16:i]
            # print(query_token)
            query_token += os.urandom(16)
            tot = []
            for _ in range(5):
                dat = {
                    "rsa_data" : admin_data["rsa_data"],
                    "aes_data" : query_token.hex()
                }
                spent = send_data(dat)
                tot.append(spent)
            tot.sort()
            tot = tot[2]
            tt.append((tot, chr(k ^ (j+1))))
            if tot > record:
                sol = k
                record = tot
        tt.sort()
        print(tt[-7:])
        true_ptxt[i-j-1] = sol ^ (j + 1)
        print(bytes(true_ptxt))
