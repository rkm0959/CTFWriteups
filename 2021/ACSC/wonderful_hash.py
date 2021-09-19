from Crypto.Cipher import AES, PKCS1_OAEP, PKCS1_v1_5
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad
from Crypto.Util.number import inverse, long_to_bytes, bytes_to_long, isPrime, getPrime
from sympy.matrices.matrices import num_mat_mul
from tqdm import tqdm
from pwn import *
from sage.all import *
from sympy import *
import gmpy2, pickle, itertools, sys, json, hashlib, os, math, time, base64, binascii, string, re, struct, datetime, subprocess
import numpy as np
import random as rand
import multiprocessing as mp
from base64 import b64encode, b64decode
from sage.modules.free_module_integer import IntegerLattice
from ecdsa import ecdsa
from Crypto.Hash import SHA3_256, HMAC, BLAKE2s
from sage.modules.free_module_integer import IntegerLattice
from Crypto.Cipher import AES, ARC4, DES


r = remote('wonderful-hash.chal.acsc.asia', 10217)

for i in range(5):
    print(r.recvline())
ans = b'cat flag        DxriPBQeGgXmjlewgmpxnBnWbfoxGirrLUtUlukpPmjqMOlCBmaOIXXqKIGXoFJsdVGypWXGdXcPScZXFQPbnigusUZZdrxpCyMeGgKGqzJQIzbRqThOJXNgPPNXdPjIOtRhGKBXJDlYDGMfcnyAIojYUJaFyUhzjlsSQHZPasglvQOWIyVoYELtFwJQSsBPsNpvcKZYuKWBrEHwDQLkpCYWkbNIHPTHxbPqrzDgcXCnVvJKeIzkiMKqPhUwDRIe                                                                                                                                                 '
r.sendline("S")
r.sendline(ans)
for i in range(4):
    print(r.recvline())

r.sendline("E")
for i in range(10):
    print(r.recvline())

## main sol
BLOCK = 16

def bxor(a, b):
    res = [c1 ^ c2 for (c1, c2) in zip(a, b)]
    return bytes(res)


def block_hash(data):
    data = AES.new(data, AES.MODE_ECB).encrypt(b"\x00" * AES.block_size)
    data = ARC4.new(data).encrypt(b"\x00" * DES.key_size)
    data = DES.new(data, DES.MODE_ECB).encrypt(b"\x00" * DES.block_size)
    return data[:-2]


def hash(data):
    length = len(data)
    if length % BLOCK != 0:
        pad_len = BLOCK - length % BLOCK
        data += bytes([pad_len] * pad_len)
        length += pad_len
    block_cnt = length // BLOCK
    blocks = [data[i * BLOCK:(i + 1) * BLOCK] for i in range(block_cnt)]
    res = b"\x00" * BLOCK
    for block in blocks:
        res = bxor(res, block_hash(block))
    return res

def get_random_block():
    res = "".join([rand.choice(string.ascii_letters) for _ in range(16)])
    return res.encode()

cmd = (b"echo 'There are a lot of Capture The Flag (CTF) competitions in "
       b"our days, some of them have excelent tasks, but in most cases "
       b"they're forgotten just after the CTF finished. We decided to make"
       b" some kind of CTF archive and of course, it'll be too boring to "
       b"have just an archive, so we made a place, where you can get some "
       b"another CTF-related info - current overall Capture The Flag team "
       b"rating, per-team statistics etc'")

# 27 

print(len(cmd))

target = bytes_to_long(hash(cmd))

fin_blocks = []
block0 = b"cat flag" + b" " * 8
fin_blocks.append(block0)

target ^= bytes_to_long(block_hash(block0))

back_blocks = []
for i in range(9):
    back_blocks.append(b" " * 16)
    target ^= bytes_to_long(block_hash(b" "*16))
back_blocks.append(b" ")
target ^= bytes_to_long(block_hash(b" " + bytes([15] * 15)))


# now we need 16 blocks

grounds = []
for i in range(16):
    cur = []
    for j in range(6000):
        val = get_random_block()
        cc = block_hash(val)
        cc = bytes_to_long(cc)
        if i == 7:
            cc ^= target
        cur.append([[val], cc])
    grounds.append(cur)

def merger(l, r, tot):
    print("WORKING", l, r, tot)
    global grounds
    if l + 1 == r:
        return grounds[l]
    cc1 = merger(l, (l+r)//2, tot - 12)
    cc2 = merger((l+r) // 2, r, tot - 12)
    print(l, (l+r)//2, len(cc1))
    print((l+r)//2, r, len(cc2))
    LEFT = {}
    for i in range(len(cc1)):
        res = cc1[i][1] % (1 << tot)
        if res in LEFT.keys():
            arr = LEFT[res]
            arr.append(i)
            LEFT[res] = arr
        else:
            LEFT[res] = [i]
    ret = []
    for i in range(len(cc2)):
        res = cc2[i][1] % (1 << tot)
        if res in LEFT.keys():
            arr = LEFT[res]
            for idx in arr:
                xred = cc1[idx][1] ^ cc2[i][1]
                vals = cc1[idx][0] + cc2[i][0]
                ret.append([vals, xred])
    return ret

fin = merger(0, 16, 48)
print(fin[0])

ret = fin[0][0]

sol = fin_blocks + ret + back_blocks

gogo = b""
for block in sol:
    gogo += block

print(gogo)
print(len(gogo))

print(hash(gogo))
print(hash(cmd))

