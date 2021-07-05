from Crypto.Cipher import AES, PKCS1_OAEP, PKCS1_v1_5
from Crypto.PublicKey import RSA
from Crypto.Util.number import inverse, long_to_bytes, bytes_to_long, isPrime, getPrime
from tqdm import tqdm
from pwn import *
from sage.all import *
import itertools, sys, json, hashlib, os, math, time, base64, binascii, string, re, struct, datetime, subprocess
import numpy as np
import random as rand
import multiprocessing as mp
from Crypto.Hash import SHA256

r = remote('111.186.59.28', 31337)
charset = string.ascii_letters + string.digits + '!#$%&*-?'

def _prod(L):
    p = 1
    for x in L:
        p *= x
    return p

def _sum(L):
    s = 0
    for x in L:
        s ^= x
    return s

def find_sol(args):
    START, TARGET, RANGE = args
    if RANGE >= 70:
        return None
    for i in range(70):
        for j in range(70):
            for k in range(70):
                cur = charset[RANGE] + charset[i] + charset[j] + charset[k]
                v = cur.encode() + START
                if hashlib.sha256(v).digest() == TARGET:
                    return cur.encode()
    return None 

def PoW(NUM, START, TARGET):
    batch = 1
    pool = mp.Pool(NUM)
    nonce = 0
    while True:
        nonce_range = [nonce + i * batch for i in range(NUM)]
        params = [(START, TARGET, RANGE) for RANGE in nonce_range]
        solutions = pool.map(find_sol, params)
        solutions = list(filter(None, solutions))
        print("Checked", nonce + batch * NUM)
        if len(solutions) != 0:
            return solutions[0]
        nonce += batch * NUM

def do_Pow():
    s = r.recvline()
    r.recvline()
    cc = s.split()[2][:-1]
    target = s.split()[4].decode()
    target = bytes.fromhex(target)
    res = PoW(12, cc, target)
    print(res)
    r.sendline(res)
    print("Solved PoW")

def get_keystream(idx):
    r.recvline()
    r.sendline(str(idx))
    bits = []
    for i in range(5):
        ss = r.recvuntil(":::end\n")[:-1]
        ss = ss[8:-6]
        for j in range(1000):
            t = ss[j]
            for k in range(7, -1, -1):
                bits.append((t >> k) & 1)
    cc = r.recvline().split()[-1].decode()
    hint = bytes.fromhex(cc)
    return bits, hint

mat = [[0] * 64 for _ in range(64)]
cur = 64
for i in range(64):
    for j in range(i+1, 64):
        mat[i][j] = cur
        cur += 1

def single(i):
    return i

def double(i, j):
    if i > j:
        i, j = j, i
    if i == j:
        return i
    return mat[i][j]

r.close()


'''
LFSR = []
for i in range(64):
    cur = [0] * 64
    cur[i] = 1
    cur = vector(GF(2), cur)
    LFSR.append(cur)

for i in tqdm(range(10000)):
    LFSR = LFSR[1:] + [LFSR[0] + LFSR[55]]
    LFSR = LFSR[1:] + [LFSR[0] + LFSR[55]]
    LFSR = LFSR[1:] + [LFSR[0] + LFSR[55]]
    res = [0] * 2080
    for j in range(64):
        for k in range(64):
            if LFSR[8][j] == GF(2)(1) and LFSR[63][k] == GF(2)(1):
                res[double(j, k)] ^= 1
    for j in range(64):
        if LFSR[8][j] == GF(2)(1):
            res[single(j)] ^= 1
    for k in range(64):
        if LFSR[63][k] == GF(2)(1):
            res[single(k)] ^= 1
    s = ''
    for j in range(2080):
        s += str(res[j]) + " "
    f.write(s + "\n")
f.close()
'''

attempt = 0
while True:
    r = remote('111.186.59.28', 31337)
    do_Pow()
    attempt += 1
    print("#Attempt = ", attempt)

    print("Solving #1")
    bits, hint = get_keystream(1)
    r.recvline()
    print(hint)
    solve = False
    for i in tqdm(range(1 << 16)):
        LFSR = [0] * 16
        NFSR = [0] * 48
        for j in range(16):
            LFSR[j] = (i >> j) & 1
        for j in range(48):
            bb = LFSR[4] + LFSR[15] + LFSR[2] * LFSR[15] + LFSR[2] * LFSR[4] * LFSR[7] + LFSR[2] * LFSR[7] * LFSR[15]
            bb = bb % 2
            NFSR[j] = (bits[j] + bb) % 2
            LFSR = LFSR[1: ] + [_sum(LFSR[k] for k in [0, 1, 12, 15])]
        key = 0
        for j in range(48):
            key = 2 * key + NFSR[j]
        for j in range(16):
            LFSR[j] = (i >> j) & 1
        for j in range(16):
            key = 2 * key + LFSR[j]
        vv = hashlib.sha256(str(key).encode()).hexdigest()
        vv = bytes.fromhex(vv)
        if vv == hint:
            r.sendline(str(key))
            print(r.recvline())
            solve = True
            break
    if solve == False:
        r.close()
        continue

    print("Solving #3")
    bits, hint = get_keystream(3)
    print(r.recvline())
    print(len(bits))
    print(hint)
    B = []
    cnt = 0

    f = open("Matrix3.txt", 'r')

    for i in range(10000):
        s = f.readline()
        cc = s.split()
        res = [0] * 2080
        for j in range(2080):
            res[j] = int(cc[j])
        if bits[i] == 1:
            cnt += 1
            B.append(res)
    f.close()

    print("Solving!!")
    Mat = Matrix(GF(2), B)
    vv = vector(GF(2), [1 for _ in range(cnt)])
    print(len(Mat.right_kernel().basis()))
    v = Mat.solve_right(vv)
    key = 0
    for i in range(64):
        if v[i] == GF(2)(0):
            key = 2 * key
        else:
            key = 2 * key + 1
    r.sendline(str(key))
    print(r.recvline())
    print(r.recvline())
    print(r.recvline())
    print(r.recvline())