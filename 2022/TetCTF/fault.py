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

conn = remote("139.162.61.222", 13373)

def bitcount(x):
    return bin(x).count("1")

d_val = [-1 for _ in range(128)]

THRESHOLD = 40
query_rem = 2022

c_results = []
for i in range(20):
    query_rem -= 1
    conn.sendline(b"c")
    c_fault, c_res = eval(conn.recvline())
    c_results.append([c_fault, c_res])

n = 0
while True:
    query_rem -= 1
    conn.sendline(b"-1")
    vec, val = eval(conn.recvline())
    if val != 1:
        n = val + 1
        break

COMP = [0] * 500
INV = [0] * 500
for i in range(500):
    COMP[i] = Zmod(n)(4) ** (1 << i)
    INV[i] = COMP[i] ** (-1)

conn.sendlines([b"2"] * query_rem)
lines = conn.recvlines(query_rem)


res = []
for i in range(query_rem):
    vec, val = eval(lines[i])
    res.append([vec, val])

def getbit(x, i):
    return (int(x) >> i) & 1

def work(mask1, val1, mask2, val2):
    # if too slow rewrite in sage

    # 2^(d + mask1 - 2 * (d & mask1)) == val1
    # 2^(d + mask2 - 2 * (d & mask2)) == val2 
    # 2^(mask1 - mask2 - 2 (d & mask1) + 2 * (d & mask2)) == val1 / val2
    # remove common parts, still same
    # 4^((d & mask2) - (d & mask1)) == target

    val1 = Zmod(n)(val1)
    val2 = Zmod(n)(val2)

    target = (val1 * (val2 ** -1))
    target = (target * Zmod(n)(2) ** mask2)
    target = (target * Zmod(n)(2) ** (-mask1))

    common = mask1 & mask2 
    mask1 -= common 
    mask2 -= common 

    for i in range(128):
        if d_val[i] == 0:
            if getbit(mask1, i) == 1:
                mask1 -= (1 << i)
            if getbit(mask2, i) == 1:
                mask2 -= (1 << i)
        if d_val[i] == 1:
            if getbit(mask1, i) == 1:
                target = (target * COMP[i]) 
                mask1 -= (1 << i)
            if getbit(mask2, i) == 1:
                target = (target * INV[i])
                mask2 -= (1 << i)
    
    # now MITM work begins
    # 4^((d & mask2) - (d & mask1)) == target

    d_search = []
    for i in range(128):
        if getbit(mask1, i) == 1 or getbit(mask2, i) == 1:
            d_search.append(i)
    lef = d_search[:len(d_search) // 2]
    rig = d_search[len(d_search) // 2:]

    dic = {}
    for i in tqdm(range(1 << len(lef))):
        val = Zmod(n)(1)
        for j in range(len(lef)):
            bit = getbit(i, j)
            if bit == 0:
                continue
            if getbit(mask1, lef[j]) == 1:
                val = (val * INV[lef[j]])
            if getbit(mask2, lef[j]) == 1:
                val = (val * COMP[lef[j]])
        dic[val] = i
    
    for i in tqdm(range(1 << len(rig))):
        val = Zmod(n)(1)
        for j in range(len(rig)):
            bit = getbit(i, j)
            if bit == 0:
                continue
            if getbit(mask1, rig[j]) == 1:
                val = (val * INV[rig[j]])
            if getbit(mask2, rig[j]) == 1:
                val = (val * COMP[rig[j]])
        desire = (target * (val ** -1))
        if desire in dic.keys():
            print("OK!")
            final_mask = dic[desire] + (1 << len(lef)) * i
            for j in range(len(d_search)):
                d_val[d_search[j]] = getbit(final_mask, j)
            return
    return


t = 0
for i in tqdm(range(query_rem)):
    for j in range(i+1, query_rem):
        if bitcount(res[i][0] ^ res[j][0]) < THRESHOLD:
            work(res[i][0], res[i][1], res[j][0], res[j][1])
            t |= (res[i][0] ^ res[j][0])


undetermined = []
for i in range(128):
    if d_val[i] == -1:
        undetermined.append(i)
l = len(undetermined)

d_final = 0
for i in range(1 << l):
    for j in range(l):
        d_val[undetermined[j]] = ((i >> j) & 1)
    d = 0
    for j in range(128):
        d += d_val[j] * (1 << j)
    isok = True
    for j in range(query_rem):
        if pow(2, d ^ res[j][0], n) != res[j][1]:
            isok = False 
    if isok:
        d_final = d
        print("d found!")

for i in range(20):
    for j in range(i+1, 20):
        actual_exp1 = d_final ^ c_results[i][0]
        actual_exp2 = d_final ^ c_results[j][0]
        if GCD(actual_exp1, actual_exp2) == 1:
            print("OK, exists pair to do GCD stuff")
            u = inverse(actual_exp1, actual_exp2)
            v = (actual_exp1 * u - 1) // actual_exp2 
            # c_res[i][1]^u * c_res[j][1]^-v = c
            ptxt = pow(c_results[i][1], u * d_final, n)
            ptxt = ptxt * inverse(pow(c_results[j][1], v * d, n), n)
            ptxt = ptxt % n 
            print("FLAG", long_to_bytes(int(ptxt)))
