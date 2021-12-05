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

conn = remote('crc.hackable.software' , 1337)
conn.sendline(b"My crc64 is 0x7a8abd9a85eed3b9! Cool, isn't it?")
print(conn.recvline())

def crc64(buf, crc=0xffffffffffffffff):
    for val in buf:
        crc ^= val << 56
        for _ in range(8):
            crc <<= 1
            if crc & 2**64:
                crc ^= 0x1ad93d23594c935a9
    return crc

def arrayfy(x):
    arr = []
    for i in range(63, -1, -1):
        arr.append((x >> i) & 1)
    arr = vector(GF(2), arr)
    return arr

def dearrayfy(x):
    ret = 0
    for i in range(0, 64):
        ret += int(x[i]) * (1 << (63 - i))
    return ret 

inp = b'My crc64 is 0x6b12c5691a7caa5a! Cool, isn\'t it?'
crc = crc64(inp)

print(f'My crc64 is 0x{crc:016x}! Cool, isn\'t it?'.encode())

if inp == f'My crc64 is 0x{crc:016x}! Cool, isn\'t it?'.encode():
    print("HEY?")
else:
    print('Nope!')

M1 = []
L1 = ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9']
M2 = []
L2 = ['a', 'b', 'c', 'e', 'f']

base = b"My crc64 is 0x" + b"\x00" * 16 + b"! Cool, isn\'t it?"
START = crc64(base)

for i in range(16):
    vals = []
    for c in L1:
        modified = b"My crc64 is 0x" + b"\x00" * i + c.encode() + b"\x00" * (15 - i) + b"! Cool, isn\'t it?"
        diff = arrayfy(START ^ crc64(modified))
        vals.append(diff)
    add = vals[0]
    add_1 = vals[1] + vals[0]
    add_2 = vals[2] + vals[0]
    add_4 = vals[4] + vals[0]
    add_8 = vals[8] + vals[0]
    M = Matrix(GF(2), [add_8, add_4, add_2, add_1])
    M = M.transpose()
    M1.append([M, add])

for i in range(16):
    vals = [0] * 16
    for c in L2:
        modified = b"My crc64 is 0x" + b"\x00" * i + c.encode() + b"\x00" * (15 - i) + b"! Cool, isn\'t it?"
        diff = arrayfy(START ^ crc64(modified))
        vals[ord(c) - ord('a') + 10] = diff
    add_1 = vals[10] + vals[11]
    add_2 = vals[12] + vals[14]
    add_4 = vals[10] + vals[14]
    add_8 = vals[10] + add_2 
    assert vals[10] == add_2 + add_8
    assert vals[11] == add_1 + add_2 + add_8 
    assert vals[12] == add_4 + add_8 
    assert vals[14] == add_2 + add_4 + add_8 
    assert vals[15] == add_1 + add_2 + add_4 + add_8
    add = vector(GF(2), [0] * 64)
    M = Matrix(GF(2), [add_8, add_4, add_2, add_1])
    M = M.transpose()
    M2.append([M, add])


def solve_attempt(v):
    modified = b"My crc64 is 0x"
    for i in range(16):
        if v[i] != 2:
            modified += b"\x00"
        if v[i] == 2:
            modified += b"d" 
    modified += b"! Cool, isn\'t it?"
    val = arrayfy(crc64(modified))
    for i in range(16):
        if v[i] == 0:
            val += M1[i][1]
    target = [0] * 64
    for i in range(16):
        if v[i] == 2:
            target[4 * i] = 1
            target[4 * i + 1] = 1
            target[4 * i + 2] = 0
            target[4 * i + 3] = 1
    target = vector(GF(2), target)
    corr = [0] * 16
    cnt = 0
    for i in range(16):
        if v[i] != 2:
            corr[cnt] = i
            cnt += 1
    app = []
    for i in range(16):
        if v[i] == 0:
            app.append(M1[i][0])
        if v[i] == 1:
            app.append(M2[i][0])
    MM = block_matrix(GF(2), 1, cnt, app)
    for i in range(cnt):
        for j in range(4):
            MM[4 * corr[i] + j, 4 * i + j] -= 1
    try:
        fin_target = val + target 
        vvv = MM.solve_right(fin_target)
        df = MM.right_kernel().basis()
        l = len(df)
        for i in range(1 << l):
            cur = vvv
            isok = True
            for j in range(l):
                if ((i >> j) & 1) == 1:
                    cur += df[j]
            sol = b""
            nxt = 0
            for j in range(16):
                if nxt < cnt and corr[nxt] == j:
                    vv = int(cur[4 * nxt]) * 8 + int(cur[4 * nxt + 1]) * 4 + int(cur[4 * nxt + 2]) * 2 + int(cur[4 * nxt + 3])
                    if 0 <= vv <= 9:
                        sol += str(vv).encode()
                    if 10 <= vv <= 15:
                        sol += chr(vv + 87).encode()
                    if v[corr[nxt]] == 0 and (vv >= 10):
                        isok = False
                    if v[corr[nxt]] == 1 and (vv <= 9 or vv == 13):
                        isok = False
                    nxt += 1
                    if isok == False:
                        break
                else:
                    sol += b"d" 
            if isok == False:
                continue
            print(sol)
            print(cur)
            print(MM * cur + val + target)
            print(cnt)
            if isok:
                inp = b"My crc64 is 0x" + sol + b"! Cool, isn\'t it?"
                crc = crc64(inp)
                if inp == f'My crc64 is 0x{crc:016x}! Cool, isn\'t it?'.encode():
                    print("FOUND")
                    print(inp)
                    exit()
    except:
        pass


def calc_single_crc(dat):
    actual_sol = b"My crc64 is 0x"
    actual_target = 0
    for i in range(16):
        actual_target = 16 * actual_target + dat[i]
        if 0 <= dat[i] <= 9:
            actual_sol += str(dat[i]).encode()
        else:
            actual_sol += chr(dat[i] + 87).encode()
    actual_sol += b"! Cool, isn\'t it?"
    print("calc arg", actual_sol)
    print("actual crc", crc64(actual_sol))
    print("actual target", actual_target)
    modified = b"My crc64 is 0x"
    v = [0] * 16
    for i in range(16):
        if dat[i] <= 9:
            v[i] = 0
        elif dat[i] == 13:
            v[i] = 2
        else:
            v[i] = 1
    for i in range(16):
        if v[i] != 2:
            modified += b"\x00"
        if v[i] == 2:
            modified += b"d" 
    modified += b"! Cool, isn\'t it?"
    val = arrayfy(crc64(modified))
    for i in range(16):
        if v[i] == 0:
            val += M1[i][1]
    target = [0] * 64
    for i in range(16):
        if v[i] == 2:
            target[4 * i] = 1
            target[4 * i + 1] = 1
            target[4 * i + 2] = 0
            target[4 * i + 3] = 1
    target = vector(GF(2), target)
    corr = [0] * 16
    vec = []
    cnt = 0
    for i in range(16):
        if v[i] != 2:
            corr[cnt] = i
            vec.append((dat[i] >> 3) & 1)
            vec.append((dat[i] >> 2) & 1)
            vec.append((dat[i] >> 1) & 1)
            vec.append((dat[i] >> 0) & 1)
            cnt += 1
    vec = vector(GF(2), vec)
    app = []
    for i in range(16):
        if v[i] == 0:
            app.append(M1[i][0])
        if v[i] == 1:
            app.append(M2[i][0])
    MM = block_matrix(GF(2), 1, cnt, app)
    adv = Matrix(GF(2), 64, 4 * cnt)
    for i in range(cnt):
        for j in range(4):
            adv[4 * corr[i] + j, 4 * i + j] += 1
    CRC_result = MM * vec + val
    true_target = adv * vec + target
    CRC_result = dearrayfy(CRC_result)
    true_target = dearrayfy(true_target)
    print("computed crc", CRC_result)
    print("target", true_target)

    assert actual_target == true_target 
    assert crc64(actual_sol) == CRC_result


'''
for i in range(256):
    tt = [rand.randint(0, 15) for _ in range(16)]
    calc_single_crc(tt)
'''

        
for v in tqdm(itertools.product(range(2), repeat = 16)):
    v = list(v)
    solve_attempt(v)


for v in tqdm(itertools.product(range(2), repeat = 15)):
    v = list(v) + [2]
    for i in range(16):
        solve_attempt(v)
        v = v[1:] + v[:1]

for v in tqdm(itertools.product(range(2), repeat = 14)):
    for i in range(16):
        for j in range(i+1, 16):
            cc = [0] * 16
            cc[i] = 2
            cc[j] = 2
            cnt = 0
            for k in range(16):
                if k != i and k != j:
                    cc[k] = v[cnt]
                    cnt += 1
            solve_attempt(cc)
'''
inp = 0
if inp == f'My crc64 is 0x{crc:016x}! Cool, isn\'t it?'.encode():
    with open('flag.txt', 'r') as f:
        print(f.read().strip())
else:
    print('Nope!')
    '''