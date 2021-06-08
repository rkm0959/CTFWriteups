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


r = remote('crypto.zh3r0.cf', 1111)

r.recvlines(6)

# level 1
ans = ['68656c6c6f20776f726c6421204c6574732067657420676f696e67', '4e6f7468696e672066616e63792c206a757374207374616e646172642062797465735f746f5f696e74']
ans.append('6d6f6e6f20737562737469747574696f6e73206172656e742074686174206372656174697665')
ans.append('6372656174696e6720646966666572656e7420737562737469747574696f6e7320666f7220656163682063686172')

for x in ans:
    print(long_to_bytes(int(x, 16)))
cur = 0
while True:
    cc = r.recvline().strip()
    print(cc)
    level = int(cc.decode().split()[1][0], 16)
    target = int(cc.decode().split()[-1], 16)
    if cur < len(ans):
        r.recvuntil("flag\n")
        r.sendline("2")
        r.sendline(ans[cur])
        print(r.recvline())
        cur += 1
        continue
    if level == 1:
        print(hex(target))
        L = 1
        R = (16 ** len(hex(target)))
        best = 0
        while L <= R:
            mid = (L + R) >> 1
            query = long_to_bytes(mid).hex()
            print(query)
            r.recvuntil("flag\n")
            r.sendline("1")
            r.recvuntil("hex:")
            r.sendline(query)
            val = int(r.recvline().strip().decode().split()[-1], 16)
            if val == target:
                r.recvuntil("flag\n")
                r.sendline("2")
                r.sendline(query)
                print(r.recvline())
                break
            if val < target:
                L = mid + 1
            if val > target:
                R = mid - 1
    if level == 2:
        rec = [0] * 256
        for i in tqdm(range(256)):
            r.recvuntil("flag\n")
            r.sendline("1")
            r.recvuntil("hex:")
            query = bytes([i])
            query = query.hex()
            r.sendline(query)
            val = int(r.recvline().strip().decode().split()[-1], 16)
            rec[val] = i
        cc = b''
        tt = long_to_bytes(target)
        for i in range(len(tt)):
            cc += bytes([rec[tt[i]]])
        cc = cc.hex()
        r.recvuntil("flag\n")
        r.sendline("2")
        r.sendline(cc)
        print(cc)
        print(r.recvline())
        continue
    if level == 3:
        tt = long_to_bytes(target)
        L = len(tt)
        res = [[0] * 256 for _ in range(L)]
        for i in tqdm(range(256)):
            r.recvuntil("flag\n")
            r.sendline("1")
            r.recvuntil("hex:")
            query = bytes([i]) * L
            query = query.hex()
            r.sendline(query)
            val = int(r.recvline().strip().decode().split()[-1], 16)
            val = long_to_bytes(val)
            val = b'\x00' * (L - len(val)) + val
            for j in range(L):
                res[j][val[j]] = i
        print(res)
        cc = b''
        for i in range(L):
            cc += bytes([res[i][tt[i]]])
        cc = cc.hex()
        r.recvuntil("flag\n")
        r.sendline("2")
        r.sendline(cc)
        print(cc)
        print(r.recvline())
        continue
    if level == 4:
        r.interactive()


            


