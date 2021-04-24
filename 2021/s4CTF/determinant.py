from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad, unpad
from Crypto.Util.number import inverse, long_to_bytes, bytes_to_long, isPrime, getPrime
from tqdm import tqdm
from pwn import *
from sage.all import *
import sys, json, hashlib, os, math, time, base64, binascii, string, re, struct, datetime
import random as rand
from os import urandom
import multiprocessing as mp

def get_sol1(x, t):
    for i in divisors(x):
        if i > t:
            return i, x // i

def get_sol2(A, B, t):
    x = inverse(A, B) + (t + 150) * abs(B)
    y = (A * x - 1) // B 
    return x, y

def solve(AR, cnt, t):
    if cnt == 1:
        if AR[0] == None:
            AR[0] = (AR[1] * AR[2] + 1) // AR[3]
            return AR
        if AR[1] == None:
            AR[1] = (AR[0] * AR[3] - 1) // AR[2]
            return AR
        if AR[2] == None:
            AR[2] = (AR[0] * AR[3] - 1) // AR[1]
            return AR
        if AR[3] == None:
            AR[3] = (AR[1] * AR[2] + 1) // AR[0]
            return AR
    
    if cnt == 2:
        if AR[0] == None and AR[3] == None:
            AR[0], AR[3] = get_sol1(AR[1] * AR[2] + 1, t)
            return AR
        if AR[1] == None and AR[2] == None:
            AR[1], AR[2] = get_sol1(AR[0] * AR[3] - 1, t)
            return AR
        ss, tt = -1, -1
        for i in [0, 3]:
            if AR[i] == None:
                ss = i
        for i in [1, 2]:
            if AR[i] == None:
                tt = i
        AR[ss], AR[tt] = get_sol2(AR[3-ss], AR[3-tt], t)
        return AR
    
    if cnt == 3:
        for i in range(4):
            if AR[i] != None:
                vv = 3000 * t + 150000
                for u in range(4000):
                    vv += 1
                    if GCD(vv, AR[i]) == 1:
                        AR[i ^ 1] = vv
                        ans = solve(AR, 2, t)
                        return ans

def nature(x):
    if x[0] == '\'':
        return None
    return int(x) 

r = remote('157.90.231.113', 2570)
for i in range(0, 6):
    r.recvline()

for i in range(0, 2000):
    s = r.recvline().decode().strip()
    t = int(r.recvline().strip().split()[-1].decode())
    ST = s.split(',')
    VAR = []
    VAR.append(ST[0][ST[0].find('[') + 2 : ])
    VAR.append(ST[1][1:-1])
    VAR.append(ST[2][2:])
    VAR.append(ST[3][1:-2])
    AR = []
    for tt in range(4):
        AR.append(nature(VAR[tt]))
    PV = copy(AR)
    cnt = 0
    for tt in range(4):
        if AR[tt] == None:
            cnt += 1
    TT = solve(AR, cnt, t)
    res = [-5] * 3
    for tt in range(4):
        if PV[tt] == None:
            res[ord(VAR[tt][1]) - ord('x')] = TT[tt]
    ret = ''
    for tt in range(3):
        if res[tt] != -5:
            ret += str(res[tt]) 
            ret += ", "
    ret = ret[:-2]
    r.sendline(ret)
    print(r.recvline())