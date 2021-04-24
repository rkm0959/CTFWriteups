from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Util.number import inverse, long_to_bytes, bytes_to_long, isPrime, getPrime
from tqdm import tqdm
from pwn import *
from sage.all import *
import sys, json, hashlib, os, math, time, base64, binascii, string, re, struct, datetime
import random as rand
import multiprocessing as mp
import numpy as np

r = remote('198.211.127.76', 3580)

p = getPrime(1024)

for i in range(6):
    print(r.recvline())

for i in range(400):
    r.recvline()
    s = r.recvline().strip().decode()
    n = s.count(',') + 1
    print(n)
    print(s)
    mat = [[0] * n for _ in range(n)]
    for j in range(n):
        if j != 0:
            s = r.recvline().strip().decode()
            print(s)
        for k in range(n):
            mat[j][k] = ord(s[1 + 3 * k]) - ord('0')
    for j in range(n):
        for k in range(n):
            assert mat[j][k] == mat[k][j]
        mat[j][j] = 0
    act = [[0] * n for _ in range(n)]
    for j in range(n):
        deg = 0
        for k in range(n):
            if mat[j][k] == 1:
                act[j][k] = -1
                deg += 1
        act[j][j] = deg
    TT = [[0] * (n-1) for _ in range(n-1)]
    for i in range(n-1):
        for j in range(n-1):
            TT[i][j] = act[i][j]
    M = Matrix(ZZ, TT)
    print(r.recvline())
    tt = abs(int(M.determinant()))
    r.sendline(str(tt)) 
    print(tt)
    print(r.recvline())
