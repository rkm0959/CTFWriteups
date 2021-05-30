from Crypto.Cipher import AES, PKCS1_OAEP, PKCS1_v1_5
from Crypto.PublicKey import RSA
from Crypto.Util.number import inverse, long_to_bytes, bytes_to_long, isPrime, getPrime
from tqdm import tqdm
from pwn import *
from sage.all import *
import sys, json, hashlib, os, math, time, base64, binascii, string, re, struct, datetime, subprocess
import random as rand
import multiprocessing as mp

r = remote('oh-anna-julia.pwn2win.party', '1337')

def readmenu():
    for i in range(7):
        r.recvline()

def createkey():
    readmenu()
    r.sendline("1")
    r.recvline()

def createsecret(s):
    readmenu()
    assert len(s) == 40
    r.sendline("2")
    r.recvline()
    r.send(s)

def showdata():
    readmenu()
    r.sendline("3")
    r.recvline()
    q = int(r.recvline().decode().split()[-1])
    r.recvline()
    r.recvline()
    return q

def encrypt(idx):
    readmenu()
    r.sendline("4")
    r.recvline()
    r.sendline(str(idx))
    s = r.recvline().decode().strip().split()
    A = int(s[3][1:-1])
    B = int(s[4][:-1])
    return A, B

for i in range(2):
    r.recvline()

for i in range(4):
    createkey()

createsecret(b"\x00" * 40)

q = showdata()

df = [0] * 256
for i in range(256):
    df[i] = i - (255 ^ i)

RES = {}
cur = 1
for i in range(256 * 50):
    RES[cur] = i
    cur = (cur * 2) % q

def getsum():
    TOTA, TOTB = 1, 1
    for i in tqdm(range(1, 41)):
        A, B = encrypt(i)
        TOTA = (TOTA * A) % q
        TOTB = (TOTB * B) % q
    v = (TOTA * inverse(TOTB, q)) % q
    assert v in RES
    return RES[v]

org = getsum()
ans = ''

for i in range(1, 41):
    sec = b"\x00" * (i - 1) + b"\xff" + b"\x00" * (40 - i)
    createsecret(sec)
    vv = getsum()
    dif = org - vv
    idx = df.index(dif)
    ans += chr(idx)
    print(ans)

print(ans)