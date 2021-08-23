from Crypto.Cipher import AES, PKCS1_OAEP, PKCS1_v1_5
from Crypto.PublicKey import RSA
from Crypto.Util.number import inverse, long_to_bytes, bytes_to_long, isPrime, getPrime, GCD
from tqdm import tqdm
from pwn import *
from sage.all import *
import gmpy2, pickle, itertools, sys, json, hashlib, os, math, time, base64, binascii, string, re, struct, datetime, subprocess
import numpy as np
import random as rand
import multiprocessing as mp
from base64 import b64encode, b64decode
from sage.modules.free_module_integer import IntegerLattice
from ecdsa import ecdsa
import requests
import scipy.stats
import matplotlib.pyplot as plt

p = (1 << 192) - (1 << 64) - 1
a = p - 3
b = 0x64210519E59C80E70FA7E9AB72243049FEB8DEECC146B9B1

E = EllipticCurve(GF(p), [a, b])
n = E.order()

Gx = 0x188DA80EB03090F67CBF20EB43A18800F4FF0AFD82FF1012
Gy = 0x07192B95FFC8DA78631011ED6B24CDD573F977A11E794811

G = E(Gx, Gy)

def int_to_bytes(x):
    return x.to_bytes((x.bit_length() + 7) // 8, 'big')

def base32_encode(x):
    # 48 * 5 = 240 bits
    cc = ""
    B = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
    ret = ""
    for i in range(30):
        cc += "{0:08b}".format(x[i])
    for i in range(0, 240, 5):
        tt = int(cc[i:i+5], 2)
        ret += B[tt]
        if i % 40 == 35 and i != 235:
            ret += "-"
    return ret

def base32_decode(x):
    B = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
    b = ""
    for i in x:
        b += "{0:05b}".format(B.find(i))
    return int_to_bytes(int(b, 2))

def verify(dgst, sig, PK):
    z = bytes_to_long(dgst)
    r, s = sig
    u_1 = (z * inverse(s, n)) % n
    u_2 = (r * inverse(s, n)) % n
    # print(u_1, u_2)
    GG = u_1 * G + u_2 * PK
    cc = int(GG.xy()[0])
    assert cc == r


# k1 = base32_decode("BHAWBGQ5-MB4IUR5V-26YFXZSW-MSHEVTDN-GZB4ED2N-KDHX7A5I".replace("-", ""))
# k1 = base32_decode("BJUWBPYH-MCVFRYIZ-ZV45N5EU-D5HL6K6H-6N4VCS6X-BIUQSUTR".replace("-", ""))
u11, u12 = 6208018712665992685317371884848654579228254089530446391244, 3901371225190145511686010375115837075071144129982529625516
u21, u22 = 2861418786602039821386694068852808988532492969716540836428, 5623577365242345842961574633168820564776518525420727533800

'''
30 byte result 

first 6 bytes : digested to dgst
next 24 bytes : buf -> part of the signature

'''

# for checking key
# assert(k1[0] ^ k1[7] == k1[28] and k1[1] ^ k1[3] == k1[12])

buf = b""

'''
B = b"0123456789ABCDEF"
for i in k1[6:]:
    buf += bytes([B[i >> 4]])
    buf += bytes([B[i & 0xF]])
'''

x = 4910017285067243285659645658183706496882752243738091681795
y = 894613538273475752824630788065081050497548342550540448591
PK = E(x, y)
target = 4295308421698895742407195884872675142566054683881561619252
dlog = 1325031087835349138965290766193329882829064869944584756462

r = 5241427081939067204984227503904086701023032271828334909509

# for checking key
# s = int(buf, 16)

assert u11 * G + u12 * PK == u21 * G + u22 * PK
assert PK == dlog * G
assert int((target * G).xy()[0]) == r

trial = 0
tsp = 1629129600
iv = inverse(target, n)
rdlog = (r * dlog) % n 
cnt = 0

while True:
    tsp += 3600
    for i in range(256):
        for j in range(256):
            k1 = bytes([i]) + bytes([j]) + long_to_bytes(tsp)
            dgst = hashlib.sha1(bytes(k1[:6])).digest()

            s = ((bytes_to_long(dgst) + rdlog) * iv) % n 
            s_bytes = long_to_bytes(s, blocksize = 24)
            k1 += s_bytes

            if k1[0] ^ k1[7] != k1[28] or k1[1] ^ k1[3] != k1[12]:
                continue
          
            hsh = hashlib.sha256(k1[:30]).digest()
            xor = [0x9C, 0xA2, 0x53, 0xC7, 0xC9, 0xBA, 0xA7, 0x7A, 0x2F, 0x93, 0xE5, 0xB1, 0xC2, 0xAD, 0xE8, 0x01, 0x0F, 0x2B, 0xE4, 0x5F, 0x9E, 0xCA, 0xA8, 0x9A, 0xA4, 0xAB, 0xC9, 0x53, 0x58, 0x30, 0xF2, 0x95]
            ans = []
            for i in range(32):
                ans.append(hsh[i] ^ xor[i])
            ans = bytes(ans)
            if ans[:4] == b"SCTF":
                print(ans)