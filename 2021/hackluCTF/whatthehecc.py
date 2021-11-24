from Crypto.Cipher import AES, PKCS1_OAEP, PKCS1_v1_5
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad, unpad
from Crypto.Util.number import inverse, long_to_bytes, bytes_to_long, isPrime, getPrime, getRandomRange
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

'''
sig = (R, s)
s * G - Q + R = hash(msg) * G
'''

'''
hash(msg) * G + hash(z) * G, (d - hash(z))
'''

def hsh(msg):
    return bytes_to_long(hashlib.sha3_256(msg).digest())

conn = remote('flu.xxx', 20085)
print(conn.recvline())
conn.sendline(b"sign")
print(conn.recvline())
conn.sendline(b"id")

sig = conn.recvline().split()[-1].split(b'|')

x = int(sig[0])
y = int(sig[1])
s = int(sig[2])
cmd = sig[3]

p = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
a = p - 3
b = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B

Gx = 0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296 
Gy = 0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5

E = EllipticCurve(GF(p), [a, b])
G = E(Gx, Gy)
V = E(x, y)

Q = s * G + V - hsh(cmd) * G

'''
s * G - Q + R = hash(msg) * G
'''

s = 3
V = hsh(b"cat flag") * G + Q - s * G
x = int(V.xy()[0])
y = int(V.xy()[1])
cmd = b"cat flag"

send = str(x).encode() + b"|" + str(y).encode() + b"|" + str(s).encode() + b"|" + cmd

print(conn.recvline())
conn.sendline("run")
print(conn.recvline())
conn.sendline(send)
print(conn.recvline())
