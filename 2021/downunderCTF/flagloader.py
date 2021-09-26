from Crypto.Cipher import AES, PKCS1_OAEP, PKCS1_v1_5
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad, unpad
from Crypto.Util.number import inverse, long_to_bytes, bytes_to_long, isPrime, getPrime
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
from Crypto.Hash import SHA3_256, HMAC, BLAKE2s
from sage.modules.free_module_integer import IntegerLattice
from Crypto.Cipher import AES, ARC4, DES

r = remote('pwn-2021.duc.tf', 31919)

def solve1():
    for i in range(1, 256, 2):
        for j in range(2, 256, 2):
            res = b''
            res += bytes([0x44 ^ i])
            res += bytes([0x55 ^ j])
            res += bytes([0x43 ^ (256 - j)])
            res += bytes([0x54 ^ (256 - i)])
            res += bytes([0x46])

            mul = 120
            mul = (mul * res[0] * res[1] * res[2] * res[3] * res[4]) % 256
            if mul == 16:
                r.send(res)
                return

solve1()

g = int(r.recvline().split()[-1])
print(g)
x = (1 << 15) + (1 << 31)
y = g - (1 << 15) + (1 << 31)
r.sendline((str(x) + " " + str(y)).encode())


g = int(r.recvline().split()[-1])
print(g)
x2 = g // 5 - 128
x3 = g // 5 
x4 = g // 5 + 256
x5 = g // 5 + 256 + 256
x1 = g - x2 - x3 - x4 - x5
r.sendline((str(x1) + " " + str(x2) + " " + str(x3) + " " + str(x4) + " " + str(x5)).encode())

print(r.recvline())
print(r.recvline())
print(r.recvline())