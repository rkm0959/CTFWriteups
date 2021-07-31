from Crypto.Cipher import AES, PKCS1_OAEP, PKCS1_v1_5
from Crypto.PublicKey import RSA
from Crypto.Util.number import inverse, long_to_bytes, bytes_to_long, isPrime, getPrime, GCD
from tqdm import tqdm
from pwn import *
from sage.all import *
import itertools, sys, json, hashlib, os, math, time, base64, binascii, string, re, struct, datetime, subprocess
import numpy as np
import random as rand
import multiprocessing as mp
from base64 import b64encode, b64decode
from sage.modules.free_module_integer import IntegerLattice
from ecdsa import ecdsa

r = remote('07.cr.yp.toc.tf', 31010)


def read_lines(num = 5):
    for _ in range(num):
        r.recvline()

def get_params():
    read_lines()
    r.sendline("E")
    p = int(r.recvline().split()[-1])
    u = int(r.recvline().split()[-1])
    v = int(r.recvline().split()[-1])
    w = int(r.recvline().split()[-1])
    return p, u, v, w

def get_flagenc():
    read_lines()
    r.sendline("S")
    s = r.recvline()
    ca = int(s.split()[-3][1:-1])
    cb = int(s.split()[-2][:-1])
    cc = int(s.split()[-1][:-1])
    return ca, cb, cc

def get_enc(m):
    read_lines()
    r.sendline("T")
    r.recvline()
    res = long_to_bytes(m)
    r.sendline(res)
    s = r.recvline()
    ca = int(s.split()[-3][1:-1])
    cb = int(s.split()[-2][:-1])
    cc = int(s.split()[-1][:-1])
    return ca, cb, cc

read_lines()

p, u, v, w = get_params()

x = GF(p)(w).log(GF(p)(u))
rr = GF(p)(v).log(GF(p)(u))

ca, cb, cc = get_flagenc()

wr = pow(ca, x, p)
wb = pow(cb, (x * inverse(rr, p-1)), p)

m = cc * inverse(int(wr * wb), p)

m = m % p 

print(long_to_bytes(m))
