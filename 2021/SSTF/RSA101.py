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

r = remote('rsa101.sstf.site', 1104)

r.recvline()

n = int(r.recvline().split()[-1].decode(), 16)

print(n)

e = int(r.recvline().split()[-1].decode(), 16)

print(e)

for i in range(6):
    print(r.recvline())

target = b"cat flag"

workaround = (bytes_to_long(target) * (2 ** e)) % n
workaround = long_to_bytes(workaround)

sender = b64encode(workaround)

r.sendline(b"2")

r.sendline(sender)

cc = r.recvline().split()[-1]


signed = b64decode(cc)

print("signed" , signed)

val = bytes_to_long(signed)

fin = (val * inverse(2, n)) % n

for i in range(6):
    print(r.recvline())

r.sendline(b"1")


fin = b64encode(long_to_bytes(fin))

r.sendline(fin)

print(r.recvline())
print(r.recvline())