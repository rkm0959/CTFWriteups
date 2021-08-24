
from Crypto.Cipher import AES, PKCS1_OAEP, PKCS1_v1_5
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad
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


def genkey():
    e = 0x10001
    p, q = getPrime(256), getPrime(256)
    if p <= q:
      p, q = q, p
    n = p * q
    pubkey = (e, n)
    privkey = (p, q)
    return pubkey, privkey

def encrypt(m, pubkey):
    e, n = pubkey
    c = pow(m, e, n)
    return c


def get_params():
    m = bytes_to_long(b"sampleflag{samplesampleflag}")
    pubkey, privkey = genkey()
    c = encrypt(m, pubkey)
    hint = pubkey[1] % (privkey[1] - 1)
    return pubkey, hint, c

pubkey, hint, c = get_params()

# hint = n % (p - 1)
e, n = pubkey

gg = pow(2, hint, n) - pow(2, n, n)
p = GCD(gg, n)
q = n // p
phi = (p-1) * (q-1)

d = inverse(e, phi)

print(long_to_bytes(pow(c, d, n)))