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


ALPHABET = string.printable[:62] + '\\='

FIELD = GF(64)

F = list(FIELD)

def maptofarm(c):
	assert c in ALPHABET
	return F[ALPHABET.index(c)]


enc = '805c9GMYuD5RefTmabUNfS9N9YrkwbAbdZE0df91uCEytcoy9FDSbZ8Ay8jj'

for i in range(1, 64):
    u = FIELD.fetch_int(i)
    pkey = (u ** 5) + (u ** 3) + (u ** 2) + 1
    if pkey == FIELD(0):
        continue
    pkey = pkey ** (-1) 
    res = ''
    for m in enc:
        res += ALPHABET[F.index(pkey * maptofarm(m))]
    try:
        msg = b64decode(res)
        print(msg)
    except:
        pass

