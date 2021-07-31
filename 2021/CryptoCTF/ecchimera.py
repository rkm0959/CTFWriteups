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


n = 43216667049953267964807040003094883441902922285265979216983383601881964164181
U = 18230294945466842193029464818176109628473414458693455272527849780121431872221
V = 13100009444194791894141652184719316024656527520759416974806280188465496030062
W = 5543957019331266247602346710470760261172306141315670694208966786894467019982
p = 227316839687407660649258155239617355023
q = 190116434441822299465355144611018694747

'''

factorize n by computing point's order

GF(p) -> order = p + 1 => MOV attack, but do it partially (for easy primes only)
GF(q) -> order = q => SMART attack

=> combine with CRT, find one with full ascii

'''

nq = 35886536999264548257653961517736633452
np = 9092500866606561

res = 10214219295529808

md = res * q

st = crt(np, nq, res, q)

def is_ascii(s):
	return all(c < 128 for c in s)

for i in tqdm(range(80000000)):
    flag = long_to_bytes(st)
    if is_ascii(flag):
        print(flag)
    st += md

