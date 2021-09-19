from Crypto.Cipher import AES, PKCS1_OAEP, PKCS1_v1_5
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad
from Crypto.Util.number import inverse, long_to_bytes, bytes_to_long, isPrime, getPrime
from sympy.matrices.matrices import num_mat_mul
from tqdm import tqdm
from pwn import *
from sage.all import *
from sympy import *
import gmpy2, pickle, itertools, sys, json, hashlib, os, math, time, base64, binascii, string, re, struct, datetime, subprocess
import numpy as np
import random as rand
import multiprocessing as mp
from base64 import b64encode, b64decode
from sage.modules.free_module_integer import IntegerLattice
from ecdsa import ecdsa
from Crypto.Hash import SHA3_256, HMAC, BLAKE2s
from sage.modules.free_module_integer import IntegerLattice

length = 723
n = 30004084769852356813752671105440339608383648259855991408799224369989221653141334011858388637782175392790629156827256797420595802457583565986882788667881921499468599322171673433298609987641468458633972069634856384101309327514278697390639738321868622386439249269795058985584353709739777081110979765232599757976759602245965314332404529910828253037394397471102918877473504943490285635862702543408002577628022054766664695619542702081689509713681170425764579507127909155563775027797744930354455708003402706090094588522963730499563711811899945647475596034599946875728770617584380135377604299815872040514361551864698426189453
e = 65537

f = open("chal.py","rb")
inp = f.read()
f.close()

f = open("chal.enc", "rb")
outp = f.read()
f.close()

data = []
e = 65537

for i in range(0, 768, 256):
    cc = inp[i:i+256]
    if len(cc) < 256:
        cc = pad(cc, 256)
    res = bytes_to_long(cc) ^ bytes_to_long(outp[i:i+256])
    data.append([res, e])
    e = nextprime(e)

u = inverse(65537, 65539)
v = (65537 * u - 1) // 65539

m = (pow(data[0][0], u, n) * inverse(pow(data[1][0], v, n), n)) % n

print(long_to_bytes(m))    