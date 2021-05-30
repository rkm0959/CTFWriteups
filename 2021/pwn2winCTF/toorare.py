from Crypto.Cipher import AES, PKCS1_OAEP, PKCS1_v1_5
from Crypto.PublicKey import RSA
from Crypto.Util.number import inverse, long_to_bytes, bytes_to_long, isPrime, getPrime
from tqdm import tqdm
from pwn import *
from sage.all import *
import itertools, sys, json, hashlib, os, math, time, base64, binascii, string, re, struct, datetime, subprocess
import numpy as np
import random as rand
import multiprocessing as mp


p = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
a = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC
b = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
E = EllipticCurve(GF(p), [a, b])
G = E(0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296,
      0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5)

q1 = 2 * 2 * 2 * 2 * 3 * 71 * 131 * 373 * 3407
q2 = 17449 * 38189 * 187019741 * 622491383 * 1002328039319 * 2624747550333869278416773953
q = int(next_prime(q1*q2))
N = 115792089210356248762697446949407573529996955224135760342422259061068512044369
assert q == q1 * q2 + 1

r = remote('t00-rare.pwn2win.party', 1337)

# RFC 6979 section 2.3.2
def bits2int(b, q):
  res = int.from_bytes(b, 'big')
  blen = res.bit_length() 
  qlen = q.bit_length()
  return res >> (blen - qlen) if qlen < blen else res


# RFC 6979 section 2.3.3
def int2octets(x, q):
  rlen = ceil(q.bit_length()/8)
  return int(x % q).to_bytes(rlen, 'big')


# RFC 6979 section 3.2
def generate_k(hash_func, h, q, x, kp = b""):
  qlen = q.bit_length()//8
  hlen = hash_func().digest_size

  v = b"\x01" * hlen
  k = b"\x00" * hlen
  dgst = hmac.new(k, digestmod=hash_func)
  to_hash = v + b"\x00" + int2octets(x, q) + int2octets(h, q)
  to_hash += kp # Additional data described per variant at section 3.6 (k')
  dgst.update(to_hash)
  k = dgst.digest()

  v = hmac.new(k, v, hash_func).digest()
  dgst = hmac.new(k, digestmod=hash_func)
  to_hash = v + b"\x01" + int2octets(x, q) + int2octets(h, q)
  to_hash += kp # Additional data described per variant at section 3.6 (k')
  dgst.update(to_hash)
  k = dgst.digest()

  v = hmac.new(k, v, hash_func).digest()
  while True:
    t = b""
    while len(t) < qlen:
      v = hmac.new(k, v, hash_func).digest()
      t += v
    k = bits2int(t, q)

    if 1 <= k < q:
      return k

    k = hmac.new(k, v + b"\x00", hash_func).digest()
    v = hmac.new(k, v, hash_func).digest()

def do_Pow():
    s = r.recvline().split()[-1].decode()
    r.recvline()
    result = subprocess.run(['hashcash', '-mb25', s], stdout = subprocess.PIPE)
    tt = result.stdout.split()[-1]
    r.sendline(tt)
    r.recvline()
    r.recvline()
    print("Pow Done")

def readmenu():
    for i in range(5):
        r.recvline()

def get_signature(h):
    readmenu()
    r.sendline("1")
    r.sendline(hex(h)[2:])
    r.recvline()
    s = r.recvline().strip().decode().split()
    print(s)
    X = int(s[0][1:-1])
    Y = int(s[1][:-1])
    print(X, Y)
    return X, Y
    
def readflag(h):
    readmenu()
    r.sendline("3")
    r.sendline(str(h))
    HASH = int(r.recvline().strip().split()[-1][:-3], 16)
    print(r.recvline())
    return HASH


do_Pow()


h = 100
rr, ss = get_signature(h)


BLOCK = 800000


# r, (h + rx) / k
# ks = h + rx
# k = h/s + r/s x
# kG = (h/s) G + (r/s) (xG)
# U - (h/s) G 

U = E.lift_x(GF(p)(rr))
V = int(q - (h * inverse(ss, q) % q)) * G
Target = U + V
Target = int((ss * inverse(rr, q)) % q) * Target

# Target = x G
g = int(pow(7, q2, q))

f = open("fuck.txt", "r")

RES = {}
for i in tqdm(range(900000)):
    s = f.readline()
    a, b = s.split()
    a = int(a)
    b = int(b)
    assert b == i
    RES[a] = b

'''
def calc_1(args):
    idx, g, q, G = args
    ret = []
    st = pow(g, idx * 75000, q)
    TT = st * G
    for i in range(idx * 75000, idx * 75000 + 75000):
        if i % 1000 == 0:
            print(i)
        ret.append((TT.xy()[0], i))
        TT = g * TT
    return ret

cc = 1

NUM = 12
pool = mp.Pool(NUM)
params = [(i, g, q, G) for i in range(NUM)]
sols = pool.map(calc_1, params)

f = open("fuck.txt", "w")
RES = {}
for i in range(NUM):
    for a, b in sols[i]:
        f.write(str(int(a)) + " " + str(b) + "\n")
        RES[a] = b

f.close()

TARGET = g^(x + y) G
g^-x TARGET = g^y G

'''

def calc_2(args):
    idx, Target, q, jmp, RES = args
    # Target * (jmp^idx)
    st = pow(jmp, idx * 75000, q)
    TT = st * Target
    for i in range(idx * 75000, idx * 75000 + 75000):
        if i % 1000 == 0:
            print(i)
        if int(TT.xy()[0]) in RES:
            tt = i * 800000 + RES[int(TT.xy()[0])]
            print("HEY!!")
            return tt
        TT = jmp * TT
    return None

NUM = 12
pool = mp.Pool(NUM)
jmp = inverse(pow(g, BLOCK, q), q)
params = [(i, Target, q, jmp, RES) for i in range(NUM)]
sols = pool.imap_unordered(calc_2, params)

x = -1
for res in sols:
    if res != None:
        x = pow(g, res, q)
        break

print(x)
print(x * G)
print(Target)

HASH = readflag(100)
h = HASH + q
rr, ss = get_signature(h)

# ks = h + rx

k = ((h + rr * x) * inverse(ss, q)) % q
cc = inverse(k, q)

GG = readflag(cc)
GG = readflag(q - cc)

k = ((h + rr * (q-x)) * inverse(ss, q)) % q
cc = inverse(k, q)

GG = readflag(cc)
GG = readflag(q - cc)