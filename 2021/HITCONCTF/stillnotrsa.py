from Crypto.Cipher import AES, PKCS1_OAEP, PKCS1_v1_5
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad, unpad
from Crypto.Util import Counter
from Crypto.Util.number import inverse, long_to_bytes, bytes_to_long, isPrime, getPrime, getRandomRange, sieve_base
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

POL = PolynomialRing(ZZ, 'x')
x = POL.gen()

n, q = 167, 128

def list_to_pol(l):
    ret = 0
    for i in range(len(l)):
        ret += l[i] * (x ** i)
    return ret

def randomdpoly(d1, d2):
    result = d1 * [1] + d2 * [-1] + (n - d1 - d2) * [0]
    rand.shuffle(result)
    return list_to_pol(result)

def convolution(f, g):
    return (f * g) % ((x ** n) - 1)

def balancedmod(f, q):
    coefs = f.coefficients(sparse=False)
    while len(coefs) < n:
        coefs.append(0)
    g = list(((coefs[i] + q//2) % q) - q//2 for i in range(n))
    return list_to_pol(g)

def invertmodprime(f,p):
    T = POL.change_ring(Integers(p)).quotient((x ** n) - 1)
    return POL(lift(1 / T(f)))

def invertmodpowerof2(f,q):
    g = invertmodprime(f,2)
    while True:
        r = balancedmod(convolution(g, f), q)
        if r == 1: return g
        g = balancedmod(convolution(g, 2 - r), q)

def keypair():
    while True:
        try:
            f = randomdpoly(61, 60)
            f3 = invertmodprime(f,3)
            fq = invertmodpowerof2(f,q)
            break
        except Exception as e:
            pass
    g = randomdpoly(15, 15)
    publickey = balancedmod(3 * convolution(fq,g),q)
    secretkey = f
    return publickey, secretkey, g

def encode(val):
    poly = 0
    for i in range(n):
        poly += ((val%3)-1) * (x ** i)
        val //= 3
    return poly

def decode(val):
    coefs = val.coefficients(sparse=False)
    ret = 0
    for i in range(len(coefs)):
        ret += (int(coefs[i]) + 1) * (3 ** i)
    return ret 

def decrypt(ciphertext, secretkey):
    f = secretkey
    f3 = invertmodprime(f,3)
    a = balancedmod(convolution(ciphertext, f), q)
    return balancedmod(convolution(a, f3), 3)


def encrypt(message, publickey):
    r = randomdpoly(18, 18)
    return balancedmod(convolution(publickey,r) + encode(message), q)

def parse_poly(pol_string):
    pol_string = pol_string.split()
    sign = 1
    pol = 0 
    for token in pol_string:
        if token == "+":
            sign = 1
            continue
        if token == "-":
            sign = -1
            continue
        coef = 1
        if "*" in token:
            coef = int(token.split("*")[0])
        elif "-" in token:
            coef = -1
        deg = 0
        if "x" in token:
            deg = 1
        if "^" in token:
            deg = int(token.split("^")[1])
        if deg == 0:
            coef = int(token)
        pol += sign * coef * (x ** deg)
    return pol

def send_prep(pol):
    coefs = pol.coefficients(sparse=False)
    ret = 0
    for i in range(len(coefs)):
        ret += int(int(coefs[i]) % q) * (q ** i)
    return ret 

def calc_inv(pol):
    coefs = pol.coefficients(sparse = False)
    while len(coefs) < n:
        coefs.append(0)
    M = Matrix(GF(3), n, n)
    for i in range(n):
        for j in range(n):
            M[i, j] = coefs[(i - j) % n] 
    vec = [1] + [0] * (n - 1)
    vec = vector(GF(3), vec)
    L = M.solve_right(vec)
    res = 0
    for i in range(n):
        res += int(L[i]) * (x ** i)
    return res

cnt = 0
NUM = 1000
REMOTE = True
pubkey = None
seckey = None 

if REMOTE == False: 
    flag = b"hitcon{testflagforthis}"
    flag += (16 - len(flag) % 16) * b'\x00'

while True:
    cnt += 1
    print("trial :", cnt)

    if REMOTE:
        conn = remote('54.92.57.54', 31337)
        iv = bytes.fromhex(conn.recvline().split()[-1].decode())
        flag_enc = bytes.fromhex(conn.recvline().split()[-1].decode())
        pol_string = conn.recvline().decode()
        pubkey = parse_poly(pol_string)
    else:
        iv = os.urandom(16)
        pubkey, seckey, g = keypair()
        keykey = hashlib.sha256(str(seckey).encode()).digest()
        flag_enc = AES.new(key = keykey, mode = AES.MODE_CBC, iv = iv).encrypt(flag)

    for _ in tqdm(range(NUM)):
        ctxt = 0
        U = rand.sample(range(n), 3)
        V = rand.sample(range(n), 3)
        pol_1 = 0
        pol_2 = 0
        for deg in U:
            pol_1 += (x ** deg)
        for deg in V:
            pol_2 += (x ** deg)
        ctxt = balancedmod(convolution(4 * pubkey, pol_1) + 12 * pol_2, 128) 
        enc = send_prep(ctxt)

        if REMOTE:
            val = binascii.hexlify(long_to_bytes(enc))
            conn.sendline(val)
            pol_recv_string = conn.recvline().decode()
            pol_recv = parse_poly(pol_recv_string)
            dec = decode(pol_recv)
        else:
            dec = decode(decrypt(ctxt, seckey))

        if dec != 0:
            try:
                inv = calc_inv(encode(dec))
                if REMOTE == True:
                    for i in range(n):
                        for j in [-1, 1]:
                            act_key = balancedmod(convolution(inv, j * (x ** i)), 3)
                            key = hashlib.sha256(str(act_key).encode()).digest()
                            ff = AES.new(key, AES.MODE_CBC, iv).decrypt(flag_enc)
                            if b"hitcon" in ff:
                                print(ff)
                if REMOTE == False:
                    for i in range(n):
                        for j in [-1, 1]:
                            act_key = balancedmod(convolution(inv, j * (x ** i)), 3)
                            if decode(act_key) == decode(seckey):
                                print("OK!")
                                key = hashlib.sha256(str(act_key).encode()).digest()
                                ff = AES.new(key, AES.MODE_CBC, iv).decrypt(flag_enc)
                                print(ff)
            except ZeroDivisionError:
                pass
            except ValueError:
                pass