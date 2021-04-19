from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad, unpad
from Crypto.Util.number import inverse, long_to_bytes, bytes_to_long, isPrime, getPrime
from tqdm import tqdm
from pwn import *
from sage.all import *
import sys, json, hashlib, os, math, time, base64, binascii, string, re, struct, datetime
import random as rand
from os import urandom
import multiprocessing as mp
from Crypto.Util import Counter
from subprocess import call 


def find_sol(args):
    START, TARGET, RANGE = args
    for i in range(RANGE[0], RANGE[1]):
        v = START + "".join(rand.choices(string.ascii_letters, k=6))
        if hashlib.sha1(v.encode()).hexdigest()[:len(TARGET)] == TARGET:
            return v
    return None

def PoW(NUM, START, TARGET):
    batch = 30000
    pool = mp.Pool(NUM)
    nonce = 0
    while True:
        nonce_range = [(nonce + i * batch, nonce + i * batch + batch) for i in range(NUM)]
        params = [(START, TARGET, RANGE) for RANGE in nonce_range]
        solutions = pool.map(find_sol, params)
        solutions = list(filter(None, solutions))
        if len(solutions) != 0:
            return solutions[0]
        nonce += batch * NUM

F = GF(2 ** 128, 'x')
P = PolynomialRing(F, 'y')
y = P.gen()

def calc_ans(args):
    enc_iv, tag, rag = args
    F = GF(2 ** 128, 'x')
    for cand in rag:
        enc_iv = enc_iv[:-1] + cand
        TAG = F.fetch_int(tag)
        T = F.fetch_int(int(enc_iv, 16))
        CC = T / TAG
        N = (1 << 128) - 1
        if (CC ** (N // 255)) == F.fetch_int(1):
            return cand
    return None

def get_ans(enc_iv, tag):
    print(enc_iv, tag)
    pool = mp.Pool(12)
    rag = ['0', '1', '2', '3', '4', '5', '6', '7', '89', 'ab', 'cd', 'ef']
    params = [(enc_iv, tag, whi) for whi in rag]
    for result in pool.imap_unordered(calc_ans, params):
        if result != None:
            return result


F = GF(2 ** 128, 'x')
P = PolynomialRing(F, 'y')
y = P.gen()

C = 255
attempt = 0

def xor(a, b):
    return bytes(x^y for x,y in zip(a,b))

while True:
    attempt += 1
    r = remote('leaky.pwni.ng', 1337)
    s = r.recvline().strip().decode()
    print("PoW")

    tt = PoW(12, "0:0:" + s + ":", "00000")
    r.sendline(tt)

    print("Solve", attempt)
    print(r.recvline())
    print(r.recvline())
    print(r.recvline())


    ST = '0123456789abcdef'
    fail = False

    for ffff in range(20):
        print(ffff)
        iv = r.recvline().strip()
        iv = iv.split()[-1].decode()
        iv = bytes.fromhex(iv)
        ivi = int.from_bytes(iv, 'big')
        data = b''
        for i in range(C):
            cntr = (ivi + i + 1) % (1 << 128)
            cntr = cntr.to_bytes(16, byteorder = 'big')
            data += xor(cntr, iv)
        r.sendline(data.hex())
        s = r.recvline()
        tag = s.strip().split()[-1].decode()
        tag = int(tag, 16)
        r.recvline()
        r.recvline()
        enc_iv = r.recvline().strip().split()[-1].decode()
        ans = get_ans(enc_iv, tag)        
        r.sendline(ans)
        s = r.recvline()
        print(s)
        if b"Sorry" in s or b"Killed" in s:
            fail = True
            break
    if fail == True:
        continue

    s = r.recvline()
    while True:
        print(s)

