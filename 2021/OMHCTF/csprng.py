from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Util.number import inverse, long_to_bytes, bytes_to_long, isPrime, getPrime
from tqdm import tqdm
from pwn import *
from sage.all import *
import sys, json, hashlib, os, math, time, base64, binascii, string, re, struct, datetime
import random as rand
import multiprocessing as mp

r = remote('csprng.zajebistyc.tf', 17006)

p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
E = EllipticCurve(GF(p), [0, 7])
X = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
Y = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
G = E(X, Y)

def TALK(V):
    r.sendline("1")
    print(r.recvline())
    s = r.recvline()
    s = r.recvline()
    VV = bytes.fromhex(s.split()[-1].decode().strip()[:2])
    pubkey = int(s.split()[-1].decode().strip()[2:], 16)
    P = E.lift_x(GF(p)(pubkey))
    r.sendline(V)
    RES = r.recvline().split()[-1].decode().strip()
    print(r.recvline())
    return RES

def FLAG():
    r.sendline("2")
    print(r.recvline())
    r.sendline('y')
    print(r.recvline())
    print(r.recvline())
    print(r.recvline())
    print(r.recvline())
    print(r.recvline())
    print(r.recvline())
    print(r.recvline())
    T = r.recvline().strip().decode()
    print(r.recvline())
    V = r.recvline().strip().decode()
    print(r.recvline())
    print(r.recvline())
    print(r.recvline())
    print(r.recvline())
    print(r.recvline())
    return T, V



print(r.recvline())
print(r.recvline())
print(r.recvline())
T, V = FLAG()

print(r.recvline())
print(r.recvline())
RES = TALK(V)

A = int(T, 16)
B = int(RES, 16)

print(long_to_bytes(A ^ B))
