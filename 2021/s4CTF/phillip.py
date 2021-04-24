from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Util.number import inverse, long_to_bytes, bytes_to_long, isPrime, getPrime
from tqdm import tqdm
from pwn import *
from sage.all import *
import sys, json, hashlib, os, math, time, base64, binascii, string, re, struct, datetime
import random as rand
import multiprocessing as mp

r = remote('157.90.231.113', 9999)
for i in range(0, 12):
    print(r.recvline())

r.sendline('g')
s = r.recvline() 
print(s)
n = int(s.split()[3][1:-1].decode())
print(n)
m1 = 2 
m2 = pow(2, n+1, n*n)

for i in range(7):
    r.recvline()
r.sendline('r')
print(r.recvline())
r.sendline(str(m1))
print(r.recvline())
r.sendline(str(m2))
print(r.recvline())
