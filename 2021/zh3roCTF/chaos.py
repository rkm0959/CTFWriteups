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

def ROTL(value, bits, size=32):
    return ((value % (1 << (size - bits))) << bits) | (value >> (size - bits))

def ROTR(value, bits, size=32):
    return ((value % (1 << bits)) << (size - bits)) | (value >> bits)


def pad(pt):
    pt+=b'\x80'
    L = len(pt)
    to_pad = 60-(L%64) if L%64 <= 60 else 124-(L%64)
    padding = bytearray(to_pad) + int.to_bytes(L-1,4,'big')
    return pt+padding

def hash(text:bytes):
    text = pad(text)
    text = [int.from_bytes(text[i:i+4],'big') for i in range(0,len(text),4)]
    M = 0xffff
    x,y,z,u = 0x0124fdce, 0x89ab57ea, 0xba89370a, 0xfedc45ef
    A,B,C,D = 0x401ab257, 0xb7cd34e1, 0x76b3a27c, 0xf13c3adf
    RV1,RV2,RV3,RV4 = 0xe12f23cd, 0xc5ab6789, 0xf1234567, 0x9a8bc7ef
    for i in range(0,len(text),4):
        X,Y,Z,U = text[i]^x,text[i+1]^y,text[i+2]^z,text[i+3]^u
        RV1 ^= (x := (X&0xffff)*(M - (Y>>16)) ^ ROTL(Z,1) ^ ROTR(U,1) ^ A)
        RV2 ^= (y := (Y&0xffff)*(M - (Z>>16)) ^ ROTL(U,2) ^ ROTR(X,2) ^ B)
        RV3 ^= (z := (Z&0xffff)*(M - (U>>16)) ^ ROTL(X,3) ^ ROTR(Y,3) ^ C)
        RV4 ^= (u := (U&0xffff)*(M - (X>>16)) ^ ROTL(Y,4) ^ ROTR(Z,4) ^ D)
    return int.to_bytes( (RV1<<96)|(RV2<<64)|(RV3<<32)|RV4 ,16,'big')

x,y,z,u = 0x0124fdce, 0x89ab57ea, 0xba89370a, 0xfedc45ef
A,B,C,D = 0x401ab257, 0xb7cd34e1, 0x76b3a27c, 0xf13c3adf
tt = long_to_bytes(x) + long_to_bytes(y) + long_to_bytes(z) + long_to_bytes(u)
cc = long_to_bytes(A) + long_to_bytes(B) + long_to_bytes(C) + long_to_bytes(D)

M = 0xffff
msg1 = b''
X, Y, Z, U = 0, 0, 0, 0
x,y,z,u = 0x0124fdce, 0x89ab57ea, 0xba89370a, 0xfedc45ef

for i in range(0, 4):
    msg1 += long_to_bytes(x ^ X) + long_to_bytes(y ^ Y) + long_to_bytes(z ^ Z) + long_to_bytes(u ^ U)
    x = (X&0xffff)*(M - (Y>>16)) ^ ROTL(Z,1) ^ ROTR(U,1) ^ A
    y =  (Y&0xffff)*(M - (Z>>16)) ^ ROTL(U,2) ^ ROTR(X,2) ^ B
    z = (Z&0xffff)*(M - (U>>16)) ^ ROTL(X,3) ^ ROTR(Y,3) ^ C
    u= (U&0xffff)*(M - (X>>16)) ^ ROTL(Y,4) ^ ROTR(Z,4) ^ D
    print(x, y, z, u)

print(msg1)
print(len(msg1))
print(hash(msg1))

msg2 = b''
X, Y, Z, U = 1, 1, 1, 1
x,y,z,u = 0x0124fdce, 0x89ab57ea, 0xba89370a, 0xfedc45ef


for i in range(0, 4):
    msg2 += long_to_bytes(x ^ X) + long_to_bytes(y ^ Y) + long_to_bytes(z ^ Z) + long_to_bytes(u ^ U)
    x = (X&0xffff)*(M - (Y>>16)) ^ ROTL(Z,1) ^ ROTR(U,1) ^ A
    y =  (Y&0xffff)*(M - (Z>>16)) ^ ROTL(U,2) ^ ROTR(X,2) ^ B
    z = (Z&0xffff)*(M - (U>>16)) ^ ROTL(X,3) ^ ROTR(Y,3) ^ C
    u= (U&0xffff)*(M - (X>>16)) ^ ROTL(Y,4) ^ ROTR(Z,4) ^ D
    if i == 1:
        X, Y, Z, U = 0, 0, 0, 0

print(msg2)
print(len(msg2))
print(hash(msg2))

r = remote('crypto.zh3r0.cf', 2222)

r.sendline(msg1.hex())
r.sendline(msg2.hex())

print(r.recvline())
print(r.recvline())
print(r.recvline())