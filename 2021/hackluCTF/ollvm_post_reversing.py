from Crypto.Cipher import AES, PKCS1_OAEP, PKCS1_v1_5
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad, unpad
from Crypto.Util.number import inverse, long_to_bytes, bytes_to_long, isPrime, getPrime, getRandomRange
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

def tester(inp):
    buf = [0] * 24
    buf[3] = inp
    buf[2] = buf[3] + 0x4ddb14ee5c8771c5
    buf[2] = buf[2] % (1 << 64)
    buf[4] = 0xb31c9545ac410d72
    buf[5] = (buf[2] ^ buf[4]) + 0x8bc715d20d923835
    buf[5] = buf[5] % (1 << 64)
    buf[6] = 0xce9a20c53746a9f7
    buf[7] = ((buf[5] ^ buf[6]) << 0x20) % (1 << 64)
    buf[8] = (buf[5] ^ buf[6]) >> 0x20
    buf[9] = buf[7] + buf[8]
    buf[10] = 0xa648bd40dace4ef5
    buf[11] = (buf[9] * buf[10]) % (1 << 64)
    buf[12] = (buf[11] + 0x18B205A73CB902B7) % (1 << 64)
    buf[13] = 0x8
    buf[14] = buf[12] >> buf[13]
    buf[15] = ((buf[12] << 0x38) | buf[14]) % (1 << 64)
    buf[16] = 0x29D5CA44D143B4FC
    buf[17] = ((0x326DEB9C5D995AEB ^ buf[15]) + buf[16]) % (1 << 64)
    buf[18] = buf[17] >> 0x8
    buf[19] = buf[18] & 0xff00ff00ff00ff
    buf[20] = 0x8
    buf[21] = (buf[17] << buf[20]) & 0xff00ff00ff00ff00
    buf[22] = buf[19] | buf[21]
    buf[23] = 0xb9b8a788569d772d
    buf[0] = (1 << 64) - ((buf[22] ^ buf[23]) * 0x51f6d71704b266f5) % (1 << 64)
    return buf

def solve(buf0):
    buf = [0] * 24
    buf[0] = buf0
    nbf0 = (1 << 64) - buf[0] 
    # this is (buf[22] ^ buf[23]) * 0x51f6d71704b266f5
    d = inverse(0x51f6d71704b266f5, 1 << 64)
    target = (nbf0 * d) % (1 << 64)
    buf[23] = 0xb9b8a788569d772d
    buf[22] = target ^ buf[23]
    # buf[22] = buf[19] | buf[21]
    # = (buf[17] >> 8) & 0xff00ff00ff00ff
    # | (buf[17] << 8) & 0xff00ff00ff00ff00

    res1 = buf[22] & 0xff00ff00ff00ff
    res2 = buf[22] & 0xff00ff00ff00ff00
    buf[17] = ((res1 << 8) | (res2 >> 8)) % (1 << 64)
    buf[18] = buf[17] >> 0x8
    buf[19] = buf[18] & 0xff00ff00ff00ff
    buf[20] = 0x8
    buf[21] = (buf[17] << buf[20]) & 0xff00ff00ff00ff00
    assert (buf[19] | buf[21]) == buf[22]

    buf[16] = 0x29D5CA44D143B4FC
    # buf[17] = (0x326DEB9C5D995AEB ^ buf[15]) + buf[16]
    buf[15] = ((buf[17] - buf[16] + (1 << 64)) % (1 << 64)) ^ 0x326DEB9C5D995AEB
    '''
    buf[12] = buf[11] + 0x18B205A73CB902B7
    0x67afa0 -> 46b1f0 : buf[13] = 0x8
    0x67ae60 -> 461da0 : buf[14] = buf[12] >> buf[13]
    0x67a408 -> 4195f0 : buf[15] = (buf[12] << 0x38) | buf[14]
    '''
    # buf[15] = (buf[12] << 56) + (buf[12] >> 8)
    res1 = buf[15] // (1 << 56)
    res2 = buf[15] % (1 << 56)
    buf[12] = res1 + (res2 << 8)
    buf[13] = 0x8
    buf[14] = buf[12] >> buf[13]

    buf[11] = (buf[12] - 0x18B205A73CB902B7 + (1 << 64)) % (1 << 64)
    buf[10] = 0xa648bd40dace4ef5

    buf[9] = (buf[11] * inverse(buf[10], 1 << 64)) % (1 << 64)

    buf[6] = 0xce9a20c53746a9f7

    '''
    buf[7] = (buf[5] ^ buf[6]) << 0x20
    buf[8] = (buf[5] ^ buf[6]) >> 0x20
    '''

    cc = (buf[9] >> 32) % (1 << 64) + (buf[9] << 32) % (1 << 64)
    buf[5] = cc ^ buf[6]
    buf[7] = ((buf[5] ^ buf[6]) << 0x20) % (1 << 64)
    buf[8] = (buf[5] ^ buf[6]) >> 0x20

    buf[4] = 0xb31c9545ac410d72 
    buf[2] = ((buf[5] - 0x8bc715d20d923835 + (1 << 64)) % (1 << 64)) ^ buf[4]

    buf[3] = (buf[2] - 0x4ddb14ee5c8771c5 + (1 << 64)) % (1 << 64)

    return long_to_bytes(buf[3])


ret = b''
ret += solve(0x875cd4f2e18f8fc4)
ret += solve(0xbb093e17e5d3fa42)
ret += solve(0xada5dd034aae16b4)
ret += solve(0x97322728fea51225)
ret += solve(0x4124799d72188d0d) 
ret += solve(0x2b3e3fbbb4d44981) 
ret += solve(0xdfcac668321e4daa) 
ret += solve(0xeac2137a35c8923a)

print(ret)