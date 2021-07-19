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


import argparse
import pwnlib
import challenge_pb2
import struct
import sys

def handle_pow(tube):
    raise NotImplemented()

def read_message(tube, typ):
    n = struct.unpack('<L', tube.recvnb(4))[0]
    buf = tube.recvnb(n)
    msg = typ()
    msg.ParseFromString(buf)
    return msg

def write_message(tube, msg):
    buf = msg.SerializeToString()
    tube.send(struct.pack('<L', len(buf)))
    tube.send(buf)


p256 = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
a256 = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC
b256 = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
X256 = 0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296
Y256 = 0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5

E = EllipticCurve(GF(p256), [a256, b256])
G = E(X256, Y256)
n = E.order()

def get_z(msg):
    h = hashlib.sha1(msg)
    return bytes_to_long(h.digest())

def checker(Point, h, r, s):
    u1 = (h * inverse(s, n)) % n
    u2 = (r * inverse(s, n)) % n
    F = int(u1) * G + int(u2) * Point
    assert int(F.xy()[0]) % n == r % n

def work():
    tube = pwnlib.tubes.remote.remote("tonality.2021.ctfcompetition.com", 1337)
    print(tube.recvuntil('== proof-of-work: '))
    if tube.recvline().startswith(b'enabled'):
        handle_pow(tube)

    # Step 1: Hello.
    hello = read_message(tube, challenge_pb2.HelloResponse)
    m0 = hello.message0.encode()
    m1 = hello.message1.encode()
    pubx = bytes_to_long(hello.pubkey.x)
    puby = bytes_to_long(hello.pubkey.y)
    z0 = get_z(m0)
    z1 = get_z(m1)

    P = E(pubx, puby)
    
    # Step 2: Sign.
    a = int((z0 * inverse(z1, n)) % n)
    sign_req = challenge_pb2.SignRequest()
    sign_req.scalar = a.to_bytes((a.bit_length() + 7) // 8, 'big')
    write_message(tube, sign_req)

    sign_res = read_message(tube, challenge_pb2.SignResponse)
    r = bytes_to_long(sign_res.message0_sig.r)
    s = bytes_to_long(sign_res.message0_sig.s)

    checker(a * P, get_z(m0), r, s)

    # Step 3: Verify.
    verify_req = challenge_pb2.VerifyRequest()
    verify_req.message1_sig.r = long_to_bytes(r)
    verify_req.message1_sig.s = long_to_bytes((z1 * s * inverse(z0, n)) % n)
    write_message(tube, verify_req)

    verify_res = read_message(tube, challenge_pb2.VerifyResponse)
    print(verify_res)

work()