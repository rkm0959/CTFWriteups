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

p = 103286641759600285797850797617629977324547405479993669860676630672349238970323
c1 = 39515350190224022595423324336682561295008443386321945222926612155252852069385
c2 = 102036897442608703406754776248651511553323754723619976410650252804157884591552

F = GF(p)
E = EllipticCurve(F, [1, 2])
n = E.order()
e = 0x10001

def decrypt(enc, key):
    org_x = int(enc) ^ int(key)
    P = E.lift_x(Integer(org_x))
    G = inverse(e, n) * P
    message = int(G.xy()[0])
    return long_to_bytes(message)

print(decrypt(c1, 0)) # CHTB{Counting_points_w

# if it works on isomorphic curve, why not itself?
key = -F(1728) * (F(4) ** 3) / F(E.discriminant())

print(decrypt(c2, key))


