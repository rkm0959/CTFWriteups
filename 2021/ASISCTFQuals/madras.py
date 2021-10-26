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
from ecdsa import ecdsa
from Crypto.Hash import SHA3_256, HMAC, BLAKE2s
from Crypto.Cipher import AES, ARC4, DES

abc = 4553352994596121904719118095314305574744898996748617662645730434291671964711800262656927311612741715902
bca = 4414187148384348278031172865715942397786003125047353436418952679980677617016484927045195450392723110402
cab = 2621331497797998680087841425011881226283342008022511638116013676175393387095787512291008541271355772802
enca = 1235691098253903868470929520042453631250042769029968
encb = 2235727505835415157472856687960365216626058343546572
encc = 1197976933648163722609601772402895844093866589777721
enc = 6238548897897912462708514382106387305984378113132192980353695746912882399991285268937548949835500837749446265632471076030233510866260067177632747513323223


nm = (enc - enca) * (enc - encb) * (enc - encc)

a = GCD(pow(2, abc-cab, nm) - 1, nm)
b = GCD(pow(2, abc-bca, nm) - 1, nm)
c = GCD(pow(2, bca-cab, nm) - 1, nm)

print(int(a).bit_length())
print(int(b).bit_length())
print(int(c).bit_length())

for i in range(2, 1500):
    while a % i == 0:
        a = a // i
    while b % i == 0:
        b = b // i
    while c % i == 0:
        c = c // i

phi = (a - 1) * (b - 1) * (c - 1)

ans = pow(enc, inverse(65537, phi), a * b * c)

print(long_to_bytes(int(ans)))