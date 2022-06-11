from Crypto.Cipher import AES, PKCS1_OAEP, PKCS1_v1_5
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad, unpad
from Crypto.Util import Counter
from Crypto.Util.number import getStrongPrime, inverse, long_to_bytes, bytes_to_long, isPrime, getPrime, getRandomRange, sieve_base
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
from mt19937predictor import MT19937Predictor
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes

result = "070a4a5811dd013c301f30070924528796cb8fe8ddd6d8851f90ab1a8977e9c71accbed0a5936414445739ce76763002fd29337834c8976fef36decdc522a6b93c967c90d0e69e46674d634ba5a9badbd834bad8042515029b6fa833c98da0a7"
result = bytes.fromhex(result)

N = 16
M = 1 << 128

iv = bytes_to_long(result[:16])

for _ in range(31337):
    val = iv % 2
    for j in range(1, 128):
        res = (iv - (2 * val * val + val)) >> j
        if res % 2 == 1:
            val += (1 << j)
    iv = val 

key = iv 

cipher = AES.new(long_to_bytes(key), AES.MODE_CBC, iv = result[:16])
print(cipher.decrypt(result[16:]))







