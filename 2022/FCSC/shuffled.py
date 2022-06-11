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

res = "f668cf029d2dc4234394e3f7a8S9f15f626Cc257Ce64}2dcd93323933d2{F1a1cd29db"
res_list = list(res)

for i in range(256):
    init = [t for t in range(len(res))]
    rand.seed(i)
    rand.shuffle(init)
    unshuffled = [''] * len(res)
    for j in range(len(res)):
        unshuffled[init[j]] = res_list[j]
    flag = ''.join(unshuffled)
    if "FCSC{" in flag:
        print(flag)


