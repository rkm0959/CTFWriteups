from Crypto.Cipher import AES, PKCS1_OAEP, PKCS1_v1_5
from Crypto.PublicKey import RSA
from Crypto.Util.number import inverse, long_to_bytes, bytes_to_long, isPrime, getPrime
from tqdm import tqdm
from pwn import *
# from sage.all import *
import itertools, sys, json, hashlib, os, math, time, base64, binascii, string, re, struct, datetime, subprocess
import numpy as np
import random
import multiprocessing as mp

r = remote('crypto.zh3r0.cf', 3333)
FLAG = '6df3c292a9bc9631060d10aeed218275c1169332a5814c2727d866c9d3d756c1c7c2573ff09aee9b068e5067d61838485e4e38a36c8b80572fade43bbbed749edbe0b9589e6acb14208962bfe6a7ddc1bd44176f268a6732583cda45fedbda12bf69217385c36f8f8589cf69b3bcc807cc4dddf0af65adbb73134940d1957912'
FLAG = bytes.fromhex(FLAG)

seed_1 = 3351946939
np.random.seed(seed_1)
iv, key = np.random.bytes(16), np.random.bytes(16)
cipher = AES.new(key, iv = iv, mode = AES.MODE_CBC)
print(iv == FLAG[:16])
FLAG = cipher.decrypt(FLAG[16:])

seed_2 = 2869927714
np.random.seed(seed_2)
iv, key = np.random.bytes(16), np.random.bytes(16)
cipher = AES.new(key, iv = iv, mode = AES.MODE_CBC)
print(iv == FLAG[:16])
FLAG = cipher.decrypt(FLAG[16:])
print(FLAG)

exit()

def find_sol(args):
    TARGET, RANGE = args
    for i in tqdm(range(RANGE[0], RANGE[1])):
        np.random.seed(i)
        if np.random.bytes(16) == TARGET:
            return i
    return None 

NUM = 12
batch = 3 * (10 ** 6)
pool = mp.Pool(NUM)
nonce = 0
while True:
    nonce_range = [(nonce + i * batch, nonce + i * batch + batch) for i in range(NUM)]
    params = [(FLAG[:16], RANGE) for RANGE in nonce_range]
    solutions = pool.map(find_sol, params)
    solutions = list(filter(None, solutions))
    print("Checked", nonce + batch * NUM)
    if len(solutions) != 0:
        while True:
            print(solutions[0])
            exit()
    nonce += batch * NUM
