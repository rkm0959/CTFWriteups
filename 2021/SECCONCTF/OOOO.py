from Crypto.Cipher import AES, PKCS1_OAEP, PKCS1_v1_5
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad, unpad
from Crypto.Util import Counter
from Crypto.Util.number import inverse, long_to_bytes, bytes_to_long, isPrime, getPrime, getRandomRange, sieve_base
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

from z3 import *

# https://github.com/jhs7jhs/LLL/tree/master/low-density-attack

def inthroot(a, n):
    return a.nth_root(n, truncate_mode=True)[0]

class HighDensityException(Exception):
    pass


class CJLOSSAttack:

    def __init__(self, array, target_sum, try_on_high_density=False):
        self.array = array
        self.n = len(self.array)
        self.target_sum = target_sum
        self.density = self._calc_density()
        self.try_on_high_density = try_on_high_density

    def _calc_density(self):
        return self.n / log(max(self.array), 2)

    def _check_ans(self, ans):
        calc_sum = sum(map(lambda x: x[0] * x[1], zip(self.array, ans)))
        return self.target_sum == calc_sum

    def solve(self):
        if self.density >= 0.9408 and not self.try_on_high_density:
            raise HighDensityException()

        # 1. Initialize Lattice
        L = Matrix(ZZ, self.n + 1, self.n + 1)
        N = inthroot(Integer(self.n), 2) // 2
        for i in range(self.n + 1):
            for j in range(self.n + 1):
                if j == self.n and i < self.n:
                    L[i, j] = 2 * N * self.array[i]
                elif j == self.n:
                    L[i, j] = 2 * N * self.target_sum
                elif i == j:
                    L[i, j] = 2
                elif i == self.n:
                    L[i, j] = 1
                else:
                    L[i, j] = 0

        # 2. LLL!
        B = L.LLL()

        # 3. Find answer
        for i in range(self.n + 1):
            if B[i, self.n] != 0:
                continue

            if all(v == -1 or v == 1 for v in B[i][:self.n]):
                ans = [ (-B[i, j] + 1) // 2 for j in range(self.n)]
                if self._check_ans(ans):
                    return ans

        # Failed to find answer
        return None

conn = remote('oooooo.quals.seccon.jp', 8000)

REMOTE = True

if REMOTE:
    M = int(conn.recvline().split()[-1])
    S = int(conn.recvline().split()[-1])
    conn.recvline()
else:
    message = b""
    for _ in range(128):
        message += b"o" if rand.getrandbits(1) == 1 else b"O"
    print(message)

    M = getPrime(len(message) * 5)
    S = bytes_to_long(message) % M

base = 0
for i in range(128):
    base += 79 * (256 ** i)


sums = ((S - base) * inverse(32, M)) % M

arr = [(256 ** i) % M for i in range(128)]
target_sum = sums

st = time.time()

for i in tqdm(range(128)):
    attack = CJLOSSAttack(arr, target_sum + i * M, True)
    res = attack.solve()
    if res != None:
        msg = ""
        for i in range(128):
            if res[i] == 0:
                msg += "O"
            else:
                msg += "o"
        msg = msg[::-1]
        conn.sendline(msg.encode())
        print(conn.recvline())


en = time.time()

print(en - st)



