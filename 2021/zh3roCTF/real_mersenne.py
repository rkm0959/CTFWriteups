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

# http://www.secmem.org/blog/2021/05/18/breaking-python-random-module/
class Twister:
    N = 624
    M = 397
    A = 0x9908b0df

    def __init__(self):
        self.state = [ [ (1 << (32 * i + (31 - j))) for j in range(32) ] for i in range(624)]
        self.index = 0
    
    @staticmethod
    def _xor(a, b):
        return [x ^ y for x, y in zip(a, b)]
    
    @staticmethod
    def _and(a, x):
        return [ v if (x >> (31 - i)) & 1 else 0 for i, v in enumerate(a) ]
    
    @staticmethod
    def _shiftr(a, x):
        return [0] * x + a[:-x]
    
    @staticmethod
    def _shiftl(a, x):
        return a[x:] + [0] * x

    def get32bits(self):
        if self.index >= self.N:
            for kk in range(self.N):
                y = self.state[kk][:1] + self.state[(kk + 1) % self.N][1:]
                z = [ y[-1] if (self.A >> (31 - i)) & 1 else 0 for i in range(32) ]
                self.state[kk] = self._xor(self.state[(kk + self.M) % self.N], self._shiftr(y, 1))
                self.state[kk] = self._xor(self.state[kk], z)
            self.index = 0

        y = self.state[self.index]
        y = self._xor(y, self._shiftr(y, 11))
        y = self._xor(y, self._and(self._shiftl(y, 7), 0x9d2c5680))
        y = self._xor(y, self._and(self._shiftl(y, 15), 0xefc60000))
        y = self._xor(y, self._shiftr(y, 18))
        self.index += 1

        return y
    
    def getrandbits(self, bit):
        return self.get32bits()[:bit]

class Solver:
    def __init__(self):
        self.equations = []
        self.outputs = []
    
    def insert(self, equation, output):
        for eq, o in zip(self.equations, self.outputs):
            lsb = eq & -eq
            if equation & lsb:
                equation ^= eq
                output ^= o
        
        if equation == 0:
            return

        lsb = equation & -equation
        for i in range(len(self.equations)):
            if self.equations[i] & lsb:
                self.equations[i] ^= equation
                self.outputs[i] ^= output
    
        self.equations.append(equation)
        self.outputs.append(output)
    
    def solve(self):
        num = 0
        for i, eq in enumerate(self.equations):
            if self.outputs[i]:
                # Assume every free variable is 0
                num |= eq & -eq
        
        state = [ (num >> (32 * i)) & 0xFFFFFFFF for i in range(624) ]
        return state

outputs = []
r = remote('crypto.zh3r0.cf', 4444)

def get_pair(st, idx):
    r.recvline()
    r.sendline(st)
    t = r.recvline().decode().split()
    totsc = float(t[-4][:-1])
    print(totsc, idx)
    if totsc > 10 ** 6:
        print(r.recvline())
    if idx < 624:
        tt = t[-1]
        s = tt.split("/")
        a = int(s[0])
        b = int(s[1])
        # a / b = 2^53 / ?
        val = (b << 53) // a
        # (a >> 5) << 26 + (b >> 6)
        A = val >> 27
        B = val & ((1 << 26) - 1)
        return A, B
    return None

num = 1248
bit = 26
twister = Twister()
equations = [ twister.getrandbits(bit) for _ in range(num) ]

solver = Solver()
for i in range(0, 1248, 2):
    a, b = get_pair("0", i // 2)
    for j in range(bit):
        solver.insert(equations[i][j], (a >> (bit - 1 - j)) & 1)
    for j in range(bit):
        solver.insert(equations[i+1][j], (b >> (bit - 1 - j)) & 1)

state = solver.solve()
recovered_state = (3, tuple(state + [0]), None)
random.setstate(recovered_state)

for i in range(1248):
    random.getrandbits(32)

for i in range(624, 2000):
    a = random.getrandbits(32)
    b = random.getrandbits(32)
    res = (a >> 20) << 41
    res = res / (2 ** 53)
    get_pair(str(res), i)
