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
from Crypto.Hash import SHA256

charset = string.ascii_letters + string.digits + '!#$%&*-?'

def _prod(L):
    p = 1
    for x in L:
        p *= x
    return p

def _sum(L):
    s = 0
    for x in L:
        s ^= x
    return s

def b2n(x):
    return int.from_bytes(x, 'big')

def n2l(x, l):
    return list(map(int, '{{0:0{}b}}'.format(l).format(x)))

def split(x, n, l):
    return [(x >> (i * l)) % 2**l for i in range(n)][::-1]

def combine(x, n, l):
    return sum([x[i] << (l * (n - i - 1)) for i in range(n)])

class Generator1:
    def __init__(self, key: list):
        assert len(key) == 64
        self.NFSR = key[: 48]
        self.LFSR = key[48: ]
        self.TAP = [0, 1, 12, 15]
        self.TAP2 = [[2], [5], [9], [15], [22], [26], [39], [26, 30], [5, 9], [15, 22, 26], [15, 22, 39], [9, 22, 26, 39]]
        self.h_IN = [2, 4, 7, 15, 27]
        self.h_OUT = [[1], [3], [0, 3], [0, 1, 2], [0, 2, 3], [0, 2, 4], [0, 1, 2, 4]]

    def g(self):
        x = self.NFSR
        return _sum(_prod(x[i] for i in j) for j in self.TAP2)

    def h(self):
        x = [self.LFSR[i] for i in self.h_IN[:-1]] + [self.NFSR[self.h_IN[-1]]]
        return _sum(_prod(x[i] for i in j) for j in self.h_OUT)

    def f(self):
        return _sum([self.NFSR[0], self.h()])

    def clock(self):
        o = self.f()
        self.NFSR = self.NFSR[1: ] + [self.LFSR[0] ^ self.g()]
        self.LFSR = self.LFSR[1: ] + [_sum(self.LFSR[i] for i in self.TAP)]
        return o

class Generator2:
    def __init__(self, key):
        assert len(key) == 64
        self.NFSR = key[: 16]
        self.LFSR = key[16: ]
        self.TAP = [0, 35]
        self.f_IN = [0, 10, 20, 30, 40, 47]
        self.f_OUT = [[0, 1, 2, 3], [0, 1, 2, 4, 5], [0, 1, 2, 5], [0, 1, 2], [0, 1, 3, 4, 5], [0, 1, 3, 5], [0, 1, 3], [0, 1, 4], [0, 1, 5], [0, 2, 3, 4, 5], [
            0, 2, 3], [0, 3, 5], [1, 2, 3, 4, 5], [1, 2, 3, 4], [1, 2, 3, 5], [1, 2], [1, 3, 5], [1, 3], [1, 4], [1], [2, 4, 5], [2, 4], [2], [3, 4], [4, 5], [4], [5]]
        self.TAP2 = [[0, 3, 7], [1, 11, 13, 15], [2, 9]]
        self.h_IN = [0, 2, 4, 6, 8, 13, 14]
        self.h_OUT = [[0, 1, 2, 3, 4, 5], [0, 1, 2, 4, 6], [1, 3, 4]]

    def f(self):
        x = [self.LFSR[i] for i in self.f_IN]
        return _sum(_prod(x[i] for i in j) for j in self.f_OUT)

    def h(self):
        x = [self.NFSR[i] for i in self.h_IN]
        return _sum(_prod(x[i] for i in j) for j in self.h_OUT)        

    def g(self):
        x = self.NFSR
        return _sum(_prod(x[i] for i in j) for j in self.TAP2)  

    def clock(self):
        self.LFSR = self.LFSR[1: ] + [_sum(self.LFSR[i] for i in self.TAP)]
        self.NFSR = self.NFSR[1: ] + [self.LFSR[1] ^ self.g()]
        return self.f() ^ self.h()

class Generator2p:
    def __init__(self, key):
        assert len(key) == 64
        self.NFSR = key[: 16]
        self.LFSR = key[16: ]
        self.TAP = [0, 35]

    def clock(self):
        self.LFSR = self.LFSR[1: ] + [_sum(self.LFSR[i] for i in self.TAP)]
        return (self.LFSR[10] + self.LFSR[20] + self.LFSR[47]) % 2

class Generator3:
    def __init__(self, key: list):
        assert len(key) == 64
        self.LFSR = key
        self.TAP = [0, 55]
        self.f_IN = [0, 8, 16, 24, 32, 40, 63]
        self.f_OUT = [[1], [6], [0, 1, 2, 3, 4, 5], [0, 1, 2, 4, 6]]

    def f(self):
        x = [self.LFSR[i] for i in self.f_IN]
        return _sum(_prod(x[i] for i in j) for j in self.f_OUT)

    def clock(self):
        self.LFSR = self.LFSR[1: ] + [_sum(self.LFSR[i] for i in self.TAP)]
        return self.f()

class Generator4:
    def __init__(self, key: list):
        assert len(key) == 64
        self.LFSR = key
        self.TAP = [0, 55]

    def clock(self):
        self.LFSR = self.LFSR[1: ] + [_sum(self.LFSR[i] for i in self.TAP)]
        return (self.LFSR[8] + self.LFSR[63]) % 2


class KDF:
    def __init__(self, key: int):
        self.msk = key
        self.SBOX = [12, 5, 1, 2, 7, 15, 9, 3, 0, 13, 14, 6, 8, 10, 4, 11]
        self.idx = [[0, 3], [0, 1], [2, 3], [0, 3]]

    def substitue(self, x):
        return [self.SBOX[i] for i in x]

    def expand(self):
        h = hashlib.sha256(str(self.msk).encode()).digest()
        rnd_key = [h[: 2], h[2: 4], h[2: 4], h[4: 6]]
        rnd_key = list(map(b2n, rnd_key))
        chunk = split(self.msk, 4, 16)
        sub_key = [combine(self.substitue(split(chunk[self.idx[i][0]] ^ chunk[self.idx[i][1]] , 4, 4)), 4, 4) for i in range(4)]
        final_key = [rnd_key[i] ^ sub_key[i] for i in range(4)]
        return combine(final_key, 4, 16)

class zer0lfsr:
    def __init__(self, msk: int):
        self.key = []
        for i in range(3):
            msk = KDF(msk).expand()
            self.key.append(msk)
        self.g1 = Generator1(n2l(self.key[0], 64))
        self.g2 = Generator2(n2l(self.key[1], 64))
        self.g3 = Generator3(n2l(self.key[2], 64))

    def next(self):
        o1 = self.g1.clock()
        o2 = self.g2.clock()
        o2 = self.g2.clock()
        o3 = self.g3.clock()
        o3 = self.g3.clock()
        o3 = self.g3.clock()
        o = (o1 * o2) ^ (o2 * o3) ^ (o1 * o3)
        return o

sbox = [12, 5, 1, 2, 7, 15, 9, 3, 0, 13, 14, 6, 8, 10, 4, 11]
sbox_inv = [0] * 16
for i in range(16):
    sbox_inv[sbox[i]] = i

def s_16(x):
    L = split(x, 4, 4)
    for i in range(4): 
        L[i] = sbox[L[i]]
    return combine(L, 4, 4)

def s_inverse_16(x):
    L = split(x, 4, 4)
    for i in range(4): 
        L[i] = sbox_inv[L[i]]
    return combine(L, 4, 4)

def find_sol(args):
    START, TARGET, RANGE = args
    if RANGE >= 70:
        return None
    for i in range(70):
        for j in range(70):
            for k in range(70):
                cur = charset[RANGE] + charset[i] + charset[j] + charset[k]
                v = cur.encode() + START
                if hashlib.sha256(v).digest() == TARGET:
                    return cur.encode()
    return None 

def PoW(NUM, START, TARGET):
    batch = 1
    pool = mp.Pool(NUM)
    nonce = 0
    while True:
        nonce_range = [nonce + i * batch for i in range(NUM)]
        params = [(START, TARGET, RANGE) for RANGE in nonce_range]
        solutions = pool.map(find_sol, params)
        solutions = list(filter(None, solutions))
        print("Checked", nonce + batch * NUM)
        if len(solutions) != 0:
            return solutions[0]
        nonce += batch * NUM

def do_Pow():
    s = r.recvline()
    r.recvline()
    cc = s.split()[2][:-1]
    target = s.split()[4].decode()
    target = bytes.fromhex(target)
    res = PoW(12, cc, target)
    print(res)
    r.sendline(res)
    print("Solved PoW")

def matches3(bits, key):
    lst = [0] * 64
    for i in range(64):
        lst[i] = int(key[i])
    GEN = Generator4(lst)
    ret = 0
    for i in range(10000):
        GEN.clock()
        GEN.clock()
        if GEN.clock() == bits[i]:
            ret += 1
    return ret

def matches2(bits, key):
    lst = [0] * 64
    for i in range(64):
        lst[i] = int(key[i])
    GEN = Generator2(key)
    ret = 0
    for i in range(10000):
        GEN.clock()
        if GEN.clock() == bits[i]:
            ret += 1
    return ret

def inbound(x):
    return 0 <= x and x < 160000

def getbits(msk):
    GEN = zer0lfsr(msk)
    print(msk, GEN.key[0], GEN.key[1], GEN.key[2])
    assert KDF(GEN.key[0]).expand() == GEN.key[1]
    assert KDF(GEN.key[1]).expand() == GEN.key[2]
    bits = []
    for i in range(160000):
        bits.append(GEN.next())
    return bits, GEN.key[0], GEN.key[1], GEN.key[2]

def recover_key3(bits):
    rat = []
    for i in range(60000, 100000):
        cnt = 0
        ok = 0
        CC = [64, 61, 58, 55, 0]
        for j in range(0, 16):
            for k in range(5):
                isok = True
                for l in range(5):
                    if inbound(i - CC[k] + CC[l]) == False:
                        isok = False
                if isok == False:
                    continue
                cnt += 1
                tot = 0
                for l in range(5):
                    tot += bits[i - CC[k] + CC[l]]
                if tot % 2 == 0:
                    ok += 1
            CC[0] *= 2
            CC[1] *= 2
            CC[2] *= 2
            CC[3] *= 2
        rat.append((ok / cnt, i))
    rat.sort()
    rat = rat[::-1]
    INDEX = [-1] * 160000
    for i in range(64):
        u, v = rat[i]
        INDEX[v] = bits[v]
    LFSR = []
    for i in range(64):
        cc = [0] * 64
        cc[i] = 1
        cc = vector(GF(2), cc)
        LFSR.append(cc)
    VAL = []
    bts = []
    for i in range(160000):
        LFSR = LFSR[1:] + [LFSR[0] + LFSR[55]]
        LFSR = LFSR[1:] + [LFSR[0] + LFSR[55]]
        LFSR = LFSR[1:] + [LFSR[0] + LFSR[55]]
        if INDEX[i] != -1:
            VAL.append(LFSR[8] + LFSR[63])
            bts.append(INDEX[i])
    bts = vector(GF(2), bts)
    MAT = Matrix(GF(2), VAL)
    BASIS = MAT.right_kernel().basis()
    L = len(BASIS)
    cur_key = 0
    cur_match = 0
    target = 0
    for i in range(65):
        if i == 64:
            target = bts
        else:
            cc = [0] * 64
            cc[i] = 1
            target = bts + vector(GF(2), cc)
        try:
            key = MAT.solve_right(target)
            for j in range(1 << L):
                kkey = key
                for k in range(L):
                    if ((j >> k) & 1) == 1:
                        kkey += BASIS[k]
                match = matches3(bits, kkey)
                if match > cur_match:
                    cur_match = match
                    cur_key = kkey
        except:
            pass
    res = 0
    for i in range(64):
        if cur_key[i] == GF(2)(0):
            res = 2 * res
        else:
            res = 2 * res + 1
    return res, cur_match

def KDF_is_god(kdf_value, xored_value):
    Kprime = split(kdf_value, 4, 16)
    tmp = s_16(xored_value) ^ Kprime[1] ^ Kprime[2]
    return s_inverse_16(tmp)

def find_sol_2(args):
    MAT, ACT, btss, key3, st = args
    
    for idx in range(3 * st, 3 * st + 3):
        target = btss
        
        if idx < 32:
            cc = [0] * 32
            cc[idx] = 1
            cc = vector(GF(2), cc)
            target = btss + cc
        
        try:
            val = MAT.solve_right(target)
        except:
            return None
        
        org = 0
        for i in range(48):
            if val[i] == GF(2)(1):
                org ^= (1 << (47 - i))
        
        for i in range(len(ACT)):
            sol = org ^ ACT[i]
            K1 = (sol >> 32) & 65535
            K2 = (sol >> 16) & 65535
            K3 = sol & 65535
            K0 = KDF_is_god(key3, K2 ^ K3) ^ K1
            key2 = (K0 << 48) + sol
            fin = KDF(key2).expand()
            if fin == key3:
                return key2
    return None

def recover_key2(bits, key3):
    gen3 = Generator3(n2l(key3, 64))
    bit3 = []
    for i in range(160000):
        gen3.clock()
        gen3.clock()
        bit3.append(gen3.clock())
    bit2 = [-1] * 160000
    for i in range(160000):
        if bit3[i] != bits[i]:
            bit2[i] = bits[i]
    rat = []
    for i in range(20000, 140000):
        cnt = 0
        ok = 0
        CC = [48, 35, 0]
        for j in range(0, 16):
            for k in range(3):
                isok = True
                for l in range(3):
                    if inbound(i - CC[k] + CC[l]) == False or bit2[i - CC[k] + CC[l]] == -1:
                        isok = False
                if isok == False:
                    continue
                cnt += 1
                tot = 0
                for l in range(3):
                    tot += bit2[i - CC[k] + CC[l]]
                if tot % 2 == 0:
                    ok += 1
            CC[0] *= 2
            CC[1] *= 2
        if cnt >= 5:
            rat.append((ok/cnt, ok, cnt, i))
    rat.sort()
    rat = rat[::-1]
    INDEX = [-1] * 160000
    for i in range(32):
        u, ok, cnts, v = rat[i]
        INDEX[v] = bit2[v]
    LFSR = []
    for i in range(48):
        cc = [0] * 48
        cc[i] = 1
        cc = vector(GF(2), cc)
        LFSR.append(cc)
    VAL = []
    bts = []
    for i in range(160000):
        LFSR = LFSR[1:] + [LFSR[0] + LFSR[35]]
        LFSR = LFSR[1:] + [LFSR[0] + LFSR[35]]
        if INDEX[i] != -1:
            VAL.append(LFSR[10] + LFSR[20] + LFSR[47])
            bts.append(INDEX[i])
    MAT = Matrix(GF(2), VAL)
    KERNEL = MAT.right_kernel().basis()
    RES = []
    for i in range(len(KERNEL)):
        v = 0
        for j in range(48):
            if KERNEL[i][j] == GF(2)(1):
                v ^= (1 << (47 - j))
        RES.append(v)
    ACT = []
    for i in range(1 << len(KERNEL)):
        v = 0
        for j in range(len(KERNEL)):
            if ((i >> j) & 1) == 1:
                v ^= RES[j]
        ACT.append(v)
    bts = vector(GF(2), bts)
    pool = mp.Pool(11)
    params = [(MAT, ACT, bts, key3, i) for i in range(11)]
    sols = pool.map(find_sol_2, params)
    sols = list(filter(None, sols))
    if len(sols) != 0:
        return sols[0], bit3
    return None, None


attempts = 0

# flag = 'flag{bruteforce_can_solve_everything?}'
# print(hashlib.sha256(flag.encode()).hexdigest())

while True:
    # msk = rand.getrandbits(64)
    # msk = 8041876756744840591
    # bits, KEY1, KEY2, KEY3 = getbits(msk)
    
    attempts += 1
    print("Attempt #", attempts)

    r = remote('111.186.59.28', 13337)
    do_Pow()

    bits = []
    for i in range(20):
        s = r.recvuntil(":::end\n")
        s = s[8 : -7]
        for j in range(1000):
            t = s[j]
            for k in range(7, -1, -1):
                bits.append((t >> k) & 1)

    st = time.time()
    key3, curmatch = recover_key3(bits)
    en = time.time()
    print(key3, curmatch, en - st)

    if curmatch < 6000:
        continue

    key2, bit3 = recover_key2(bits, key3)
    en = time.time()

    if key2 == None:
        continue

    print(key2, en - st)

    gen2 = Generator2(n2l(key2, 64))
    bit2 = []
    for i in range(160000):
        gen2.clock()
        bit2.append(gen2.clock())
    
    res2 = ''
    res3 = ''
    res = ''
    for i in range(160000):
        if bit2[i] == 0:
            res2 += "0 "
        else:
            res2 += "1 "
    
    for i in range(160000):
        if bit3[i] == 0:
            res3 += "0 "
        else:
            res3 += "1 "
    
    for i in range(160000):
        if bits[i] == 0:
            res += "0 "
        else:
            res += "1 "
    
    cc = [0] * 65536
    ress = ''
    for i in range(65536):
        cc[i] = KDF_is_god(key2, i)
        ress += str(cc[i]) + " "
    
    f = open("input.txt", "w")
    f.write(res2 + "\n")
    f.write(res3 + "\n")
    f.write(res + "\n")
    f.write(ress + "\n")
    f.write(str(key2) + "\n")
    f.close()
    
    subprocess.run(["timeout", "60s", "./a.exe"])

    f = open("output.txt", "r")
    rr = f.read().strip()
    if len(rr) == 0:
        continue
    
    key1 = int(rr)
    print(key1)

    print(r.recvline())
    r.sendline(str(key1))
    print(r.recvline())
    r.sendline(str(key2))
    print(r.recvline())
    r.sendline(str(key3))
    print(r.recvline())
    print(r.recvline())
    print(r.recvline())
    exit()
    