from tqdm import tqdm 
from pwn import *
from Crypto.Util.number import * 
import os 
import hashlib
from base64 import urlsafe_b64decode


P = 2**255 - 19
A = 486662
B = 1
O = 7237005577332262213973186563042994240857116359379907606001950938285454250989


# ECC Class
class Point:
    def __init__(self, x, y=None):
        self.x = x
        if y:
            self.y = y
        else:
            self.y = self.__class__.lift_x(x)
            
        if not self.is_on_curve():
            raise ValueError("Point NOT on Curve 25519!")
        
    def is_on_curve(self):
        if self.x == 0 and self.y == 1:
            return True
        if ((self.x**3 + A * self.x**2 + self.x) % P) == ((B * self.y**2) % P):
            return True
        return False
    
    @staticmethod
    def lift_x(x):
        y_sqr = ((x**3 + A * x**2 + x) * inverse(B, P)) % P
        v = pow(2 * y_sqr, (P - 5) // 8, P)
        i = (2 * y_sqr * v**2) % P
        return Point(x, (y_sqr * v * (1 - i)) % P)
    
    def __repr__(self):
        return "Point ({}, {}) on Curve 25519".format(self.x, self.y)
    
    def __eq__(self, other):
        return self.x == other.x and self.y == other.y
        
    def __add__(self, other):
        if self == self.__class__(0, 1):
            return other
        if other == self.__class__(0, 1):
            return self
        
        if self.x == other.x and self.y != other.y:
            return self.__class__(0, 1)
        
        if self.x != other.x:
            l = ((other.y - self.y) * inverse(other.x - self.x, P)) % P
        else:
            l = ((3 * self.x**2 + 2 * A * self.x + 1) * inverse(2 * self.y, P)) % P
            
        x3 = (l**2 - A - self.x - other.x) % P
        y3 = (l * (self.x - x3) - self.y) % P
        return self.__class__(x3, y3)
    
    def __rmul__(self, k):
        out = self.__class__(0, 1)
        tmp = self.__class__(self.x, self.y)
        while k:
            if k & 1:
                out += tmp
            tmp += tmp
            k >>= 1
        return out

G = Point.lift_x(9)
print("G", G)

url = "blackhat4-933fea1b58abb17fa8ee8125481f6a8a-0.chals.bh.ctf.sa"

conn = remote(url, 443, ssl=True, sni=url)


conn.recvlines(14)

conn.recvlines(1)
pub_hash = int(conn.recvline().strip().split()[-1])
print("pub_hash", pub_hash)

conn.recvlines(2)

enc_flag = conn.recvline().strip().split()[-1]

print(len(enc_flag))

results = []
for i in tqdm(range(432)):
    r_cand = []
    s_cand = []

    for j in range(3):
        try:
            r = bytes_to_long(urlsafe_b64decode(enc_flag[86 * i : 86 * i + 43] + b"=" * j))
            r_cand.append(r)
        except:
            pass 
    for j in range(3):
        try:
            s = bytes_to_long(urlsafe_b64decode(enc_flag[86 * i + 43 : 86 * i + 86] + b"=" * j))
            s_cand.append(s)
        except:
            pass 
    
    results.append([r_cand, s_cand])


conn.recvlines(2)

'''
r1 = ((h/s1) * G + (r1/s1) * PK).x
r2 = ((h/s2) * G + (r2/s2) * PK).x
'''

NUM_SIGS = 8

sigs = []

for i in range(NUM_SIGS):
    conn.recvline()
    conn.sendline(b"11")
    conn.recvline()
    conn.recvline()
    tt = conn.recvline()
    r_ = int(tt.split()[-2][1:-1])
    s_ = int(tt.split()[-1][:-1])
    sigs.append([r_, s_])


real_pk = 0
found = False

for u in tqdm(range(NUM_SIGS)):
    if found:
        break
    for v in range(u + 1, NUM_SIGS):
        for i in range(8):
            if found:
                break
            for j in range(8):
                if found:
                    break
                try:
                    E1 = Point.lift_x(sigs[u][0] + i * O).__rmul__(8)
                    E2 = Point.lift_x(sigs[v][0] + j * O).__rmul__(8)

                    PP = E1.__rmul__(sigs[u][1]) + E2.__rmul__((8 * O - sigs[v][1]))
            
                    iv = inverse(8 * sigs[u][0] - 8 * sigs[v][0], O)
                   

                    PK = PP.__rmul__(int(iv))

                    check_hash = int.from_bytes(hashlib.sha256(str(PK).encode() + b"").digest(), 'big')

                    if check_hash == pub_hash:
                        real_pk = PK
                        found = True 
                        print("OK")
                        break
                except:
                    pass

print(real_pk)
print(int.from_bytes(hashlib.sha256(str(real_pk).encode() + b"").digest(), 'big'))

flag = 0
for i in tqdm(range(432)):
    r_cand = results[i][0]
    s_cand = results[i][1]
    
    h = int.from_bytes(hashlib.sha256(str(real_pk).encode() + b"1").digest(), 'big')

    isok = False

    for r in r_cand:
        for s in s_cand:
            for j in range(8):
                try:
                    E_kG = Point.lift_x(r + j * O)
                    LHS = (8 * s) * E_kG
                    RHS = 8 * (h * G + r * real_pk)
                    if LHS.x == RHS.x:
                        isok = True
                except:
                    pass
    if isok:
        flag = 2 * flag + 1
    else:
        flag = 2 * flag
    
    if i % 8 == 7:
        print(long_to_bytes(flag))

print(long_to_bytes(flag))
