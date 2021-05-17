from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Util.number import inverse, long_to_bytes, bytes_to_long, isPrime, getPrime
from tqdm import tqdm
from pwn import *
from sage.all import *
import sys, json, hashlib, os, math, time, base64, binascii, string, re, struct, datetime
import random as rand
import multiprocessing as mp

## incomplete code

M = 'x^127 + x^126 + x^125 + x^124 + x^122 + x^120 + x^118 + x^117 + x^115 + x^108 + x^107 + x^104 + x^103 + x^100 + x^99 + x^98 + x^96 + x^95 + x^94 + x^91 + x^88 + x^85 + x^83 + x^82 + x^81 + x^77 + x^74 + x^72 + x^70 + x^66 + x^65 + x^64 + x^57 + x^56 + x^55 + x^54 + x^50 + x^49 + x^48 + x^46 + x^44 + x^43 + x^37 + x^36 + x^34 + x^33 + x^28 + x^25 + x^22 + x^19 + x^18 + x^17 + x^16 + x^15 + x^14 + x^13 + x^11 + x^10 + x^8 + x^7 + x^4 + x^2 + x^0'
pol = 'x^126 + x^124 + x^123 + x^120 + x^119 + x^118 + x^117 + x^116 + x^115 + x^114 + x^111 + x^109 + x^108 + x^107 + x^105 + x^103 + x^100 + x^99 + x^98 + x^95 + x^92 + x^87 + x^84 + x^83 + x^82 + x^80 + x^79 + x^76 + x^74 + x^73 + x^71 + x^70 + x^69 + x^67 + x^64 + x^62 + x^61 + x^56 + x^52 + x^51 + x^48 + x^47 + x^45 + x^44 + x^41 + x^40 + x^36 + x^35 + x^34 + x^30 + x^29 + x^27 + x^25 + x^24 + x^18 + x^17 + x^16 + x^15 + x^14 + x^12 + x^11 + x^10 + x^8 + x^6 + x^5 + x^4 + x^1'
flag = '55bd2e97c4efb27b8352ae7e4bcba2b566a9c6f645e4e59312f1945a461c71035a2396a72c3099cd39ec88d238be73992505436068f3f5a416a1bb72d59e2b74'


# g == r / t mod f
def HGCD(f, g):
    # deg(f) >= deg(g)
    s = [1, 0]
    t = [0, 1]
    r = [f, g]
    for i in range(2, 150):
        q, _ = r[i-2].quo_rem(r[i-1])
        r.append(r[i-2] - q * r[i-1])
        s.append(s[i-2] - q * s[i-1])
        t.append(t[i-2] - q * t[i-1])
        if t[i].degree() <= 63 and r[i].degree() <= 63:
            return r[i], t[i]
    assert(False)

##### defining the basic finite field GF(2^127) #####
##### conversion to x^127 + x + 1 #####

P = PolynomialRing(GF(2), 'y')
y = P.gen()


var('x')
K1 = GF(2 ** 127, 'x', x ** 127 + x + 1)

Q = PolynomialRing(K1, 'w')
w = Q.gen()

f = 0
CC = M.split()
for v in CC:
    if '+' in v:
        continue
    tt = int(v[2:])
    f += w ** tt

L = f.roots()[0][0]

z = L + 1

g = 0
CC = pol.split()
for v in CC:
    if '+' in v:
        continue
    tt = int(v[2:])
    g += L ** tt

print(g)
print(z)

B = 12
D = 13
K = 4
H = 32

##### building irreducible binary polys of deg <= B #####
IRR = []
IRRGF = []

for i in range(1, 1 << (B + 1)):
    pol = 0
    tt = 0
    for j in range(0, B + 1):
        if (i & (1 << j)) != 0:
            pol += (y ** j)
            tt += (2 ** j)
    if pol.is_irreducible():
        IRR.append(pol)
        IRRGF.append(K1.fetch_int(tt))

print(len(IRR))

ARR = [[0] * 747 for _ in range(1332)]
CNT = 0
POL = (y ** 127) + y + 1
TOTCNT = 0

##### finding relations & building database #####
'''
def find_sol(params):
    U, IRR = params
    P = PolynomialRing(GF(2), 'y')
    y = P.gen()
    ret = []
    for V in range(1, 1 << 14):
        AA = 0
        BB = 0
        for i in range(0, 14):
            if (U & (1 << i)) != 0:
                AA += (y ** i)
            if (V & (1 << i)) != 0:
                BB += (y ** i)
        if AA == 0 or BB == 0:
            continue
        if AA.gcd(BB) != P(1):
            continue
        C = (y ** 32) * AA + BB
        D = (C ** 4) % POL
        L1 = C.factor()
        chk = True
        for pols, ex in L1:
            if pols.degree() > B:
                chk = False
                break
        if chk == False:
            continue
        L2 = D.factor()
        for pols, ex in L2:
            if pols.degree() > B:
                chk = False
                break
        if chk == False:
            continue
        APP = [0] * 747
        for pols, ex in L1:
            cc = IRR.index(pols)
            APP[cc] += K * ex
        for pols, ex in L2:
            cc = IRR.index(pols)
            APP[cc] -= ex
        ret.append(APP)
    return ret

CNT = 1332
for U in tqdm(range(80 * 12 + 1, 1 << 14, 12)):
    if CNT >= 1850:
        break
    pool = mp.Pool(12)
    params = [(U+i, IRR) for i in range(12)]
    solutions = list(pool.map(find_sol, params))
    for i in range(12):
        for j in range(len(solutions[i])):
            filef = open('ans.txt', 'a')
            print("BEGIN ", CNT)
            filef.write("NUMBER " + str(CNT) + "\n")
            for k in range(747):
                if CNT < 1850:
                    ARR[CNT][k] = solutions[i][j][k]
                    filef.write(str(ARR[CNT][k]) + "\n")
            filef.close()
            print("FINISH ", CNT)
            CNT += 1
    print(CNT)
'''

##### solving system of linear equations #####
'''
filef = open('ans.txt', 'r')

for i in range(1332):
    filef.readline()
    res = K1(1)
    for j in range(747):
        vv = int(filef.readline().strip())
        ARR[i][j] = vv
        res = res * (IRRGF[j] ** vv)
    assert res == K1(1)

filef.close()

print("PASSED!")

MAT = Matrix(GF(2 ** 127 - 1), ARR)

SS = MAT.right_kernel().basis()

print(len(SS)) # should be one

SS = SS[0]
darn = open('res.txt', 'w')
for i in range(747):
    darn.write(str(SS[i]) + "\n")
darn.close()
'''

SS = []

darn = open('res.txt', 'r')
for i in range(747):
    s = int(darn.readline().strip())
    SS.append(s)
darn.close()

def int_to_poly(v):
    f = 0
    for i in range(0, 20):
        if (v & (1 << i)) != 0:
            f += (y ** i)
    return f

##### finding logarithms #####
def MODERATE(TARGET, SS):
    print(TARGET)
    cbound = TARGET.degree()
    p = (2 ** 127) - 1
    if TARGET.is_irreducible() and TARGET.degree() <= B:
        for i in range(747):
            if IRR[i] == TARGET:
                return SS[i]
        assert(False)
    cutoff = int(sqrt(cbound * B))
    DDD = 18
    KK = 4
    HH = 32
    for U in tqdm(range(1, 1 << (DDD + 1))):
        AA = P(0)
        BB = P(0)
        for i in range(0, DDD + 1):
            if (U & (1 << i)) != 0:
                AA += (y ** i)
        BBP = ((y ** HH) * AA) % TARGET
        idx = 0
        for j in range(16):
            idx = rand.randint(1, 1 << (DDD - TARGET.degree()))
            BB = BBP + int_to_poly(idx) * TARGET
            idx += 1
            if BB.degree() > DDD:
                break
            if AA.gcd(BB) != P(1):
                continue
            CC = (y ** HH) * AA + BB 
            DD = (CC ** KK) % POL
            if CC % TARGET != P(0):
                continue
            VV = CC / TARGET

            L1 = VV.factor()
            L2 = DD.factor()

            isok = True
            for polpol, ex in L1:
                if polpol.degree() > cutoff:
                    isok = False
                    break
            for polpol, ex in L2:
                if polpol.degree() > cutoff:
                    isok = False
                    break
            
            if isok == False:
                continue
            # log(TARGET) = log(CC) - log(VV) = 1/4 * log(DD) - log(VV)

            ret = 0
            for polpol, ex in L1:
                ret -= MODERATE(polpol, SS) * ex
            for polpol, ex in L2:
                ret += inverse(4, p) * MODERATE(polpol, SS) * ex
            
            ret = (ret % p + p) % p
            return ret
    assert(False)


def GETLOG(TARGET, SS):
    p = (2 ** 127) - 1
    print(TARGET)
    cbound = TARGET.degree()
    cutoff = int(sqrt(cbound * B))
    if TARGET.is_irreducible() and TARGET.degree() <= B:
        for i in range(747):
            if IRR[i] == TARGET:
                return SS[i]
        assert(False)
    if TARGET.is_irreducible() and TARGET.degree() <= 18:
        return MODERATE(TARGET, SS)
    while True:
        exs = rand.randint(1, 1 << 126)
        GG = (TARGET * power_mod(y, exs, POL)) % POL
        R, T = HGCD(POL, GG)
        # log = (R - T - m) mod p
        L1 = R.factor()
        L2 = T.factor()
        isok = True
        for polpol, ex in L1:
            if polpol.degree() > cutoff:
                isok = False
                break
        for polpol, ex in L2:
            if polpol.degree() > cutoff:
                isok = False
                break
        if isok == False:
            continue
        ret = 0
        for polpol, ex in L1:
            ret += GETLOG(polpol, SS) * ex
        for polpol, ex in L2:
            ret -= GETLOG(polpol, SS) * ex
        ret += (p - exs)
        ret += p
        ret %= p
        return ret


sys.setrecursionlimit(10 ** 6)

g = P(g)
z = P(z)

print(g)
print(z)

CALC_1 = GETLOG(g,  SS)
CALC_2 = GETLOG(z,  SS)

'''
CALC_1 = 19597093303200477157781664624163126769
CALC_2 = 40483060082070127030444832815647636291
'''

p = (2 ** 127) - 1

tt = (CALC_1 * inverse(CALC_2, p)) % p

print(power_mod(z, tt, POL) - g)

ans = GF(p)(tt).log(GF(p)(69))
ans = (int)(ans)
flag = bytes.fromhex(flag)

for i in range(100):
    cipher = AES.new(long_to_bytes(ans), AES.MODE_ECB)
    ans += (p-1)
    print(cipher.decrypt(flag))
