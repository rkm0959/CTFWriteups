
import os
import random as rand 
from dataclasses import dataclass
from math import gcd
from typing import List, Tuple
from sage.all import * 
import gmpy2
from Crypto.Util.number import bytes_to_long, getPrime, GCD, long_to_bytes


@dataclass
class Pubkey:
    n: int
    c: int


@dataclass
class Privkey:
    p: int
    q: int


@dataclass
class Enc:
    r: int
    s: int
    t: int

    def __repr__(self) -> str:
        return f"r = {self.r}\ns = {self.s}\nt = {self.t}"


def crt(r1: int, n1: int, r2: int, n2: int) -> int:
    g, x, y = gmpy2.gcdext(n1, n2)
    assert g == 1
    return int((n1 * x * r2 + n2 * y * r1) % (n1 * n2))


def gen_prime(pbits: int) -> int:
    p = getPrime(pbits)
    while True:
        if p % 4 == 3:
            return p
        p = getPrime(pbits)


def genkey(pbits: int) -> Tuple[Pubkey, Privkey]:
    p, q = gen_prime(pbits), gen_prime(pbits)
    n = p * q
    c = rand.randint(0, n - 1)
    while True:
        if gmpy2.jacobi(c, p) == -1 and gmpy2.jacobi(c, q) == -1:
            break
        c = rand.randint(0, n - 1)
    pubkey = Pubkey(n=n, c=c)
    privkey = Privkey(p=p, q=q)
    return pubkey, privkey


# r = m + c / m
# s <- (m / n)
# t <- (c / m) < m
def encrypt(m: int, pub: Pubkey) -> Enc:
    assert 0 < m < pub.n
    assert gcd(m, pub.n) == 1
    r = int((m + pub.c * pow(m, -1, pub.n)) % pub.n)
    s = int(gmpy2.jacobi(m, pub.n))
    t = int(pub.c * pow(m, -1, pub.n) % pub.n < m)
    enc = Enc(r=r, s=s, t=t)
    assert s in [1, -1]
    assert t in [0, 1]
    return enc


def solve_quad(r: int, c: int, p: int) -> Tuple[int, int]:
    """
    Solve x^2 - r * x + c = 0 mod p
    See chapter 5.
    """

    def mod(poly: List[int]) -> None:
        """
        Calculate mod x^2 - r * x + c (inplace)
        """
        assert len(poly) == 3
        if poly[2] == 0:
            return
        poly[1] += poly[2] * r
        poly[1] %= p
        poly[0] -= poly[2] * c
        poly[0] %= p
        poly[2] = 0

    def prod(poly1: List[int], poly2: List[int]) -> List[int]:
        """
        Calculate poly1 * poly2 mod x^2 - r * x + c
        """
        assert len(poly1) == 3 and len(poly2) == 3
        assert poly1[2] == 0 and poly2[2] == 0
        res = [
            poly1[0] * poly2[0] % p,
            (poly1[1] * poly2[0] + poly1[0] * poly2[1]) % p,
            poly1[1] * poly2[1] % p,
        ]
        mod(res)
        assert res[2] == 0
        return res

    # calculate x^exp mod (x^2 - r * x + c) in GF(p)
    exp = (p - 1) // 2
    res_poly = [1, 0, 0]  # = 1
    cur_poly = [0, 1, 0]  # = x
    while True:
        if exp % 2 == 1:
            res_poly = prod(res_poly, cur_poly)
        exp //= 2
        if exp == 0:
            break
        cur_poly = prod(cur_poly, cur_poly)

    # I think the last equation in chapter 5 should be x^{(p-1)/2}-1 mod (x^2 - Ex + c)
    # (This change is not related to vulnerability as far as I know)
    a1 = -(res_poly[0] - 1) * pow(res_poly[1], -1, p) % p
    a2 = (r - a1) % p
    return a1, a2


def decrypt(enc: Enc, pub: Pubkey, priv: Privkey) -> int:
    assert 0 <= enc.r < pub.n
    assert enc.s in [1, -1]
    assert enc.t in [0, 1]
    mps = solve_quad(enc.r, pub.c, priv.p)
    mqs = solve_quad(enc.r, pub.c, priv.q)
    ms = []
    for mp in mps:
        for mq in mqs:
            m = crt(mp, priv.p, mq, priv.q)
            if gmpy2.jacobi(m, pub.n) == enc.s:
                ms.append(m)
    assert len(ms) == 2
    m1, m2 = ms
    if m1 < m2:
        m1, m2 = m2, m1
    if enc.t == 1:
        m = m1
    elif enc.t == 0:
        m = m2
    else:
        raise ValueError
    return m


from pwn import *

REMOTE = True


if REMOTE:
    conn = remote("34.141.16.87", 50001)


def get_enc():
    tt = conn.recvline()
    if b"wrong" in tt:
        return -1, -1, -1 
    tt = conn.recvlines(3)
    r = int(tt[0].split()[-1])
    s = int(tt[1].split()[-1])
    t = int(tt[2].split()[-1])
    return r, s, t 

if REMOTE:
    encrypted_flag = get_enc()
    print(encrypted_flag)

def query(r, s, t):
    st = str(r) + "," + str(s) + "," + str(t)
    conn.sendline(st.encode())
    return get_enc()



from tqdm import tqdm 

if REMOTE == False:
    pbits = 1024
    pub, priv = genkey(pbits)
    collect = []

    def get_enc_test(r, s, t):
        try:
            return encrypt(decrypt(Enc(r, s, t), pub, priv), pub)
        except:
            return Enc(-1, -1, -1)

    print(pub.n)
    print(priv.p)
    print(priv.q)

    fuck = []

    for i in tqdm(range(1, 30)):
        A = get_enc_test(i, -1, 0).r
        B = get_enc_test(i, 1, 0).r
        C = get_enc_test(i, -1, 1).r
        D = get_enc_test(i, 1, 1).r
        lst = [A, B, C, D]
        if -1 in lst:
            continue
        lst = list(set(lst))
        lst.sort()
        det = len(lst)

        if det == 2:
            collect.append(lst[0] - lst[1])
            cc = GCD(lst[0] - lst[1], pub.n) 
            fuck.append([i, lst[0], lst[1]])
                
    pr = []
    for i in range(len(collect)):
        for j in range(i + 1, len(collect)):
            tt = GCD(collect[i], collect[j])
            for k in range(2, 500):
                while tt % k == 0:
                    tt //= k
            if tt != 1 and (tt not in pr):
                pr.append(tt)
    
    assert len(pr) == 2
    N = pr[0] * pr[1]
    
    c_mod_0 = []
    c_mod_1 = []
    for i in tqdm(range(len(fuck))):
        dif = fuck[i][0]
        A = fuck[i][1]
        B = fuck[i][2]
        base_val = N // GCD(A - B, N)
        POL = PolynomialRing(GF(base_val), 'x')
        x = POL.gen()
        f = x * x - A * x - (dif - x) * (dif - x) + B * (dif - x)
        for true_x, ex in f.roots():
            c_mod = int(A * true_x - true_x * true_x)
            if base_val == pr[0]:
                if c_mod not in c_mod_0:
                    c_mod_0.append(c_mod)
            else:
                if c_mod not in c_mod_1:
                    c_mod_1.append(c_mod)

    print(c_mod_0)
    print(pub.c % pr[0])
    print(c_mod_1)
    print(pub.c % pr[1])
else:
    collect = []
    fuck = []
    for i in tqdm(range(1, 30)):
        A = query(i, -1, 0)[0]
        B = query(i, 1, 0)[0]
        C = query(i, -1, 1)[0]
        D = query(i, 1, 1)[0]
        lst = [A, B, C, D]
        if -1 in lst:
            continue
        lst = list(set(lst))
        lst.sort()
        det = len(lst)

        if det == 2:
            collect.append(lst[0] - lst[1])
            fuck.append([i, lst[0], lst[1]])
                
    pr = []
    for i in range(len(collect)):
        for j in range(i + 1, len(collect)):
            tt = GCD(collect[i], collect[j])
            for k in range(2, 500):
                while tt % k == 0:
                    tt //= k
            if tt != 1 and (tt not in pr):
                pr.append(tt)
    
    assert len(pr) == 2
    N = pr[0] * pr[1]
    
    c_mod_0 = []
    c_mod_1 = []
    for i in tqdm(range(len(fuck))):
        dif = fuck[i][0]
        A = fuck[i][1]
        B = fuck[i][2]
        base_val = N // GCD(A - B, N)
        POL = PolynomialRing(GF(base_val), 'x')
        x = POL.gen()
        f = x * x - A * x - (dif - x) * (dif - x) + B * (dif - x)
        for true_x, ex in f.roots():
            c_mod = int(A * true_x - true_x * true_x)
            if base_val == pr[0]:
                if c_mod not in c_mod_0:
                    c_mod_0.append(c_mod)
            else:
                if c_mod not in c_mod_1:
                    c_mod_1.append(c_mod)

    print("c_mod_0", c_mod_0)
    print("c_mod_1", c_mod_1)
    
    pub_c = CRT(c_mod_0[0], c_mod_1[0], pr[0], pr[1])

    print("pr", pr)
    print("N", N)
    print("pub_c", pub_c)