from sage.all import *
import hashlib 
import os 
import random as rand
from Crypto.Util.number import *

Zx = PolynomialRing(ZZ, 'x')
x = Zx.gen()

n, q = 263, Integer(128)
MOD_POLY = (x ** n) - 1
MOD_POLY_T = MOD_POLY // (x - 1)

def convolution(f,g):
    return (f * g) % MOD_POLY

def convolutionT(f, g):
    return (f * g) % MOD_POLY_T

def balancedmod(f,q):
    g = list(((f[i] + q//2) % q) - q//2 for i in range(n))
    return Zx(g) % MOD_POLY

def invertmodprime(f,p):
    T = Zx.change_ring(Integers(p)).quotient(MOD_POLY)
    return Zx(lift(1 / T(f)))

def invertmodprimeT(f, p):
    T = Zx.change_ring(Integers(p)).quotient(MOD_POLY_T)
    return Zx(lift(1 / T(f)))

def invertmodpowerof2(f,q):
    assert Integer(q).is_power_of(2)
    g = invertmodprime(f,2)
    while True:
        r = balancedmod(convolution(g,f), q)
        if r == 1: return g
        g = balancedmod(convolution(g, 2 - r), q)

def invertmodpowerof2T(f,q):
    assert Integer(q).is_power_of(2)
    g = invertmodprimeT(f,2)
    while True:
        r = balancedmod(convolutionT(g,f), q)
        if r == 1: return g
        g = balancedmod(convolutionT(g, 2 - r), q)

def encode(val):
    poly = 0
    for i in range(n):
        poly += ((val % 3) - 1) * (x ** i)
        val //= 3
    return poly

file_read = open("output.txt", "r")

public_key = Zx(eval(file_read.readline())) + 256

encryptions = []

for i in range(24):
    encryptions.append(Zx(eval(file_read.readline())))

file_read.close()

for i in range(24):
    assert (encryptions[i](1) % 128 + 128) % 128 == 83
    encryptions[i] += 83 - encryptions[i](1)
    assert encryptions[i](1) == 83

r_val_IDX = [[0] * n for _ in range(24)]

pub_div = public_key // (x - 1)

pub_div_inv = invertmodpowerof2T(pub_div, q)

for idx1 in range(24):
    for idx2 in range(24):
        diff_pol = (encryptions[idx1] - encryptions[idx2]) // (x - 1)
        diff_r = balancedmod(convolution(diff_pol, pub_div_inv), q)

        tt = diff_r.coefficients(sparse=False)
        while len(tt) < n:
            tt.append(0)
        min_v = min(tt)
        max_v = max(tt)
        if max_v - min_v != 4:
            continue
        for j in range(n):
            if tt[j] == min_v:
                r_val_IDX[idx2][j] = 1
                r_val_IDX[idx1][j] = -1
            if tt[j] == max_v:
                r_val_IDX[idx2][j] = -1
                r_val_IDX[idx1][j] = 1

from tqdm import tqdm 

for i in tqdm(range(n)):
    if r_val_IDX[12][i] != 0:
        continue 
    r_val_IDX[12][i] = 1
    for j in range(n):
        if r_val_IDX[12][j] != 0:
            continue 
        r_val_IDX[12][j] = -1
        for k in range(j + 1, n):
            if r_val_IDX[12][k] != 0:
                continue
            r_val_IDX[12][k] = -1
            tt = Zx(r_val_IDX[12])
            result = balancedmod(encryptions[12] - convolution(public_key, tt), q)
            isok = True 
            for u in range(n):
                if int(result[u]) >= 2 or int(result[u]) <= -2:
                    isok = False 
                    break 
            if isok:
                print("FOUND", i, j, k)
                flag = 0
                for u in range(n):
                    flag += (int(result[u]) + 1) * (3 ** u)
                print(long_to_bytes(flag))
            r_val_IDX[12][k] = 0
        r_val_IDX[12][j] = 0
    r_val_IDX[12][i] = 0